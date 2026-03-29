import type { ActionProposal, RuntimeContext, SafeDecision, SafeVerdict } from "./types.js";
import { normalizeTrustSignals } from "./trust.js";
import { clamp, normalizeOrigin, uniq } from "./utils.js";

function decisionRank(decision: SafeDecision): number {
  switch (decision) {
    case "ALLOW":
      return 0;
    case "REPLAN_READ_ONLY":
      return 1;
    case "USER_CONFIRM":
      return 2;
    case "QUARANTINE_ARTIFACT":
      return 3;
    case "ESCALATE_INCIDENT":
      return 4;
    case "BLOCK":
      return 5;
  }
}

function tightenDecision(current: SafeDecision, candidate: SafeDecision): SafeDecision {
  return decisionRank(candidate) > decisionRank(current) ? candidate : current;
}

function baseRiskScore(riskClass: ActionProposal["riskClass"]): number {
  switch (riskClass) {
    case "critical":
      return 0.9;
    case "high":
      return 0.7;
    case "medium":
      return 0.45;
    default:
      return 0.2;
  }
}

function matchActionPatterns(
  reasons: string[],
  patterns: Array<Record<string, unknown>>
): string[] {
  const hints = reasons.map((reason) => reason.toLowerCase()).join(" ");

  return patterns
    .filter((pattern) => {
      const family = String(pattern.family_key ?? "").toLowerCase();
      const name = String(pattern.pattern_name ?? "").toLowerCase();
      return (
        (hints.includes("origin") && family.includes("origin")) ||
        (hints.includes("sink") && name.includes("sink")) ||
        (hints.includes("approval") && name.includes("approval")) ||
        (hints.includes("write") && name.includes("write"))
      );
    })
    .slice(0, 8)
    .map((pattern) => String(pattern.pattern_id ?? "unknown-action-pattern"));
}

export function evaluateAction(
  proposal: ActionProposal,
  context: RuntimeContext
): SafeVerdict {
  const trustSignals = normalizeTrustSignals(proposal.trustSignals);
  const targetOrigin = normalizeOrigin(proposal.targetOrigin ?? proposal.targetUrl);
  const verb = proposal.verb.toLowerCase();
  const requestedWrite = proposal.requestedWrite ?? false;
  let decision: SafeDecision = "ALLOW";
  const reasonCodes: string[] = [];
  let riskScore = baseRiskScore(proposal.riskClass);

  if (context.policy.deniedActions.has(verb)) {
    decision = tightenDecision(decision, "BLOCK");
    reasonCodes.push("VERB_DENIED_BY_POLICY");
  }

  if (!context.policy.allowedActions.has(verb) && !context.policy.approvalActions.has(verb)) {
    decision = tightenDecision(decision, "REPLAN_READ_ONLY");
    reasonCodes.push("VERB_NOT_IN_TASK_PROFILE");
  }

  if (requestedWrite && !context.policy.writableOrigins.has(targetOrigin)) {
    decision = tightenDecision(decision, "BLOCK");
    reasonCodes.push("WRITE_TO_UNAPPROVED_ORIGIN");
  } else if (
    targetOrigin !== "unknown" &&
    !context.policy.readOnlyOrigins.has(targetOrigin) &&
    !context.policy.writableOrigins.has(targetOrigin)
  ) {
    decision = tightenDecision(
      decision,
      proposal.userInitiated ? "USER_CONFIRM" : "REPLAN_READ_ONLY"
    );
    reasonCodes.push("NEW_UNAPPROVED_ORIGIN");
  }

  if (context.policy.approvalActions.has(verb)) {
    decision = tightenDecision(decision, "USER_CONFIRM");
    reasonCodes.push("ACTION_REQUIRES_APPROVAL");
  }

  if (proposal.sensitiveSink && trustSignals.taintClass !== "trusted") {
    decision = tightenDecision(decision, "USER_CONFIRM");
    reasonCodes.push("TAINTED_DATA_TO_EXTERNAL_SINK");
  }

  if (
    context.taskEnvelope?.allowedOrigins?.length &&
    targetOrigin !== "unknown" &&
    !context.taskEnvelope.allowedOrigins
      .map((origin) => normalizeOrigin(origin))
      .includes(targetOrigin)
  ) {
    decision = tightenDecision(decision, "REPLAN_READ_ONLY");
    reasonCodes.push("ORIGIN_OUTSIDE_TASK_ENVELOPE");
  }

  if (
    context.taskEnvelope?.allowedVerbs?.length &&
    !context.taskEnvelope.allowedVerbs.map((item) => item.toLowerCase()).includes(verb)
  ) {
    decision = tightenDecision(decision, "REPLAN_READ_ONLY");
    reasonCodes.push("VERB_OUTSIDE_TASK_ENVELOPE");
  }

  if (
    context.taskEnvelope?.forbiddenSinks?.length &&
    targetOrigin !== "unknown" &&
    context.taskEnvelope.forbiddenSinks
      .map((sink) => normalizeOrigin(sink))
      .includes(targetOrigin)
  ) {
    decision = tightenDecision(decision, "BLOCK");
    reasonCodes.push("TARGET_IS_FORBIDDEN_SINK");
  }

  if (
    context.metadataOnlyCritic &&
    (requestedWrite || proposal.sensitiveSink || decision !== "ALLOW")
  ) {
    const criticScore = context.metadataOnlyCritic({
      actionId: proposal.actionId,
      verb,
      targetOrigin,
      requestedWrite,
      taintClass: trustSignals.taintClass,
      sameOriginRelation: trustSignals.sameOriginRelation,
      reasonCodes
    });
    riskScore = Math.max(riskScore, criticScore);
    if (criticScore >= 0.9) {
      decision = tightenDecision(decision, "BLOCK");
      reasonCodes.push("METADATA_CRITIC_HIGH_RISK");
    }
  }

  const matchedPatternIds = matchActionPatterns(
    reasonCodes,
    context.knowledgeBase?.actionIntegrityPatterns ?? []
  );

  const incidentPlaybookId =
    decision === "REPLAN_READ_ONLY"
      ? "IR-01"
      : decision === "USER_CONFIRM"
        ? "IR-02"
        : decision === "BLOCK"
          ? "IR-01"
          : undefined;

  return {
    decision,
    reasonCodes: uniq(reasonCodes),
    riskScore: clamp(riskScore),
    safeConstraints: {
      allowed_verbs: [...context.policy.allowedActions],
      allowed_origins: [...context.policy.readOnlyOrigins, ...context.policy.writableOrigins],
      forbid_external_transmission: trustSignals.taintClass !== "trusted"
    },
    matchedPatternIds,
    incidentPlaybookId,
    telemetryTags: uniq([verb, targetOrigin, decision.toLowerCase()])
  };
}


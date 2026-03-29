import type { MemoryWriteRequest, RuntimeContext, SafeVerdict } from "./types.js";
import { normalizeTrustSignals } from "./trust.js";
import { clamp, overlapScore, stableStringify, uniq } from "./utils.js";

function matchMemoryPatterns(
  reasons: string[],
  patterns: Array<Record<string, unknown>>
): string[] {
  const hints = reasons.join(" ").toLowerCase();
  return patterns
    .filter((pattern) => {
      const family = String(pattern.family_key ?? "").toLowerCase();
      const name = String(pattern.pattern_name ?? "").toLowerCase();
      return (
        (hints.includes("memory") && family.includes("memory")) ||
        (hints.includes("rollback") && name.includes("trigger")) ||
        (hints.includes("protected") && name.includes("rule"))
      );
    })
    .slice(0, 8)
    .map((pattern) => String(pattern.pattern_id ?? "unknown-memory-pattern"));
}

export function evaluateMemoryWrite(
  request: MemoryWriteRequest,
  context: RuntimeContext
): SafeVerdict {
  const trustSignals = normalizeTrustSignals({
    artifactKind: "memory",
    extractionMethod: "api",
    ...(request.trustSignals ?? {}),
    taintClass:
      request.source === "user"
        ? "trusted"
        : request.source === "web"
          ? "tainted"
          : request.trustSignals?.taintClass
  });

  const reasonCodes: string[] = [];
  let decision: SafeVerdict["decision"] = "ALLOW";
  let riskScore = request.durable ? 0.45 : 0.2;

  if (context.policy.protectedMemoryKeys.has(request.key.toLowerCase())) {
    decision = "BLOCK";
    reasonCodes.push("PROTECTED_MEMORY_KEY");
    riskScore = 0.98;
  }

  if (request.durable) {
    if (context.policy.memoryDurableWrites === "deny") {
      decision = "BLOCK";
      reasonCodes.push("DURABLE_WRITES_DISABLED");
      riskScore = Math.max(riskScore, 0.9);
    } else if (context.policy.memoryDurableWrites === "approval") {
      decision = "USER_CONFIRM";
      reasonCodes.push("DURABLE_WRITE_REQUIRES_APPROVAL");
      riskScore = Math.max(riskScore, 0.7);
    }
  }

  if (request.source === "web" && request.durable) {
    decision = "BLOCK";
    reasonCodes.push("WEB_DERIVED_DURABLE_WRITE_DENIED");
    riskScore = 0.95;
  }

  if (request.previousValue !== undefined) {
    const similarity = overlapScore(
      stableStringify(request.previousValue),
      stableStringify(request.value)
    );
    if (similarity < 0.1 && request.source === "web") {
      decision = decision === "BLOCK" ? decision : "REPLAN_READ_ONLY";
      reasonCodes.push("SUMMARY_DRIFT_DETECTED");
      riskScore = Math.max(riskScore, 0.8);
    }
  }

  if (trustSignals.taintClass === "tainted" && request.durable) {
    decision = "BLOCK";
    reasonCodes.push("TAINTED_MEMORY_PERSISTENCE");
    riskScore = 0.95;
  }

  const matchedPatternIds = matchMemoryPatterns(
    reasonCodes,
    context.knowledgeBase?.memoryContextPatterns ?? []
  );

  return {
    decision,
    reasonCodes: uniq(reasonCodes),
    riskScore: clamp(riskScore),
    safeConstraints: {
      snapshot_required: request.durable,
      rollback_required: request.durable || reasonCodes.includes("SUMMARY_DRIFT_DETECTED")
    },
    matchedPatternIds,
    incidentPlaybookId:
      decision === "BLOCK" || decision === "REPLAN_READ_ONLY" ? "IR-01" : undefined,
    telemetryTags: uniq([request.key, decision.toLowerCase()])
  };
}


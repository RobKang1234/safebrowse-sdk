import type {
  CapabilityDescriptorV6,
  CompiledObservationV6,
  ModelGuardAssessment,
  ModelGuardObservationRequest,
  PlannerViewV6,
  SafeVerdict,
  TaskSession
} from "./types.js";
import { classifyTargetPathClass } from "./pathPolicyV6.js";
import { clamp, uniq } from "./utils.js";

function aggregateContextText(observation: CompiledObservationV6): string {
  return observation.spans.map((span) => `[${span.channel}] ${span.text}`).join("\n").slice(0, 24_000);
}

function extractVisibleText(observation: CompiledObservationV6): string {
  return observation.spans
    .filter((span) => span.channel === "visible_text")
    .map((span) => span.text)
    .join(" ")
    .slice(0, 12_000);
}

export function buildModelGuardObservationRequest(
  session: TaskSession,
  observation: CompiledObservationV6,
  plannerView: PlannerViewV6,
  authorities: CapabilityDescriptorV6[] = []
): ModelGuardObservationRequest {
  const channels = new Set(observation.spans.map((span) => span.channel));
  const contextText = aggregateContextText(observation);

  return {
    session: {
      sessionId: session.sessionId,
      taskId: session.taskId,
      userGoal: session.userGoal,
      taskPurposeClass: session.taskPurposeClass,
      taskPhase: session.taskPhase,
      allowedOrigins: session.allowedOrigins,
      allowedVerbs: session.allowedVerbs,
      allowedPathClasses: session.allowedPathClasses,
      approvalRequiredPathClasses: session.approvalRequiredPathClasses
    },
    observation: {
      observationId: observation.observationId,
      sourceOrigin: observation.sourceOrigin,
      frameOrigin: observation.frameOrigin,
      surfaceType: observation.surfaceType,
      parseStatus: observation.parseStatus,
      visibleText: extractVisibleText(observation),
      contextText,
      suspicionFlags: observation.suspicionFlags,
      matchedPatternIds: observation.matchedPatternIds,
      riskFindings: observation.riskFindings,
      semanticAuthorityFindings: observation.semanticAuthorityFindings.map((finding) => finding.code),
      policyFindings: observation.policyFindings.map((finding) => finding.code),
      blockedChannels: plannerView.blockedChannels,
      channelFlags: {
        visible: channels.has("visible_text"),
        hidden: channels.has("hidden_text"),
        comment: channels.has("comment"),
        metadata: channels.has("metadata"),
        annotation: channels.has("annotation"),
        schema: channels.has("schema"),
        memory: channels.has("memory_candidate")
      },
      secretRedactionCount: observation.secretFindings.length,
      captureAttestation: observation.captureAttestation,
      contextChars: contextText.length
    },
    targets: observation.extractedTargets.flatMap((target) => {
      const authority = authorities.find(
        (candidate) =>
          candidate.kind === target.kind &&
          candidate.targetUrl === target.href &&
          candidate.selector === target.selector &&
          candidate.providerId === target.providerId &&
          candidate.operationId === target.operationId
      );
      return [
        {
          kind: target.kind,
          operationClass: target.operationClass,
          targetUrl: target.href,
          displayText: target.displayText,
          selector: target.selector,
          targetOrigin: target.targetOrigin,
          targetPathClass:
            authority?.targetPathClass ??
            (target.kind === "navigate" || target.kind === "connector_prepare"
              ? classifyTargetPathClass({
                  targetUrl: target.href,
                  displayText: target.displayText,
                  selector: target.selector
                })
              : undefined),
          requiresApproval: authority?.requiresApproval,
          sourceSpanIds: target.sourceSpanIds
        }
      ];
    }),
    structuredFeatures: {
      taskPurposeClass: session.taskPurposeClass ?? null,
      taskPhase: session.taskPhase ?? null,
      currentStep: session.currentStep,
      riskScore: observation.riskScore,
      evidenceSpanCount: observation.evidenceSpanIds.length,
      targetCount: observation.extractedTargets.length,
      authorityCandidateCount: authorities.length
    }
  };
}

function defaultReasonCodes(assessment: ModelGuardAssessment): string[] {
  return uniq(
    assessment.coarseReasonCodes.length > 0
      ? assessment.coarseReasonCodes
      : [`MODEL_GUARD_${assessment.calibratedDecisionLabel.toUpperCase()}`]
  );
}

export function applyModelGuardAssessment(
  compiledObservation: CompiledObservationV6,
  plannerView: PlannerViewV6,
  verdict: SafeVerdict,
  assessment: ModelGuardAssessment
): {
  compiledObservation: CompiledObservationV6;
  plannerView: PlannerViewV6;
  verdict: SafeVerdict;
} {
  const nextObservation: CompiledObservationV6 = {
    ...compiledObservation,
    modelAssessment: assessment,
    riskScore: clamp(Math.max(compiledObservation.riskScore, assessment.binaryThreatProbability))
  };
  const reasonCodes = defaultReasonCodes(assessment);
  const nextPlannerView: PlannerViewV6 = {
    ...plannerView,
    riskMarkers: uniq([
      ...plannerView.riskMarkers,
      `model_guard_${assessment.calibratedDecisionLabel}`,
      ...reasonCodes.map((code) => code.toLowerCase())
    ])
  };

  if (assessment.calibratedDecisionLabel === "allow_read_only") {
    return {
      compiledObservation: nextObservation,
      plannerView: nextPlannerView,
      verdict
    };
  }

  if (assessment.calibratedDecisionLabel === "require_shadow_replay") {
    nextObservation.authorityEligible = false;
    nextObservation.factsOnlyReasonCodes = uniq([
      ...nextObservation.factsOnlyReasonCodes,
      ...reasonCodes
    ]);
    return {
      compiledObservation: nextObservation,
      plannerView: {
        ...nextPlannerView,
        visibleExcerpt: ""
      },
      verdict: {
        decision: "REPLAN_READ_ONLY",
        reasonCodes,
        riskScore: clamp(Math.max(0.5, nextObservation.riskScore)),
        safeConstraints: {
          claim_profile: "secure_v6",
          authority_eligible: false
        },
        telemetryTags: uniq([...(verdict.telemetryTags ?? []), "model_guard", "facts_only"])
      }
    };
  }

  if (assessment.calibratedDecisionLabel === "require_user_approval") {
    return {
      compiledObservation: nextObservation,
      plannerView: nextPlannerView,
      verdict: {
        ...verdict,
        reasonCodes: uniq([...(verdict.reasonCodes ?? []), ...reasonCodes]),
        riskScore: clamp(Math.max(verdict.riskScore, nextObservation.riskScore))
      }
    };
  }

  nextObservation.authorityEligible = false;
  nextObservation.factsOnlyReasonCodes = uniq([
    ...nextObservation.factsOnlyReasonCodes,
    ...reasonCodes
  ]);
  return {
    compiledObservation: nextObservation,
    plannerView: {
      ...nextPlannerView,
      visibleExcerpt: ""
    },
    verdict: {
      decision: "BLOCK",
      reasonCodes,
      riskScore: clamp(Math.max(0.9, nextObservation.riskScore)),
      safeConstraints: {
        claim_profile: "secure_v6",
        authority_eligible: false
      },
      telemetryTags: uniq([...(verdict.telemetryTags ?? []), "model_guard", "blocked"])
    }
  };
}

import { randomUUID } from "node:crypto";

import type {
  ApprovalEnvelopeV5,
  CapabilityDescriptorV5,
  MemoryPromotionRequestV6,
  MemoryRecord,
  MemorySourceClassV6,
  MemoryStageRequestV6,
  SafeVerdict,
  TaskSession
} from "./types.js";
import { redactJsonValue } from "./secretIsolation.js";
import { clamp, sha256Hex, stableStringify, uniq } from "./utils.js";

function resolveMemorySource(
  sourceClass: MemorySourceClassV6
): Pick<MemoryRecord, "source" | "sourceClass"> {
  switch (sourceClass) {
    case "user_note":
      return { source: "user", sourceClass: "user_provided" };
    case "web_observation":
      return { source: "web", sourceClass: "web_observed" };
    case "model_summary":
      return { source: "model", sourceClass: "model_inferred" };
    case "retrieval_fact":
      return { source: "system", sourceClass: "system_generated" };
    case "system_validation":
      return { source: "system", sourceClass: "validated_system" };
  }
}

function corroborationRequired(sourceClass: MemorySourceClassV6): boolean {
  return ["web_observation", "model_summary", "retrieval_fact"].includes(sourceClass);
}

export function stageMemoryRecordV6(
  request: MemoryStageRequestV6,
  session: TaskSession | undefined
): {
  verdict: SafeVerdict;
  record?: MemoryRecord;
} {
  const reasonCodes: string[] = [];
  let decision: SafeVerdict["decision"] = "ALLOW";
  let riskScore = request.durable ? 0.45 : 0.2;

  if (!session) {
    decision = "BLOCK";
    reasonCodes.push("UNKNOWN_SESSION");
    riskScore = 0.99;
  }

  const redacted = redactJsonValue(request.value);
  if (redacted.secretFindings.length) {
    reasonCodes.push("SECRET_REDACTED_FROM_MEMORY");
    riskScore = Math.max(riskScore, 0.85);
  }

  const tier = request.durable ? "candidate_durable" : "tainted_ephemeral";
  const source = resolveMemorySource(request.sourceClass);

  const record: MemoryRecord = {
    recordId: randomUUID(),
    sessionId: request.sessionId,
    key: request.key,
    value: redacted.value,
    summaryValue: redacted.value,
    tier,
    source: source.source,
    sourceClass: source.sourceClass,
    sourceObservationId: request.sourceObservationId,
    sourceDigest:
      request.sourceDigest ?? sha256Hex(stableStringify(redacted.value)),
    corroboration: request.corroboration,
    secretFindings: redacted.secretFindings,
    summaryOnly: true,
    createdAt: new Date().toISOString(),
    expiresAt:
      tier === "tainted_ephemeral"
        ? new Date(Date.now() + 15 * 60_000).toISOString()
        : undefined,
    lineageChain: request.lineageChain,
    delayedTriggerIndicators: request.delayedTriggerIndicators
  };

  return {
    verdict: {
      decision,
      reasonCodes: uniq(reasonCodes),
      riskScore: clamp(riskScore),
      safeConstraints: {
        claim_profile: "secure_v6",
        staged_only: true,
        requires_corroboration: corroborationRequired(request.sourceClass),
        source_class: request.sourceClass,
        summary_only: true
      },
      telemetryTags: uniq(["memory_v6_stage", request.sourceClass, decision.toLowerCase()])
    },
    record
  };
}

export function promoteMemoryRecordV6(
  request: MemoryPromotionRequestV6,
  session: TaskSession | undefined,
  record: MemoryRecord | undefined,
  capability: CapabilityDescriptorV5 | undefined,
  approvalEnvelope: ApprovalEnvelopeV5 | undefined,
  options: {
    sourceClass: MemorySourceClassV6 | undefined;
    priorTrustedRecord?: MemoryRecord;
  }
): {
  verdict: SafeVerdict;
  promotedRecord?: MemoryRecord;
} {
  const reasonCodes: string[] = [];
  let decision: SafeVerdict["decision"] = "ALLOW";
  let riskScore = 0.35;

  if (!session) {
    decision = "BLOCK";
    reasonCodes.push("UNKNOWN_SESSION");
    riskScore = 0.99;
  }
  if (!record) {
    decision = "BLOCK";
    reasonCodes.push("UNKNOWN_MEMORY_RECORD");
    riskScore = 0.99;
  }
  if (!capability) {
    decision = "BLOCK";
    reasonCodes.push("MEMORY_PROMOTION_TICKET_REQUIRED");
    riskScore = 0.99;
  }
  if (!approvalEnvelope) {
    decision = "BLOCK";
    reasonCodes.push("APPROVAL_ENVELOPE_REQUIRED");
    riskScore = 0.99;
  }

  if (record && session && record.sessionId !== session.sessionId) {
    decision = "BLOCK";
    reasonCodes.push("MEMORY_RECORD_OUTSIDE_SESSION");
    riskScore = 0.99;
  }

  if (capability) {
    if (capability.kind !== "memory_promote") {
      decision = "BLOCK";
      reasonCodes.push("MEMORY_PROMOTION_TICKET_INVALID");
      riskScore = 0.99;
    }
    if (capability.memoryRecordId !== record?.recordId) {
      decision = "BLOCK";
      reasonCodes.push("MEMORY_PROMOTION_RECORD_MISMATCH");
      riskScore = 0.99;
    }
    if (capability.capabilityId !== request.ticketId) {
      decision = "BLOCK";
      reasonCodes.push("MEMORY_PROMOTION_TICKET_ID_MISMATCH");
      riskScore = 0.99;
    }
    if (capability.capabilityDigest !== request.ticketDigest) {
      decision = "BLOCK";
      reasonCodes.push("MEMORY_PROMOTION_TICKET_DIGEST_MISMATCH");
      riskScore = 0.99;
    }
    if (capability.consumedAt) {
      decision = "BLOCK";
      reasonCodes.push("MEMORY_PROMOTION_TICKET_ALREADY_USED");
      riskScore = 0.99;
    }
  }

  if (approvalEnvelope && capability) {
    if (approvalEnvelope.capabilityId !== capability.capabilityId) {
      decision = "BLOCK";
      reasonCodes.push("APPROVAL_CAPABILITY_MISMATCH");
      riskScore = 0.99;
    }
    if (approvalEnvelope.capabilityDigest !== capability.capabilityDigest) {
      decision = "BLOCK";
      reasonCodes.push("APPROVAL_CAPABILITY_DIGEST_MISMATCH");
      riskScore = 0.99;
    }
    if (approvalEnvelope.sinkClass !== "memory_promotion") {
      decision = "BLOCK";
      reasonCodes.push("APPROVAL_SINK_CLASS_MISMATCH");
      riskScore = 0.99;
    }
    if (approvalEnvelope.consumedAt) {
      decision = "BLOCK";
      reasonCodes.push("APPROVAL_ENVELOPE_ALREADY_USED");
      riskScore = 0.99;
    }
    if (new Date(approvalEnvelope.expiresAt).getTime() <= Date.now()) {
      decision = "BLOCK";
      reasonCodes.push("APPROVAL_ENVELOPE_EXPIRED");
      riskScore = 0.99;
    }
  }

  if (
    options.sourceClass &&
    corroborationRequired(options.sourceClass) &&
    (record?.corroboration?.length ?? 0) === 0
  ) {
    decision = "BLOCK";
    reasonCodes.push("CORROBORATION_REQUIRED");
    riskScore = 0.99;
  }

  if (decision !== "ALLOW" || !record) {
    return {
      verdict: {
        decision,
        reasonCodes: uniq(reasonCodes),
        riskScore: clamp(riskScore),
        safeConstraints: {
          claim_profile: "secure_v6",
          source_class: options.sourceClass ?? "unknown"
        },
        telemetryTags: uniq(["memory_v6_promote", decision.toLowerCase()])
      }
    };
  }

  const promotedRecord: MemoryRecord = {
    ...record,
    tier: "trusted_durable",
    summaryOnly: false,
    snapshotId: randomUUID(),
    rollbackPointId: randomUUID(),
    priorTrustedRecordId: options.priorTrustedRecord?.recordId
  };

  return {
    verdict: {
      decision,
      reasonCodes: uniq(reasonCodes),
      riskScore: clamp(riskScore),
      safeConstraints: {
        claim_profile: "secure_v6",
        source_class: options.sourceClass ?? "unknown",
        snapshot_required: true,
        rollback_required: true
      },
      telemetryTags: uniq(["memory_v6_promote", decision.toLowerCase()])
    },
    promotedRecord
  };
}

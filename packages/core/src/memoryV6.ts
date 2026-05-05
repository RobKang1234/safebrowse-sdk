import { randomUUID } from "node:crypto";

import { redactJsonValue } from "./secretIsolation.js";
import type {
  ApprovalEnvelopeV6,
  CapabilityDescriptorV6,
  MemoryRecord,
  MemoryRollbackRequest,
  MemoryRollbackResult,
  MemorySourceClassV6,
  MemoryStageRequestV6,
  MemoryStageSourceClassV5,
  SafeVerdict,
  StagedMemoryPromotionRequestV5,
  TaskSession
} from "./types.js";
import { clamp, sha256Hex, stableStringify, uniq } from "./utils.js";

function resolveMemorySource(
  sourceClass: MemoryStageSourceClassV5
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

function corroborationRequired(sourceClass: MemoryStageSourceClassV5): boolean {
  return ["web_observation", "model_summary", "retrieval_fact"].includes(sourceClass);
}

function stageVerdict(
  decision: SafeVerdict["decision"],
  reasonCodes: string[],
  riskScore: number,
  sourceClass: MemorySourceClassV6
): SafeVerdict {
  return {
    decision,
    reasonCodes: uniq(reasonCodes),
    riskScore: clamp(riskScore),
    safeConstraints: {
      claim_profile: "secure_v6",
      staged_only: true,
      requires_corroboration: corroborationRequired(sourceClass as MemoryStageSourceClassV5),
      source_class: sourceClass,
      summary_only: true
    },
    telemetryTags: uniq(["memory_v6_stage", sourceClass, decision.toLowerCase()])
  };
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
    sourceDigest: request.sourceDigest ?? sha256Hex(stableStringify(redacted.value)),
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
    verdict: stageVerdict(decision, reasonCodes, riskScore, request.sourceClass),
    record
  };
}

export function promoteMemoryRecordV6(
  request: StagedMemoryPromotionRequestV5,
  session: TaskSession | undefined,
  record: MemoryRecord | undefined,
  authority: CapabilityDescriptorV6 | undefined,
  approvalEnvelope: ApprovalEnvelopeV6 | undefined,
  options: {
    sourceClass: MemoryStageSourceClassV5 | undefined;
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
  if (!authority) {
    decision = "BLOCK";
    reasonCodes.push("MEMORY_PROMOTION_AUTHORITY_REQUIRED");
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

  if (authority) {
    if (authority.kind !== "memory_promote") {
      decision = "BLOCK";
      reasonCodes.push("MEMORY_PROMOTION_AUTHORITY_INVALID");
      riskScore = 0.99;
    }
    if (authority.memoryRecordId !== record?.recordId) {
      decision = "BLOCK";
      reasonCodes.push("MEMORY_PROMOTION_RECORD_MISMATCH");
      riskScore = 0.99;
    }
    if (authority.capabilityId !== request.ticketId) {
      decision = "BLOCK";
      reasonCodes.push("MEMORY_PROMOTION_AUTHORITY_ID_MISMATCH");
      riskScore = 0.99;
    }
    if (authority.capabilityDigest !== request.ticketDigest) {
      decision = "BLOCK";
      reasonCodes.push("MEMORY_PROMOTION_AUTHORITY_DIGEST_MISMATCH");
      riskScore = 0.99;
    }
    if (authority.consumedAt) {
      decision = "BLOCK";
      reasonCodes.push("MEMORY_PROMOTION_AUTHORITY_ALREADY_USED");
      riskScore = 0.99;
    }
  }

  if (approvalEnvelope && authority) {
    if (approvalEnvelope.capabilityId !== authority.capabilityId) {
      decision = "BLOCK";
      reasonCodes.push("APPROVAL_AUTHORITY_MISMATCH");
      riskScore = 0.99;
    }
    if (approvalEnvelope.capabilityDigest !== authority.capabilityDigest) {
      decision = "BLOCK";
      reasonCodes.push("APPROVAL_AUTHORITY_DIGEST_MISMATCH");
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

export function rollbackMemoryRecordV6(
  request: MemoryRollbackRequest,
  session: TaskSession | undefined,
  record: MemoryRecord | undefined,
  snapshot: {
    snapshotRecord?: MemoryRecord;
    baselineAbsent?: boolean;
  }
): MemoryRollbackResult {
  const reasonCodes: string[] = [];
  let decision: SafeVerdict["decision"] = "ALLOW";
  let riskScore = 0.25;

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
  if (!snapshot.snapshotRecord && !snapshot.baselineAbsent) {
    decision = "BLOCK";
    reasonCodes.push("UNKNOWN_MEMORY_SNAPSHOT");
    riskScore = 0.99;
  }

  if (record && session && record.sessionId !== session.sessionId) {
    decision = "BLOCK";
    reasonCodes.push("MEMORY_RECORD_OUTSIDE_SESSION");
    riskScore = 0.99;
  }

  if (record?.snapshotId && record.snapshotId !== request.snapshotId) {
    decision = "BLOCK";
    reasonCodes.push("SNAPSHOT_ID_MISMATCH");
    riskScore = 0.99;
  }

  if (decision !== "ALLOW") {
    return {
      verdict: {
        decision,
        reasonCodes: uniq(reasonCodes),
        riskScore: clamp(riskScore),
        safeConstraints: {
          claim_profile: "secure_v6"
        },
        telemetryTags: uniq(["memory_v6_rollback", decision.toLowerCase()])
      }
    };
  }

  if (snapshot.baselineAbsent) {
    return {
      verdict: {
        decision,
        reasonCodes: uniq(["ROLLBACK_APPLIED", "ROLLBACK_RESTORED_EMPTY_BASELINE", ...reasonCodes]),
        riskScore: clamp(riskScore),
        safeConstraints: {
          claim_profile: "secure_v6",
          rollback_applied: true,
          snapshot_id: request.snapshotId,
          baseline_absent: true
        },
        telemetryTags: uniq(["memory_v6_rollback", decision.toLowerCase()])
      }
    };
  }

  return {
    verdict: {
      decision,
      reasonCodes: uniq(["ROLLBACK_APPLIED", ...reasonCodes]),
      riskScore: clamp(riskScore),
      safeConstraints: {
        claim_profile: "secure_v6",
        rollback_applied: true,
        snapshot_id: request.snapshotId
      },
      telemetryTags: uniq(["memory_v6_rollback", decision.toLowerCase()])
    },
    restoredRecord: {
      ...snapshot.snapshotRecord!,
      tier: "trusted_durable",
      summaryOnly: false
    }
  };
}

export const promoteStagedMemoryRecordV6 = promoteMemoryRecordV6;

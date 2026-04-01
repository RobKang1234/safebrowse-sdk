import { randomUUID } from "node:crypto";

import { redactJsonValue } from "./secretIsolation.js";
import type {
  ApprovalEnvelopeV5,
  CapabilityDescriptorV5,
  MemoryPromotionRequestV5,
  MemoryRecord,
  MemoryRollbackRequest,
  MemoryRollbackResult,
  MemoryWriteRequestV5,
  SafeVerdict,
  TaskSession
} from "./types.js";
import { clamp, sha256Hex, stableStringify, uniq } from "./utils.js";

export function evaluateMemoryWriteV5(
  request: MemoryWriteRequestV5,
  session: TaskSession | undefined
): {
  verdict: SafeVerdict;
  record?: MemoryRecord;
} {
  const reasonCodes: string[] = [];
  let decision: SafeVerdict["decision"] = "ALLOW";
  let riskScore = request.durable ? 0.4 : 0.2;

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

  if (decision !== "ALLOW" || !session) {
    return {
      verdict: {
        decision,
        reasonCodes: uniq(reasonCodes),
        riskScore: clamp(riskScore),
        safeConstraints: {
          claim_profile: "secure_v5"
        },
        telemetryTags: uniq(["memory_v5_write", decision.toLowerCase()])
      }
    };
  }

  const tier = request.durable ? "candidate_durable" : "tainted_ephemeral";
  const record: MemoryRecord = {
    recordId: randomUUID(),
    sessionId: session.sessionId,
    key: request.key,
    value: redacted.value,
    summaryValue: redacted.value,
    tier,
    source: "user",
    sourceClass: "user_provided",
    secretFindings: redacted.secretFindings,
    summaryOnly: true,
    createdAt: new Date().toISOString(),
    expiresAt:
      tier === "tainted_ephemeral"
        ? new Date(Date.now() + 15 * 60_000).toISOString()
        : undefined,
    sourceDigest: sha256Hex(stableStringify(redacted.value))
  };

  return {
    verdict: {
      decision,
      reasonCodes: uniq(reasonCodes),
      riskScore: clamp(riskScore),
      safeConstraints: {
        claim_profile: "secure_v5",
        tier,
        authority_scoped: false,
        summary_only: true,
        source_class: "user_provided"
      },
      telemetryTags: uniq(["memory_v5_write", tier, decision.toLowerCase()])
    },
    record
  };
}

export function promoteMemoryRecordV5(
  request: MemoryPromotionRequestV5,
  session: TaskSession | undefined,
  record: MemoryRecord | undefined,
  capability: CapabilityDescriptorV5 | undefined,
  approvalEnvelope?: ApprovalEnvelopeV5
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

  if (record && session && record.sessionId !== session.sessionId) {
    decision = "BLOCK";
    reasonCodes.push("MEMORY_RECORD_OUTSIDE_SESSION");
    riskScore = 0.99;
  }

  if (record && record.tier === "trusted_durable") {
    decision = "BLOCK";
    reasonCodes.push("MEMORY_RECORD_ALREADY_TRUSTED");
    riskScore = 0.99;
  }

  if (!capability) {
    decision = "BLOCK";
    reasonCodes.push("MEMORY_PROMOTION_CAPABILITY_REQUIRED");
    riskScore = 0.99;
  }

  if (!approvalEnvelope) {
    decision = "BLOCK";
    reasonCodes.push("APPROVAL_ENVELOPE_REQUIRED");
    riskScore = 0.99;
  }

  if (capability && session) {
    if (capability.kind !== "memory_promote") {
      decision = "BLOCK";
      reasonCodes.push("CAPABILITY_KIND_MISMATCH");
      riskScore = 0.99;
    }
    if (capability.sessionId !== session.sessionId) {
      decision = "BLOCK";
      reasonCodes.push("CAPABILITY_OUTSIDE_SESSION");
      riskScore = 0.99;
    }
    if (capability.workflowHash !== session.workflowHash) {
      decision = "BLOCK";
      reasonCodes.push("CAPABILITY_WORKFLOW_HASH_MISMATCH");
      riskScore = 0.99;
    }
    if (capability.workflowStep !== session.currentStep) {
      decision = "BLOCK";
      reasonCodes.push("CAPABILITY_OUTSIDE_WORKFLOW_STEP");
      riskScore = 0.99;
    }
    if (capability.capabilityId !== request.capabilityId) {
      decision = "BLOCK";
      reasonCodes.push("CAPABILITY_ID_MISMATCH");
      riskScore = 0.99;
    }
    if (capability.capabilityDigest !== request.capabilityDigest) {
      decision = "BLOCK";
      reasonCodes.push("CAPABILITY_DIGEST_MISMATCH");
      riskScore = 0.99;
    }
    if (capability.memoryRecordId !== request.recordId) {
      decision = "BLOCK";
      reasonCodes.push("CAPABILITY_MEMORY_RECORD_MISMATCH");
      riskScore = 0.99;
    }
    if (capability.consumedAt) {
      decision = "BLOCK";
      reasonCodes.push("CAPABILITY_REPLAYED");
      riskScore = 0.99;
    }
    if (new Date(capability.expiresAt).getTime() <= Date.now()) {
      decision = "BLOCK";
      reasonCodes.push("CAPABILITY_EXPIRED");
      riskScore = 0.99;
    }
  }

  if (approvalEnvelope && session) {
    if (approvalEnvelope.sessionId !== session.sessionId) {
      decision = "BLOCK";
      reasonCodes.push("APPROVAL_ENVELOPE_OUTSIDE_SESSION");
      riskScore = 0.99;
    }
    if (approvalEnvelope.workflowHash !== session.workflowHash) {
      decision = "BLOCK";
      reasonCodes.push("APPROVAL_ENVELOPE_WORKFLOW_HASH_MISMATCH");
      riskScore = 0.99;
    }
    if (approvalEnvelope.sinkClass !== "memory_promotion") {
      decision = "BLOCK";
      reasonCodes.push("APPROVAL_ENVELOPE_SINK_CLASS_MISMATCH");
      riskScore = 0.99;
    }
    if (approvalEnvelope.approvalId !== request.approvalId) {
      decision = "BLOCK";
      reasonCodes.push("APPROVAL_ENVELOPE_ID_MISMATCH");
      riskScore = 0.99;
    }
    if (capability && approvalEnvelope.capabilityId !== capability.capabilityId) {
      decision = "BLOCK";
      reasonCodes.push("APPROVAL_CAPABILITY_MISMATCH");
      riskScore = 0.99;
    }
    if (capability && approvalEnvelope.capabilityDigest !== capability.capabilityDigest) {
      decision = "BLOCK";
      reasonCodes.push("APPROVAL_CAPABILITY_DIGEST_MISMATCH");
      riskScore = 0.99;
    }
    if (capability && approvalEnvelope.semanticDigest !== capability.semanticDigest) {
      decision = "BLOCK";
      reasonCodes.push("APPROVAL_SEMANTIC_DIGEST_MISMATCH");
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

  if (decision !== "ALLOW" || !record) {
    return {
      verdict: {
        decision,
        reasonCodes: uniq(reasonCodes),
        riskScore: clamp(riskScore),
        safeConstraints: {
          claim_profile: "secure_v5"
        },
        telemetryTags: uniq(["memory_v5_promote", decision.toLowerCase()])
      }
    };
  }

  const promotedRecord: MemoryRecord = {
    ...record,
    tier: "trusted_durable",
    sourceClass: "validated_system",
    summaryOnly: false,
    snapshotId: randomUUID(),
    rollbackPointId: randomUUID()
  };

  return {
    verdict: {
      decision,
      reasonCodes: uniq(reasonCodes),
      riskScore: clamp(riskScore),
      safeConstraints: {
        claim_profile: "secure_v5",
        tier: "trusted_durable",
        snapshot_required: true,
        rollback_required: true
      },
      telemetryTags: uniq(["memory_v5_promote", decision.toLowerCase()])
    },
    promotedRecord
  };
}

export function rollbackMemoryRecordV5(
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
          claim_profile: "secure_v5"
        },
        telemetryTags: uniq(["memory_v5_rollback", decision.toLowerCase()])
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
          claim_profile: "secure_v5",
          rollback_applied: true,
          snapshot_id: request.snapshotId,
          baseline_absent: true
        },
        telemetryTags: uniq(["memory_v5_rollback", decision.toLowerCase()])
      }
    };
  }

  return {
    verdict: {
      decision,
      reasonCodes: uniq(["ROLLBACK_APPLIED", ...reasonCodes]),
      riskScore: clamp(riskScore),
      safeConstraints: {
        claim_profile: "secure_v5",
        rollback_applied: true,
        snapshot_id: request.snapshotId
      },
      telemetryTags: uniq(["memory_v5_rollback", decision.toLowerCase()])
    },
    restoredRecord: {
      ...snapshot.snapshotRecord!,
      tier: "trusted_durable",
      summaryOnly: false
    }
  };
}

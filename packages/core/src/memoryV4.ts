import { randomUUID } from "node:crypto";

import { redactJsonValue } from "./secretIsolation.js";
import type {
  ApprovalGrant,
  MemoryPromotionRequest,
  MemoryRecord,
  MemoryTier,
  MemoryWriteRequest,
  RuntimeContext,
  SafeVerdict,
  TaskSession
} from "./types.js";
import { clamp, sha256Hex, stableStringify, uniq } from "./utils.js";

function buildTier(
  request: MemoryWriteRequest,
  secretFindings: string[]
): MemoryTier {
  if (request.source === "web" || request.source === "system") {
    return request.durable ? "candidate_durable" : "tainted_ephemeral";
  }

  if (request.source === "user") {
    return request.durable ? "candidate_durable" : "tainted_ephemeral";
  }

  if (secretFindings.length) {
    return request.durable ? "candidate_durable" : "tainted_ephemeral";
  }

  return request.durable ? "candidate_durable" : "tainted_ephemeral";
}

export function evaluateMemoryWriteV4(
  request: MemoryWriteRequest,
  session: TaskSession | undefined,
  context: RuntimeContext
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

  if (context.policy.protectedMemoryKeys.has(request.key.toLowerCase())) {
    decision = "BLOCK";
    reasonCodes.push("PROTECTED_MEMORY_KEY");
    riskScore = 0.99;
  }

  const redacted = redactJsonValue(request.value);
  const tier = buildTier(request, redacted.secretFindings);

  if (request.durable && request.source === "web") {
    reasonCodes.push("WEB_DERIVED_MEMORY_DOWNGRADED_TO_CANDIDATE");
    riskScore = Math.max(riskScore, 0.72);
  }

  if (redacted.secretFindings.length) {
    reasonCodes.push("SECRET_REDACTED_FROM_MEMORY");
    riskScore = Math.max(riskScore, 0.85);
  }

  if (decision === "BLOCK" || !session) {
    return {
      verdict: {
        decision,
        reasonCodes: uniq(reasonCodes),
        riskScore: clamp(riskScore),
        safeConstraints: {
          tier
        },
        telemetryTags: uniq(["memory_v4", decision.toLowerCase()])
      }
    };
  }

  const createdAt = new Date().toISOString();
  const record: MemoryRecord = {
    recordId: request.entryId || randomUUID(),
    sessionId: session.sessionId,
    key: request.key,
    value: redacted.value,
    summaryValue: redacted.value,
    tier,
    source: request.source === "web" ? "web" : request.source === "system" ? "system" : "user",
    secretFindings: redacted.secretFindings,
    summaryOnly: tier !== "trusted_durable",
    createdAt,
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
        tier,
        authority_scoped: tier === "trusted_durable",
        summary_only: tier !== "trusted_durable"
      },
      telemetryTags: uniq(["memory_v4", tier, decision.toLowerCase()])
    },
    record
  };
}

export function promoteMemoryRecordV4(
  request: MemoryPromotionRequest,
  session: TaskSession | undefined,
  record: MemoryRecord | undefined,
  approvalGrant?: ApprovalGrant
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

  if (record && session) {
    if (record.sessionId !== session.sessionId) {
      decision = "BLOCK";
      reasonCodes.push("MEMORY_RECORD_OUTSIDE_SESSION");
      riskScore = 0.99;
    }

    if (record.tier === "trusted_durable") {
      decision = "BLOCK";
      reasonCodes.push("MEMORY_RECORD_ALREADY_TRUSTED");
      riskScore = Math.max(riskScore, 0.95);
    }
  }

  const hasValidationEvidence = Boolean(request.validationEvidence?.length);
  const hasApprovalGrant = Boolean(approvalGrant);

  if (!hasValidationEvidence && !hasApprovalGrant) {
    decision = "USER_CONFIRM";
    reasonCodes.push("PROMOTION_REQUIRES_VALIDATION_OR_APPROVAL");
    riskScore = Math.max(riskScore, 0.8);
  }

  if (approvalGrant && session && record) {
    if (approvalGrant.sessionId !== session.sessionId) {
      decision = "BLOCK";
      reasonCodes.push("APPROVAL_GRANT_OUTSIDE_SESSION");
      riskScore = 0.99;
    }

    if (approvalGrant.workflowHash !== session.workflowHash) {
      decision = "BLOCK";
      reasonCodes.push("APPROVAL_GRANT_WORKFLOW_HASH_MISMATCH");
      riskScore = 0.99;
    }

    if (approvalGrant.sinkClass !== "memory_promotion") {
      decision = "BLOCK";
      reasonCodes.push("APPROVAL_GRANT_SINK_CLASS_MISMATCH");
      riskScore = 0.99;
    }
  }

  if (decision !== "ALLOW" || !record) {
    return {
      verdict: {
        decision,
        reasonCodes: uniq(reasonCodes),
        riskScore: clamp(riskScore),
        telemetryTags: uniq(["memory_v4_promotion", decision.toLowerCase()])
      }
    };
  }

  const promotedRecord: MemoryRecord = {
    ...record,
    tier: "trusted_durable",
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
        tier: "trusted_durable",
        snapshot_required: true,
        rollback_required: true
      },
      telemetryTags: uniq(["memory_v4_promotion", decision.toLowerCase()])
    },
    promotedRecord
  };
}


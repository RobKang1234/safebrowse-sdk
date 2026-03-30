import type {
  ApprovalGrant,
  RuntimeContext,
  SafeVerdict,
  TaskSession,
  ToolCallbackVerificationRequest,
  ToolCallbackVerificationResult,
  ToolOnboardingSession,
  ToolPreparationResult,
  ToolRequest
} from "./types.js";
import { prepareToolOnboarding, verifyToolCallback } from "./toolProtocolV2.js";
import { clamp, normalizeOrigin, sha256Hex, stableStringify, uniq } from "./utils.js";

function grantMatchesToolEnvelope(
  grant: ApprovalGrant | undefined,
  session: TaskSession | undefined,
  request: ToolRequest
): {
  ok: boolean;
  reasonCodes: string[];
} {
  const reasonCodes: string[] = [];

  if (!grant) {
    reasonCodes.push("APPROVAL_GRANT_REQUIRED");
    return {
      ok: false,
      reasonCodes
    };
  }

  if (!session) {
    reasonCodes.push("UNKNOWN_SESSION");
    return {
      ok: false,
      reasonCodes
    };
  }

  if (grant.sessionId !== session.sessionId) {
    reasonCodes.push("APPROVAL_GRANT_OUTSIDE_SESSION");
  }

  if (grant.workflowHash !== session.workflowHash) {
    reasonCodes.push("APPROVAL_GRANT_WORKFLOW_HASH_MISMATCH");
  }

  if (grant.connectorId !== request.toolId) {
    reasonCodes.push("APPROVAL_GRANT_CONNECTOR_MISMATCH");
  }

  if (grant.sinkClass !== "connector_oauth") {
    reasonCodes.push("APPROVAL_GRANT_SINK_CLASS_MISMATCH");
  }

  if (!grant.capabilityIds.length || !request.capabilityId) {
    reasonCodes.push("APPROVAL_GRANT_CAPABILITY_REQUIRED");
  } else if (!grant.capabilityIds.includes(request.capabilityId)) {
    reasonCodes.push("APPROVAL_GRANT_CAPABILITY_MISMATCH");
  }

  const requestedScopes = request.requestedScopes ?? request.oauthContext?.requestedScopes ?? [];
  for (const scope of requestedScopes) {
    if (!grant.scopes.includes(scope)) {
      reasonCodes.push("APPROVAL_GRANT_SCOPE_MISMATCH");
      break;
    }
  }

  const targetOrigin = normalizeOrigin(
    request.callbackOrigin ??
      request.oauthContext?.callbackOrigin ??
      request.callbackUri ??
      request.requestedRedirectUri
  );

  if (targetOrigin !== normalizeOrigin(grant.targetOrigin)) {
    reasonCodes.push("APPROVAL_GRANT_TARGET_ORIGIN_MISMATCH");
  }

  if (new Date(grant.expiresAt).getTime() <= Date.now()) {
    reasonCodes.push("APPROVAL_GRANT_EXPIRED");
  }

  return {
    ok: reasonCodes.length === 0,
    reasonCodes
  };
}

export function createApprovalGrantHash(grant: Omit<ApprovalGrant, "grantHash">): string {
  return sha256Hex(stableStringify(grant));
}

export function prepareToolOnboardingV4(
  request: ToolRequest,
  session: TaskSession | undefined,
  approvalGrant: ApprovalGrant | undefined,
  context: RuntimeContext
): ToolPreparationResult & {
  approvalVerdict: SafeVerdict;
} {
  const approvalCheck = grantMatchesToolEnvelope(approvalGrant, session, request);
  const approvalVerdict: SafeVerdict = {
    decision: approvalCheck.ok ? "ALLOW" : "BLOCK",
    reasonCodes: uniq(approvalCheck.reasonCodes),
    riskScore: clamp(approvalCheck.ok ? 0.2 : 0.99),
    safeConstraints: {
      session_bound: true,
      workflow_hash_bound: true
    },
    telemetryTags: uniq(["tool_v4_approval", approvalCheck.ok ? "allow" : "block"])
  };

  if (!approvalCheck.ok) {
    return {
      verdict: approvalVerdict,
      approvalVerdict
    };
  }

  const prepared = prepareToolOnboarding(
    {
      ...request,
      approvalBindingId: approvalGrant?.approvalGrantId
    },
    context
  );

  return {
    ...prepared,
    approvalVerdict
  };
}

export function verifyToolCallbackV4(
  request: ToolCallbackVerificationRequest,
  session: TaskSession | undefined,
  onboardingSession: ToolOnboardingSession | undefined,
  approvalGrant: ApprovalGrant | undefined,
  context: RuntimeContext
): ToolCallbackVerificationResult {
  const result = verifyToolCallback(request, onboardingSession, context);
  const reasonCodes = [...result.verdict.reasonCodes];
  let decision = result.verdict.decision;
  let riskScore = result.verdict.riskScore;

  if (!session) {
    decision = "BLOCK";
    reasonCodes.push("UNKNOWN_SESSION");
    riskScore = 0.99;
  }

  if (!approvalGrant) {
    decision = "BLOCK";
    reasonCodes.push("APPROVAL_GRANT_REQUIRED");
    riskScore = 0.99;
  } else if (session) {
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
  }

  if (onboardingSession && approvalGrant) {
    if (onboardingSession.approvalBindingId !== approvalGrant.approvalGrantId) {
      decision = "BLOCK";
      reasonCodes.push("ONBOARDING_APPROVAL_GRANT_MISMATCH");
      riskScore = 0.99;
    }
  }

  return {
    ...result,
    verdict: {
      ...result.verdict,
      decision,
      reasonCodes: uniq(reasonCodes),
      riskScore: clamp(riskScore)
    }
  };
}

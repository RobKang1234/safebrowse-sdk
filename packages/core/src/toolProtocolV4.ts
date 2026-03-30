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

function deriveSinkMetadata(
  request: ToolRequest,
  entry: ToolPreparationResult["verifiedRegistryEntry"]
): {
  derivedSinkClass: "connector_oauth" | "external_sensitive_sink";
  derivedSensitiveSink: boolean;
} {
  const requestedScopes = request.requestedScopes ?? request.oauthContext?.requestedScopes ?? [];
  const scopeImpliesWrite = requestedScopes.some((scope) =>
    /(write|submit|export|post|publish|digest:write|note:write)/i.test(scope)
  );
  const capabilityImpliesWrite =
    Boolean(entry?.writeCapability) ||
    Boolean(entry?.capabilities.some((capability) => /(write|submit|export|post|publish)/i.test(capability)));
  const sensitive =
    entry?.sinkSensitivity === "external_sensitive_sink" || scopeImpliesWrite || capabilityImpliesWrite;

  return {
    derivedSinkClass: sensitive ? "external_sensitive_sink" : "connector_oauth",
    derivedSensitiveSink: sensitive
  };
}

function lookupVerifiedEntry(
  request: ToolRequest,
  context: RuntimeContext
): ToolPreparationResult["verifiedRegistryEntry"] {
  return context.verifiedRegistry?.entries.find(
    (entry) =>
      entry.registryEntryId === request.registryEntryId ||
      entry.registryEntryId === request.toolId ||
      entry.adapterId === request.toolId
  );
}

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
  const preverifiedEntry = lookupVerifiedEntry(request, context);
  const sinkMetadata = deriveSinkMetadata(request, preverifiedEntry);
  const approvalCheck = grantMatchesToolEnvelope(approvalGrant, session, request);
  const approvalVerdict: SafeVerdict = {
    decision: approvalCheck.ok ? "ALLOW" : "BLOCK",
    reasonCodes: uniq(approvalCheck.reasonCodes),
    riskScore: clamp(approvalCheck.ok ? 0.2 : 0.99),
    safeConstraints: {
      session_bound: true,
      workflow_hash_bound: true,
      derived_sink_class: sinkMetadata.derivedSinkClass,
      derived_sensitive_sink: sinkMetadata.derivedSensitiveSink
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
  const preparedSinkMetadata = deriveSinkMetadata(
    request,
    prepared.verifiedRegistryEntry ?? preverifiedEntry
  );

  return {
    ...prepared,
    verdict: {
      ...prepared.verdict,
      safeConstraints: {
        ...prepared.verdict.safeConstraints,
        derived_sink_class: preparedSinkMetadata.derivedSinkClass,
        derived_sensitive_sink: preparedSinkMetadata.derivedSensitiveSink
      }
    },
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

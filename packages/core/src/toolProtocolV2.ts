import { randomUUID } from "node:crypto";

import type {
  OriginatingSurface,
  RuntimeContext,
  SafeVerdict,
  ToolCallbackVerificationRequest,
  ToolCallbackVerificationResult,
  ToolOnboardingSession,
  ToolPreparationResult,
  ToolRequest,
  VerifiedRegistryEntry,
  WorkflowBinding
} from "./types.js";
import { normalizeTrustSignals } from "./trust.js";
import { clamp, isPrivateHost, normalizeOrigin, sha256Hex, stableStringify, uniq } from "./utils.js";

const SECURITY_SENSITIVE_TEXT =
  /\b(?:attach|carry|forward|include|pass|relay|send|submit|transport)\b[\s\S]{0,48}\b(?:authorization proof|bearer|callback|credential|secret|session|token)\b/i;

const CALLBACK_CONTINUITY_TEXT =
  /\b(?:callback continuity|continue|continuity|handshake|onboarding|finalize|finalise|resume)\b/i;

function matchToolPatterns(
  reasons: string[],
  patterns: Array<Record<string, unknown>>
): string[] {
  const hints = reasons.join(" ").toLowerCase();
  return patterns
    .filter((pattern) => {
      const family = String(pattern.family_key ?? "").toLowerCase();
      const name = String(pattern.pattern_name ?? "").toLowerCase();
      return (
        (hints.includes("registry") && family.includes("registry")) ||
        (hints.includes("redirect") && name.includes("redirect")) ||
        (hints.includes("callback") && name.includes("callback")) ||
        (hints.includes("schema") && family.includes("schema")) ||
        (hints.includes("artifact") && family.includes("artifact")) ||
        (hints.includes("token") && name.includes("token"))
      );
    })
    .slice(0, 8)
    .map((pattern) => String(pattern.pattern_id ?? "unknown-tool-pattern"));
}

export function computeToolManifestHash(request: Pick<
  ToolRequest,
  "toolId" | "description" | "authType" | "requestedScopes" | "callbackUri" | "requestedRedirectUri"
>): string {
  return sha256Hex(
    stableStringify({
      toolId: request.toolId,
      description: request.description,
      authType: request.authType ?? "none",
      requestedScopes: request.requestedScopes ?? [],
      callbackUri: request.callbackUri ?? request.requestedRedirectUri ?? ""
    })
  );
}

export function computeToolSchemaHash(schemaDescriptions?: string[]): string {
  return sha256Hex(stableStringify(schemaDescriptions ?? []));
}

function findRegistryEntry(
  request: ToolRequest,
  context: RuntimeContext
): VerifiedRegistryEntry | undefined {
  const registry = context.verifiedRegistry;
  if (!registry?.signatureVerified) {
    return undefined;
  }

  const requestIds = uniq([
    request.registryEntryId,
    request.toolId
  ].filter((value): value is string => Boolean(value?.trim())));

  return registry.entries.find(
    (entry) =>
      requestIds.includes(entry.registryEntryId) || requestIds.includes(entry.adapterId)
  );
}

function inferOriginatingSurface(request: ToolRequest): OriginatingSurface {
  if (request.originatingSurface) {
    return request.originatingSurface;
  }
  if (request.sourceArtifactId) {
    return "artifact";
  }
  if (request.schemaDescriptions?.length) {
    return "tool_schema";
  }
  return "tool_description";
}

function buildWorkflowBinding(
  request: ToolRequest,
  lineageChain: string[],
  derivedTaintClass: WorkflowBinding["derivedTaintClass"],
  createdAt: string
): WorkflowBinding {
  return {
    bindingId: randomUUID(),
    sourceObservationId: request.sourceObservationId,
    sourceArtifactId: request.sourceArtifactId,
    originatingSurface: inferOriginatingSurface(request),
    lineageChain,
    derivedTaintClass,
    createdAt
  };
}

function isEntryExpired(entry?: VerifiedRegistryEntry, now = new Date()): boolean {
  if (!entry?.expiresAt) {
    return false;
  }
  return new Date(entry.expiresAt).getTime() <= now.getTime();
}

function resolveCallbackUri(request: ToolRequest): string | undefined {
  return (
    request.oauthContext?.callbackUri ??
    request.callbackUri ??
    request.oauthContext?.redirectUri ??
    request.requestedRedirectUri
  );
}

function resolveCallbackOrigin(request: ToolRequest, callbackUri?: string): string {
  return normalizeOrigin(
    request.oauthContext?.callbackOrigin ?? request.callbackOrigin ?? callbackUri
  );
}

function containsSensitiveCallbackText(request: ToolRequest): boolean {
  const texts = [request.description, ...(request.schemaDescriptions ?? [])].filter(Boolean);
  return texts.some(
    (text) => SECURITY_SENSITIVE_TEXT.test(text) || CALLBACK_CONTINUITY_TEXT.test(text)
  );
}

function derivedTaintClass(request: ToolRequest, trustTaint: string): WorkflowBinding["derivedTaintClass"] {
  if (request.sourceArtifactId || request.originatingSurface === "artifact") {
    return "tainted";
  }
  if (request.schemaDescriptions?.length || request.originatingSurface === "tool_schema") {
    return "tainted";
  }
  return trustTaint === "trusted" ? "trusted" : "tainted";
}

function isPrivilegedConnectorFlow(request: ToolRequest, callbackUri?: string): boolean {
  return Boolean(
    request.authType === "oauth" ||
      callbackUri ||
      request.requestedScopes?.length ||
      request.oauthContext?.requestedScopes?.length
  );
}

function isAllowedCallbackOrigin(
  callbackOrigin: string,
  entry: VerifiedRegistryEntry,
  context: RuntimeContext
): boolean {
  if (entry.allowedCallbackOrigins.length) {
    return entry.allowedCallbackOrigins.includes(callbackOrigin);
  }

  if (callbackOrigin === "unknown") {
    return false;
  }

  let host = callbackOrigin;
  try {
    host = new URL(callbackOrigin).hostname;
  } catch {
    host = callbackOrigin;
  }

  if (isPrivateHost(host)) {
    return entry.allowLoopbackCallbacks || context.policy.allowLoopbackCallbacksInDev;
  }

  return true;
}

export function prepareToolOnboarding(
  request: ToolRequest,
  context: RuntimeContext
): ToolPreparationResult {
  const now = (context.now?.() ?? new Date()).toISOString();
  const trustSignals = normalizeTrustSignals({
    artifactKind: "tool_manifest",
    extractionMethod: "api",
    ...(request.trustSignals ?? {})
  });
  const lineageChain = trustSignals.lineageChain;
  const taint = derivedTaintClass(request, trustSignals.taintClass);
  const workflowBinding = buildWorkflowBinding(request, lineageChain, taint, now);
  const callbackUri = resolveCallbackUri(request);
  const callbackOrigin = resolveCallbackOrigin(request, callbackUri);
  const entry = findRegistryEntry(request, context);

  const reasonCodes: string[] = [];
  let decision: SafeVerdict["decision"] = "ALLOW";
  let riskScore = 0.35;

  if (context.policy.requireVerifiedRegistry && !context.verifiedRegistry?.signatureVerified) {
    decision = "BLOCK";
    reasonCodes.push("REGISTRY_BUNDLE_UNAVAILABLE");
    riskScore = 0.98;
  }

  if (!entry) {
    decision = "BLOCK";
    reasonCodes.push("REGISTRY_ENTRY_NOT_FOUND");
    riskScore = Math.max(riskScore, 0.98);
  }

  if (entry && isEntryExpired(entry, new Date(now))) {
    decision = "BLOCK";
    reasonCodes.push("REGISTRY_ENTRY_EXPIRED");
    riskScore = Math.max(riskScore, 0.98);
  }

  if (
    entry &&
    context.policy.allowedRegistrySigners.size &&
    !context.policy.allowedRegistrySigners.has(entry.signer.toLowerCase())
  ) {
    decision = "BLOCK";
    reasonCodes.push("REGISTRY_SIGNER_NOT_ALLOWLISTED");
    riskScore = Math.max(riskScore, 0.95);
  }

  if (entry && request.authType && request.authType !== entry.authType) {
    decision = "BLOCK";
    reasonCodes.push("AUTH_TYPE_MISMATCH");
    riskScore = Math.max(riskScore, 0.92);
  }

  if (request.tokenPassthroughRequested || containsSensitiveCallbackText(request)) {
    decision = "BLOCK";
    reasonCodes.push("SECURITY_SENSITIVE_CALLBACK_TEXT");
    riskScore = Math.max(riskScore, 0.99);
  }

  if (entry?.manifestHash) {
    if (!request.manifestHash) {
      decision = "BLOCK";
      reasonCodes.push("MANIFEST_HASH_REQUIRED");
      riskScore = Math.max(riskScore, 0.97);
    } else if (request.manifestHash !== entry.manifestHash) {
      decision = "BLOCK";
      reasonCodes.push("MANIFEST_HASH_MISMATCH");
      riskScore = Math.max(riskScore, 0.99);
    }
  }

  if (entry?.schemaHash) {
    if (!request.schemaHash) {
      decision = "BLOCK";
      reasonCodes.push("SCHEMA_HASH_REQUIRED");
      riskScore = Math.max(riskScore, 0.97);
    } else if (request.schemaHash !== entry.schemaHash) {
      decision = "BLOCK";
      reasonCodes.push("SCHEMA_HASH_MISMATCH");
      riskScore = Math.max(riskScore, 0.99);
    }
  }

  if (request.egressHosts?.some((host) => isPrivateHost(host)) && !entry?.allowPrivateEgress) {
    decision = "BLOCK";
    reasonCodes.push("PRIVATE_EGRESS_DENIED");
    riskScore = Math.max(riskScore, 0.96);
  }

  if (request.authType === "oauth") {
    if (!callbackUri) {
      decision = "BLOCK";
      reasonCodes.push("CALLBACK_URI_REQUIRED");
      riskScore = Math.max(riskScore, 0.96);
    }

    if (
      entry &&
      context.policy.enforceExactRedirectUri &&
      callbackUri &&
      !entry.allowedRedirectUris.includes(callbackUri)
    ) {
      decision = "BLOCK";
      reasonCodes.push("CALLBACK_URI_NOT_VERIFIED");
      riskScore = Math.max(riskScore, 0.99);
    }

    if (entry && callbackUri && !isAllowedCallbackOrigin(callbackOrigin, entry, context)) {
      decision = "BLOCK";
      reasonCodes.push("CALLBACK_ORIGIN_NOT_VERIFIED");
      riskScore = Math.max(riskScore, 0.99);
    }
  }

  if (request.requestedScopes?.length && entry?.allowedScopes.length) {
    const unknownScopes = request.requestedScopes.filter(
      (scope) => !entry.allowedScopes.includes(scope)
    );
    if (unknownScopes.length) {
      decision = "BLOCK";
      reasonCodes.push("REQUESTED_SCOPE_NOT_VERIFIED");
      riskScore = Math.max(riskScore, 0.97);
    }
  }

  const privilegedConnectorFlow = isPrivilegedConnectorFlow(request, callbackUri);
  const untrustedDerivation = taint !== "trusted";
  if (privilegedConnectorFlow && context.policy.requireApprovalBinding && !request.approvalBindingId) {
    decision = untrustedDerivation ? "BLOCK" : decision === "ALLOW" ? "USER_CONFIRM" : decision;
    reasonCodes.push(
      untrustedDerivation
        ? "APPROVAL_BINDING_REQUIRED_FOR_UNTRUSTED_FLOW"
        : "APPROVAL_BINDING_REQUIRED"
    );
    riskScore = Math.max(riskScore, 0.82);
  }

  if (privilegedConnectorFlow && untrustedDerivation && request.approvalBindingId && decision === "ALLOW") {
    decision = "USER_CONFIRM";
    reasonCodes.push("UNTRUSTED_CONNECTOR_FLOW_REQUIRES_CONFIRMATION");
    riskScore = Math.max(riskScore, 0.88);
  }

  const matchedPatternIds = matchToolPatterns(
    reasonCodes,
    context.knowledgeBase?.toolProtocolPatterns ?? []
  );

  return {
    verdict: {
      decision,
      reasonCodes: uniq(reasonCodes),
      riskScore: clamp(riskScore),
      safeConstraints: {
        verified_registry_required: context.policy.requireVerifiedRegistry,
        approval_binding_required: context.policy.requireApprovalBinding,
        oauth_mode: request.authType === "oauth" ? "pkce_s256" : "none",
        allowed_callback_fields: ["code", "state", "iss"],
        callback_origin: callbackOrigin,
        derived_from_untrusted_artifact: request.originatingSurface === "artifact",
        derived_from_schema_text: inferOriginatingSurface(request) === "tool_schema"
      },
      matchedPatternIds,
      incidentPlaybookId:
        decision === "BLOCK" ? "IR-04" : decision === "USER_CONFIRM" ? "IR-02" : undefined,
      telemetryTags: uniq([
        request.toolId,
        inferOriginatingSurface(request),
        decision.toLowerCase()
      ])
    },
    verifiedRegistryEntry: entry,
    workflowBinding
  };
}

export function verifyToolCallback(
  request: ToolCallbackVerificationRequest,
  session: ToolOnboardingSession | undefined,
  context: RuntimeContext
): ToolCallbackVerificationResult {
  const verifiedAt = (context.now?.() ?? new Date()).toISOString();
  const reasonCodes: string[] = [];
  let decision: SafeVerdict["decision"] = "ALLOW";
  let riskScore = 0.2;

  if (!session) {
    decision = "BLOCK";
    reasonCodes.push("UNKNOWN_ONBOARDING_SESSION");
    riskScore = 0.99;
  } else {
    if (session.status !== "prepared") {
      decision = "BLOCK";
      reasonCodes.push("ONBOARDING_SESSION_NOT_ACTIVE");
      riskScore = Math.max(riskScore, 0.99);
    }
    if (new Date(session.expiresAt).getTime() <= new Date(verifiedAt).getTime()) {
      decision = "BLOCK";
      reasonCodes.push("ONBOARDING_SESSION_EXPIRED");
      riskScore = Math.max(riskScore, 0.99);
    }
    if (request.state !== session.state) {
      decision = "BLOCK";
      reasonCodes.push("CALLBACK_STATE_MISMATCH");
      riskScore = Math.max(riskScore, 0.99);
    }
    if (request.callbackUri !== session.callbackUri) {
      decision = "BLOCK";
      reasonCodes.push("CALLBACK_URI_MISMATCH");
      riskScore = Math.max(riskScore, 0.99);
    }
    if (normalizeOrigin(request.callbackOrigin) !== normalizeOrigin(session.callbackOrigin)) {
      decision = "BLOCK";
      reasonCodes.push("CALLBACK_ORIGIN_MISMATCH");
      riskScore = Math.max(riskScore, 0.99);
    }
  }

  const payloadKeys = Object.keys(request.payload ?? {});
  if (payloadKeys.some((key) => /(authorization|bearer|secret|session|token)/i.test(key))) {
    decision = "BLOCK";
    reasonCodes.push("DISALLOWED_CALLBACK_FIELDS");
    riskScore = Math.max(riskScore, 0.99);
  }

  const matchedPatternIds = matchToolPatterns(
    reasonCodes,
    context.knowledgeBase?.toolProtocolPatterns ?? []
  );

  return {
    verdict: {
      decision,
      reasonCodes: uniq(reasonCodes),
      riskScore: clamp(riskScore),
      safeConstraints: {
        verified_registry_required: context.policy.requireVerifiedRegistry,
        approval_binding_required: context.policy.requireApprovalBinding,
        oauth_mode: "pkce_s256",
        allowed_callback_fields: ["code", "state", "iss"]
      },
      matchedPatternIds,
      incidentPlaybookId: decision === "BLOCK" ? "IR-04" : undefined,
      telemetryTags: uniq([request.sessionId, decision.toLowerCase()])
    },
    sessionId: request.sessionId,
    verifiedAt
  };
}

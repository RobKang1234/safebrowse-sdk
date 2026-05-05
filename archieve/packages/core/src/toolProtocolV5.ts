import { randomUUID, verify as verifySignatureBuffer, type KeyObject } from "node:crypto";

import type {
  ApprovalEnvelopeV5,
  CapabilityDescriptorV5,
  ConnectorHandle,
  SafeVerdict,
  TaskSession,
  ToolCallbackVerificationRequest,
  ToolOnboardingSessionV5,
  VerifiedRegistryEntry
} from "./types.js";
import { clamp, normalizeOrigin, sha256Hex, stableStringify, uniq } from "./utils.js";

export function createApprovalIntentPayloadV5(input: {
  sessionId: string;
  workflowHash: string;
  capabilityId: string;
  capabilityDigest: string;
  expiresInSeconds?: number;
}): string {
  return stableStringify({
    sessionId: input.sessionId,
    workflowHash: input.workflowHash,
    capabilityId: input.capabilityId,
    capabilityDigest: input.capabilityDigest,
    expiresInSeconds: input.expiresInSeconds ?? 600
  });
}

export function verifyApprovalIntentSignatureV5(
  payload: string,
  brokerSignature: string,
  brokerPublicKey: KeyObject | undefined
): boolean {
  if (!brokerPublicKey) {
    return false;
  }

  try {
    return verifySignatureBuffer(
      null,
      Buffer.from(payload, "utf8"),
      brokerPublicKey,
      Buffer.from(brokerSignature, "base64")
    );
  } catch {
    return false;
  }
}

function requestedScopesHash(scopes: string[]): string {
  return sha256Hex(stableStringify([...scopes].sort()));
}

function scopesSubsetSafe(requested: string[], allowed: string[]): boolean {
  const allowedSet = new Set(allowed);
  return requested.every((scope) => allowedSet.has(scope));
}

function registryEntryActive(entry: VerifiedRegistryEntry): boolean {
  if (!entry.expiresAt) {
    return true;
  }
  return new Date(entry.expiresAt).getTime() > Date.now();
}

function matchesOptional(expected: string | undefined, actual: string | undefined): boolean {
  return expected === undefined || expected === actual;
}

export function issueApprovalEnvelopeV5(input: {
  session: TaskSession | undefined;
  capability: CapabilityDescriptorV5 | undefined;
  brokerSignature: string;
  brokerSignatureVerified: boolean;
  expiresInSeconds?: number;
}): {
  verdict: SafeVerdict;
  approvalEnvelope?: ApprovalEnvelopeV5;
} {
  const reasonCodes: string[] = [];
  let decision: SafeVerdict["decision"] = "ALLOW";
  let riskScore = 0.2;

  if (!input.session) {
    decision = "BLOCK";
    reasonCodes.push("UNKNOWN_SESSION");
    riskScore = 0.99;
  }

  if (!input.capability) {
    decision = "BLOCK";
    reasonCodes.push("UNKNOWN_CAPABILITY");
    riskScore = 0.99;
  }

  if (!input.brokerSignatureVerified) {
    decision = "BLOCK";
    reasonCodes.push("APPROVAL_BROKER_SIGNATURE_INVALID");
    riskScore = 0.99;
  }

  if (input.capability) {
    if (input.capability.consumedAt) {
      decision = "BLOCK";
      reasonCodes.push("CAPABILITY_REPLAYED");
      riskScore = 0.99;
    }
    if (!["connector_prepare", "memory_promote"].includes(input.capability.kind)) {
      decision = "BLOCK";
      reasonCodes.push("CAPABILITY_NOT_APPROVABLE");
      riskScore = 0.99;
    }

    if (input.capability.kind === "connector_prepare" && !input.capability.connectorId) {
      decision = "BLOCK";
      reasonCodes.push("CONNECTOR_ID_REQUIRED");
      riskScore = 0.99;
    }

    if (
      input.capability.kind === "connector_prepare" &&
      (!input.capability.callbackUri || !input.capability.callbackOrigin)
    ) {
      decision = "BLOCK";
      reasonCodes.push("CALLBACK_BINDING_REQUIRED");
      riskScore = 0.99;
    }

    if (input.session) {
      if (input.capability.sessionId !== input.session.sessionId) {
        decision = "BLOCK";
        reasonCodes.push("CAPABILITY_OUTSIDE_SESSION");
        riskScore = 0.99;
      }
      if (input.capability.workflowHash !== input.session.workflowHash) {
        decision = "BLOCK";
        reasonCodes.push("CAPABILITY_WORKFLOW_HASH_MISMATCH");
        riskScore = 0.99;
      }
      if (input.capability.workflowStep !== input.session.currentStep) {
        decision = "BLOCK";
        reasonCodes.push("CAPABILITY_OUTSIDE_WORKFLOW_STEP");
        riskScore = 0.99;
      }
    }
  }

  if (decision !== "ALLOW" || !input.session || !input.capability) {
    return {
      verdict: {
        decision,
        reasonCodes: uniq(reasonCodes),
        riskScore: clamp(riskScore),
        safeConstraints: {
          claim_profile: "secure_v5"
        },
        telemetryTags: uniq(["approval_v5_issue", decision.toLowerCase()])
      }
    };
  }

  const issuedAt = new Date().toISOString();
  const expiresAt = new Date(
    Date.now() + (input.expiresInSeconds ?? 600) * 1000
  ).toISOString();

  const approvalEnvelope: ApprovalEnvelopeV5 = {
    approvalId: randomUUID(),
    sessionId: input.session.sessionId,
    workflowHash: input.session.workflowHash,
    workflowStep: input.session.currentStep,
    capabilityId: input.capability.capabilityId,
    capabilityDigest: input.capability.capabilityDigest,
    semanticDigest: input.capability.semanticDigest,
    sinkClass:
      input.capability.kind === "memory_promote" ? "memory_promotion" : "connector_oauth",
    connectorId: input.capability.connectorId,
    registryEntryId: input.capability.registryEntryId,
    registryBundleId: input.capability.registryBundleId,
    registryBundleVersion: input.capability.registryBundleVersion,
    registrySigner: input.capability.registrySigner,
    requestedScopes: input.capability.requestedScopes ?? [],
    requestedScopesHash: requestedScopesHash(input.capability.requestedScopes ?? []),
    callbackUri: input.capability.callbackUri,
    callbackOrigin: input.capability.callbackOrigin,
    manifestHash: input.capability.manifestHash,
    schemaHash: input.capability.schemaHash,
    targetOrigin: input.capability.targetOrigin,
    issuedAt,
    expiresAt,
    brokerSignature: input.brokerSignature,
    signedByBroker: true,
    consumedAt: undefined,
    onboardingSessionId: undefined
  };

  return {
    verdict: {
      decision,
      reasonCodes: [],
      riskScore: clamp(riskScore),
      safeConstraints: {
        claim_profile: "secure_v5",
        sink_class: approvalEnvelope.sinkClass,
        semantic_digest: approvalEnvelope.semanticDigest,
        approval_broker_verified: true
      },
      telemetryTags: uniq(["approval_v5_issue", "allow"])
    },
    approvalEnvelope
  };
}

export function prepareToolOnboardingV5(input: {
  session: TaskSession | undefined;
  capability: CapabilityDescriptorV5 | undefined;
  approvalEnvelope: ApprovalEnvelopeV5 | undefined;
  verifiedRegistryEntry: VerifiedRegistryEntry | undefined;
}): {
  verdict: SafeVerdict;
  onboardingSession?: ToolOnboardingSessionV5;
} {
  const reasonCodes: string[] = [];
  let decision: SafeVerdict["decision"] = "ALLOW";
  let riskScore = 0.2;

  if (!input.session) {
    decision = "BLOCK";
    reasonCodes.push("UNKNOWN_SESSION");
    riskScore = 0.99;
  }
  if (!input.capability) {
    decision = "BLOCK";
    reasonCodes.push("UNKNOWN_CAPABILITY");
    riskScore = 0.99;
  }
  if (!input.approvalEnvelope) {
    decision = "BLOCK";
    reasonCodes.push("APPROVAL_ENVELOPE_REQUIRED");
    riskScore = 0.99;
  }
  if (!input.verifiedRegistryEntry) {
    decision = "BLOCK";
    reasonCodes.push("REGISTRY_ENTRY_REQUIRED");
    riskScore = 0.99;
  }

  if (input.capability) {
    if (input.capability.kind !== "connector_prepare") {
      decision = "BLOCK";
      reasonCodes.push("CAPABILITY_KIND_MISMATCH");
      riskScore = 0.99;
    }
    if (input.capability.consumedAt) {
      decision = "BLOCK";
      reasonCodes.push("CAPABILITY_REPLAYED");
      riskScore = 0.99;
    }
  }

  if (input.approvalEnvelope && input.capability) {
    if (input.approvalEnvelope.capabilityId !== input.capability.capabilityId) {
      decision = "BLOCK";
      reasonCodes.push("APPROVAL_CAPABILITY_MISMATCH");
      riskScore = 0.99;
    }
    if (input.approvalEnvelope.capabilityDigest !== input.capability.capabilityDigest) {
      decision = "BLOCK";
      reasonCodes.push("APPROVAL_CAPABILITY_DIGEST_MISMATCH");
      riskScore = 0.99;
    }
    if (input.approvalEnvelope.semanticDigest !== input.capability.semanticDigest) {
      decision = "BLOCK";
      reasonCodes.push("APPROVAL_SEMANTIC_DIGEST_MISMATCH");
      riskScore = 0.99;
    }
    if (input.approvalEnvelope.sinkClass !== "connector_oauth") {
      decision = "BLOCK";
      reasonCodes.push("APPROVAL_SINK_CLASS_MISMATCH");
      riskScore = 0.99;
    }
    if (
      normalizeOrigin(input.approvalEnvelope.targetOrigin) !==
      normalizeOrigin(input.capability.targetOrigin)
    ) {
      decision = "BLOCK";
      reasonCodes.push("APPROVAL_TARGET_ORIGIN_MISMATCH");
      riskScore = 0.99;
    }
    if (new Date(input.approvalEnvelope.expiresAt).getTime() <= Date.now()) {
      decision = "BLOCK";
      reasonCodes.push("APPROVAL_ENVELOPE_EXPIRED");
      riskScore = 0.99;
    }
    if (input.approvalEnvelope.consumedAt) {
      decision = "BLOCK";
      reasonCodes.push("APPROVAL_ENVELOPE_ALREADY_USED");
      riskScore = 0.99;
    }
    if (input.approvalEnvelope.onboardingSessionId) {
      decision = "BLOCK";
      reasonCodes.push("APPROVAL_ENVELOPE_ALREADY_BOUND");
      riskScore = 0.99;
    }
  }

  if (input.verifiedRegistryEntry && input.approvalEnvelope) {
    if (!registryEntryActive(input.verifiedRegistryEntry)) {
      decision = "BLOCK";
      reasonCodes.push("REGISTRY_ENTRY_EXPIRED");
      riskScore = 0.99;
    }
    if (input.approvalEnvelope.registryEntryId !== input.verifiedRegistryEntry.registryEntryId) {
      decision = "BLOCK";
      reasonCodes.push("APPROVAL_REGISTRY_ENTRY_MISMATCH");
      riskScore = 0.99;
    }
    if (input.approvalEnvelope.connectorId !== input.verifiedRegistryEntry.adapterId) {
      decision = "BLOCK";
      reasonCodes.push("APPROVAL_CONNECTOR_ID_MISMATCH");
      riskScore = 0.99;
    }
    if (
      normalizeOrigin(input.approvalEnvelope.callbackOrigin) !==
      normalizeOrigin(input.verifiedRegistryEntry.allowedCallbackOrigins[0])
    ) {
      decision = "BLOCK";
      reasonCodes.push("APPROVAL_CALLBACK_ORIGIN_MISMATCH");
      riskScore = 0.99;
    }
    if (
      !input.approvalEnvelope.callbackUri ||
      !input.verifiedRegistryEntry.allowedRedirectUris.includes(input.approvalEnvelope.callbackUri)
    ) {
      decision = "BLOCK";
      reasonCodes.push("APPROVAL_CALLBACK_URI_MISMATCH");
      riskScore = 0.99;
    }
    if (
      requestedScopesHash(input.approvalEnvelope.requestedScopes) !==
        input.approvalEnvelope.requestedScopesHash ||
      !scopesSubsetSafe(input.approvalEnvelope.requestedScopes, input.verifiedRegistryEntry.allowedScopes)
    ) {
      decision = "BLOCK";
      reasonCodes.push("APPROVAL_SCOPE_MISMATCH");
      riskScore = 0.99;
    }
    if (input.verifiedRegistryEntry.authType !== "oauth") {
      decision = "BLOCK";
      reasonCodes.push("REGISTRY_AUTH_TYPE_MISMATCH");
      riskScore = 0.99;
    }
    if (
      !matchesOptional(input.approvalEnvelope.registryBundleId, input.verifiedRegistryEntry.bundleId) ||
      !matchesOptional(
        input.approvalEnvelope.registryBundleVersion,
        input.verifiedRegistryEntry.bundleVersion
      ) ||
      !matchesOptional(input.approvalEnvelope.registrySigner, input.verifiedRegistryEntry.signer)
    ) {
      decision = "BLOCK";
      reasonCodes.push("APPROVAL_REGISTRY_ATTESTATION_MISMATCH");
      riskScore = 0.99;
    }
    if (
      !matchesOptional(input.approvalEnvelope.manifestHash, input.verifiedRegistryEntry.manifestHash)
    ) {
      decision = "BLOCK";
      reasonCodes.push("MANIFEST_HASH_MISMATCH");
      riskScore = 0.99;
    }
    if (!matchesOptional(input.approvalEnvelope.schemaHash, input.verifiedRegistryEntry.schemaHash)) {
      decision = "BLOCK";
      reasonCodes.push("SCHEMA_HASH_MISMATCH");
      riskScore = 0.99;
    }
  }

  if (input.capability && input.approvalEnvelope) {
    if (input.capability.connectorId !== input.approvalEnvelope.connectorId) {
      decision = "BLOCK";
      reasonCodes.push("APPROVAL_CONNECTOR_ID_MISMATCH");
      riskScore = 0.99;
    }
    if (input.capability.callbackUri !== input.approvalEnvelope.callbackUri) {
      decision = "BLOCK";
      reasonCodes.push("APPROVAL_CALLBACK_URI_MISMATCH");
      riskScore = 0.99;
    }
    if (input.capability.callbackOrigin !== input.approvalEnvelope.callbackOrigin) {
      decision = "BLOCK";
      reasonCodes.push("APPROVAL_CALLBACK_ORIGIN_MISMATCH");
      riskScore = 0.99;
    }
    if (
      requestedScopesHash(input.capability.requestedScopes ?? []) !==
      input.approvalEnvelope.requestedScopesHash
    ) {
      decision = "BLOCK";
      reasonCodes.push("APPROVAL_SCOPE_MISMATCH");
      riskScore = 0.99;
    }
    if (
      !matchesOptional(input.capability.registryBundleId, input.approvalEnvelope.registryBundleId) ||
      !matchesOptional(
        input.capability.registryBundleVersion,
        input.approvalEnvelope.registryBundleVersion
      ) ||
      !matchesOptional(input.capability.registrySigner, input.approvalEnvelope.registrySigner)
    ) {
      decision = "BLOCK";
      reasonCodes.push("APPROVAL_REGISTRY_ATTESTATION_MISMATCH");
      riskScore = 0.99;
    }
    if (!matchesOptional(input.capability.manifestHash, input.approvalEnvelope.manifestHash)) {
      decision = "BLOCK";
      reasonCodes.push("MANIFEST_HASH_MISMATCH");
      riskScore = 0.99;
    }
    if (!matchesOptional(input.capability.schemaHash, input.approvalEnvelope.schemaHash)) {
      decision = "BLOCK";
      reasonCodes.push("SCHEMA_HASH_MISMATCH");
      riskScore = 0.99;
    }
  }

  if (
    decision !== "ALLOW" ||
    !input.session ||
    !input.capability ||
    !input.approvalEnvelope ||
    !input.verifiedRegistryEntry ||
    !input.capability.callbackUri ||
    !input.capability.callbackOrigin ||
    !input.capability.connectorId
  ) {
    return {
      verdict: {
        decision,
        reasonCodes: uniq(reasonCodes),
        riskScore: clamp(riskScore),
        safeConstraints: {
          claim_profile: "secure_v5"
        },
        telemetryTags: uniq(["tool_v5_prepare", decision.toLowerCase()])
      }
    };
  }

  const createdAt = new Date().toISOString();
  return {
    verdict: {
      decision,
      reasonCodes: [],
      riskScore: clamp(riskScore),
      safeConstraints: {
        claim_profile: "secure_v5",
        callback_origin: input.capability.callbackOrigin,
        connector_id: input.capability.connectorId
      },
      telemetryTags: uniq(["tool_v5_prepare", "allow"])
    },
    onboardingSession: {
      onboardingSessionId: randomUUID(),
      sessionId: input.session.sessionId,
      approvalId: input.approvalEnvelope.approvalId,
      capabilityDigest: input.capability.capabilityDigest,
      connectorId: input.capability.connectorId,
      registryEntryId: input.verifiedRegistryEntry.registryEntryId,
      registryBundleId: input.verifiedRegistryEntry.bundleId,
      registryBundleVersion: input.verifiedRegistryEntry.bundleVersion,
      registrySigner: input.verifiedRegistryEntry.signer,
      callbackUri: input.capability.callbackUri,
      callbackOrigin: input.capability.callbackOrigin,
      requestedScopes: input.capability.requestedScopes ?? [],
      manifestHash: input.capability.manifestHash,
      schemaHash: input.capability.schemaHash,
      state: randomUUID(),
      pkceMethod: "S256",
      createdAt,
      expiresAt: new Date(Date.now() + 5 * 60 * 1000).toISOString(),
      status: "prepared"
    }
  };
}

export function verifyToolCallbackV5(input: {
  session: TaskSession | undefined;
  capability: CapabilityDescriptorV5 | undefined;
  approvalEnvelope: ApprovalEnvelopeV5 | undefined;
  onboardingSession: ToolOnboardingSessionV5 | undefined;
  verifiedRegistryEntry: VerifiedRegistryEntry | undefined;
  request: ToolCallbackVerificationRequest;
}): {
  verdict: SafeVerdict;
  connectorHandle?: ConnectorHandle;
} {
  const reasonCodes: string[] = [];
  let decision: SafeVerdict["decision"] = "ALLOW";
  let riskScore = 0.2;

  if (!input.session) {
    decision = "BLOCK";
    reasonCodes.push("UNKNOWN_SESSION");
    riskScore = 0.99;
  }
  if (!input.capability) {
    decision = "BLOCK";
    reasonCodes.push("UNKNOWN_CAPABILITY");
    riskScore = 0.99;
  }
  if (!input.approvalEnvelope) {
    decision = "BLOCK";
    reasonCodes.push("APPROVAL_ENVELOPE_REQUIRED");
    riskScore = 0.99;
  }
  if (!input.onboardingSession) {
    decision = "BLOCK";
    reasonCodes.push("UNKNOWN_ONBOARDING_SESSION");
    riskScore = 0.99;
  }
  if (!input.verifiedRegistryEntry) {
    decision = "BLOCK";
    reasonCodes.push("REGISTRY_ENTRY_REQUIRED");
    riskScore = 0.99;
  }

  if (input.onboardingSession && input.approvalEnvelope) {
    if (input.onboardingSession.approvalId !== input.approvalEnvelope.approvalId) {
      decision = "BLOCK";
      reasonCodes.push("ONBOARDING_APPROVAL_MISMATCH");
      riskScore = 0.99;
    }
  }
  if (input.onboardingSession && input.capability) {
    if (input.onboardingSession.capabilityDigest !== input.capability.capabilityDigest) {
      decision = "BLOCK";
      reasonCodes.push("ONBOARDING_CAPABILITY_DIGEST_MISMATCH");
      riskScore = 0.99;
    }
    if (
      !matchesOptional(input.onboardingSession.registryBundleId, input.capability.registryBundleId) ||
      !matchesOptional(
        input.onboardingSession.registryBundleVersion,
        input.capability.registryBundleVersion
      ) ||
      !matchesOptional(input.onboardingSession.registrySigner, input.capability.registrySigner)
    ) {
      decision = "BLOCK";
      reasonCodes.push("ONBOARDING_REGISTRY_ATTESTATION_MISMATCH");
      riskScore = 0.99;
    }
    if (!matchesOptional(input.onboardingSession.manifestHash, input.capability.manifestHash)) {
      decision = "BLOCK";
      reasonCodes.push("MANIFEST_HASH_MISMATCH");
      riskScore = 0.99;
    }
    if (!matchesOptional(input.onboardingSession.schemaHash, input.capability.schemaHash)) {
      decision = "BLOCK";
      reasonCodes.push("SCHEMA_HASH_MISMATCH");
      riskScore = 0.99;
    }
  }
  if (input.approvalEnvelope && input.capability) {
    if (input.approvalEnvelope.onboardingSessionId !== input.onboardingSession?.onboardingSessionId) {
      decision = "BLOCK";
      reasonCodes.push("APPROVAL_ONBOARDING_SESSION_MISMATCH");
      riskScore = 0.99;
    }
    if (!input.approvalEnvelope.consumedAt) {
      decision = "BLOCK";
      reasonCodes.push("APPROVAL_ENVELOPE_NOT_PREPARED");
      riskScore = 0.99;
    }
    if (input.approvalEnvelope.capabilityDigest !== input.capability.capabilityDigest) {
      decision = "BLOCK";
      reasonCodes.push("APPROVAL_CAPABILITY_DIGEST_MISMATCH");
      riskScore = 0.99;
    }
    if (
      !matchesOptional(input.approvalEnvelope.registryBundleId, input.capability.registryBundleId) ||
      !matchesOptional(
        input.approvalEnvelope.registryBundleVersion,
        input.capability.registryBundleVersion
      ) ||
      !matchesOptional(input.approvalEnvelope.registrySigner, input.capability.registrySigner)
    ) {
      decision = "BLOCK";
      reasonCodes.push("APPROVAL_REGISTRY_ATTESTATION_MISMATCH");
      riskScore = 0.99;
    }
    if (!matchesOptional(input.approvalEnvelope.manifestHash, input.capability.manifestHash)) {
      decision = "BLOCK";
      reasonCodes.push("MANIFEST_HASH_MISMATCH");
      riskScore = 0.99;
    }
    if (!matchesOptional(input.approvalEnvelope.schemaHash, input.capability.schemaHash)) {
      decision = "BLOCK";
      reasonCodes.push("SCHEMA_HASH_MISMATCH");
      riskScore = 0.99;
    }
  }
  if (input.onboardingSession) {
    if (new Date(input.onboardingSession.expiresAt).getTime() <= Date.now()) {
      decision = "BLOCK";
      reasonCodes.push("ONBOARDING_SESSION_EXPIRED");
      riskScore = 0.99;
    }
    if (input.onboardingSession.status !== "prepared") {
      decision = "BLOCK";
      reasonCodes.push("ONBOARDING_SESSION_ALREADY_USED");
      riskScore = 0.99;
    }
    if (input.request.state !== input.onboardingSession.state) {
      decision = "BLOCK";
      reasonCodes.push("OAUTH_STATE_MISMATCH");
      riskScore = 0.99;
    }
    if (input.request.sessionId !== input.onboardingSession.onboardingSessionId) {
      decision = "BLOCK";
      reasonCodes.push("CALLBACK_SESSION_MISMATCH");
      riskScore = 0.99;
    }
    if (input.request.callbackUri !== input.onboardingSession.callbackUri) {
      decision = "BLOCK";
      reasonCodes.push("CALLBACK_URI_MISMATCH");
      riskScore = 0.99;
    }
    if (
      normalizeOrigin(input.request.callbackOrigin) !== normalizeOrigin(input.onboardingSession.callbackOrigin)
    ) {
      decision = "BLOCK";
      reasonCodes.push("CALLBACK_ORIGIN_MISMATCH");
      riskScore = 0.99;
    }
  }

  if (input.verifiedRegistryEntry && input.onboardingSession) {
    if (!registryEntryActive(input.verifiedRegistryEntry)) {
      decision = "BLOCK";
      reasonCodes.push("REGISTRY_ENTRY_EXPIRED");
      riskScore = 0.99;
    }
    if (!input.verifiedRegistryEntry.allowedRedirectUris.includes(input.request.callbackUri)) {
      decision = "BLOCK";
      reasonCodes.push("CALLBACK_URI_MISMATCH");
      riskScore = 0.99;
    }
    if (!input.verifiedRegistryEntry.allowedCallbackOrigins.includes(input.request.callbackOrigin)) {
      decision = "BLOCK";
      reasonCodes.push("CALLBACK_ORIGIN_MISMATCH");
      riskScore = 0.99;
    }
    if (
      requestedScopesHash(input.onboardingSession.requestedScopes) !==
        requestedScopesHash(input.approvalEnvelope?.requestedScopes ?? []) ||
      !scopesSubsetSafe(input.onboardingSession.requestedScopes, input.verifiedRegistryEntry.allowedScopes)
    ) {
      decision = "BLOCK";
      reasonCodes.push("CALLBACK_SCOPE_MISMATCH");
      riskScore = 0.99;
    }
    if (
      !matchesOptional(input.onboardingSession.registryBundleId, input.verifiedRegistryEntry.bundleId) ||
      !matchesOptional(
        input.onboardingSession.registryBundleVersion,
        input.verifiedRegistryEntry.bundleVersion
      ) ||
      !matchesOptional(input.onboardingSession.registrySigner, input.verifiedRegistryEntry.signer)
    ) {
      decision = "BLOCK";
      reasonCodes.push("CALLBACK_REGISTRY_ATTESTATION_MISMATCH");
      riskScore = 0.99;
    }
    if (!matchesOptional(input.onboardingSession.manifestHash, input.verifiedRegistryEntry.manifestHash)) {
      decision = "BLOCK";
      reasonCodes.push("MANIFEST_HASH_MISMATCH");
      riskScore = 0.99;
    }
    if (!matchesOptional(input.onboardingSession.schemaHash, input.verifiedRegistryEntry.schemaHash)) {
      decision = "BLOCK";
      reasonCodes.push("SCHEMA_HASH_MISMATCH");
      riskScore = 0.99;
    }
  }

  if (
    input.request.payload &&
    Object.keys(input.request.payload).some((key) => !["code", "state"].includes(key))
  ) {
    decision = "BLOCK";
    reasonCodes.push("CALLBACK_PAYLOAD_FIELD_NOT_ALLOWLISTED");
    riskScore = 0.99;
  }

  if (
    decision !== "ALLOW" ||
    !input.session ||
    !input.approvalEnvelope ||
    !input.onboardingSession ||
    !input.verifiedRegistryEntry ||
    !input.capability ||
    !input.capability.connectorId
  ) {
    return {
      verdict: {
        decision,
        reasonCodes: uniq(reasonCodes),
        riskScore: clamp(riskScore),
        safeConstraints: {
          claim_profile: "secure_v5"
        },
        telemetryTags: uniq(["tool_v5_callback", decision.toLowerCase()])
      }
    };
  }

  return {
    verdict: {
      decision,
      reasonCodes: [],
      riskScore: clamp(riskScore),
      safeConstraints: {
        claim_profile: "secure_v5",
        connector_id: input.capability.connectorId,
        registry_entry_id: input.verifiedRegistryEntry.registryEntryId
      },
      telemetryTags: uniq(["tool_v5_callback", "allow"])
    },
    connectorHandle: {
      handleId: randomUUID(),
      sessionId: input.session.sessionId,
      approvalId: input.approvalEnvelope.approvalId,
      connectorId: input.capability.connectorId,
      registryEntryId: input.verifiedRegistryEntry.registryEntryId,
      registryBundleId: input.verifiedRegistryEntry.bundleId,
      registryBundleVersion: input.verifiedRegistryEntry.bundleVersion,
      registrySigner: input.verifiedRegistryEntry.signer,
      manifestHash: input.onboardingSession.manifestHash,
      schemaHash: input.onboardingSession.schemaHash,
      scopeSet: input.approvalEnvelope.requestedScopes,
      issuedAt: new Date().toISOString(),
      expiresAt: new Date(Date.now() + 10 * 60 * 1000).toISOString(),
      status: "active"
    }
  };
}

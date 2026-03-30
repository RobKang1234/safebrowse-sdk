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
    requestedScopes: input.capability.requestedScopes ?? [],
    requestedScopesHash: requestedScopesHash(input.capability.requestedScopes ?? []),
    callbackUri: input.capability.callbackUri,
    callbackOrigin: input.capability.callbackOrigin,
    targetOrigin: input.capability.targetOrigin,
    issuedAt,
    expiresAt,
    brokerSignature: input.brokerSignature,
    signedByBroker: true
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
  }

  if (input.verifiedRegistryEntry && input.approvalEnvelope) {
    if (input.approvalEnvelope.registryEntryId !== input.verifiedRegistryEntry.registryEntryId) {
      decision = "BLOCK";
      reasonCodes.push("APPROVAL_REGISTRY_ENTRY_MISMATCH");
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
      callbackUri: input.capability.callbackUri,
      callbackOrigin: input.capability.callbackOrigin,
      requestedScopes: input.capability.requestedScopes ?? [],
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
    if (normalizeOrigin(input.request.callbackUri) !== normalizeOrigin(input.onboardingSession.callbackUri)) {
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
      scopeSet: input.approvalEnvelope.requestedScopes,
      issuedAt: new Date().toISOString(),
      expiresAt: new Date(Date.now() + 10 * 60 * 1000).toISOString(),
      status: "active"
    }
  };
}

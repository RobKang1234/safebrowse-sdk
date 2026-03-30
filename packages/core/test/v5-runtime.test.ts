import { generateKeyPairSync, sign as signBuffer } from "node:crypto";

import { describe, expect, it } from "vitest";

import {
  compileObservationV5,
  compilePolicy,
  createApprovalIntentPayloadV5,
  evaluateCapabilityUseV5,
  evaluateMemoryWriteV5,
  issueApprovalEnvelopeV5,
  mintCapabilitiesForObservationV5,
  mintMemoryPromotionCapabilityV5,
  prepareToolOnboardingV5,
  promoteMemoryRecordV5,
  verifyApprovalIntentSignatureV5,
  verifyToolCallbackV5,
  type CapabilityUseRequestV5,
  type PolicyPack,
  type TaskSession,
  type VerifiedRegistryBundle
} from "@safebrowse/core";

const policyPack: PolicyPack = {
  packId: "test-pack-v5",
  profile: "research",
  version: "0.5.0",
  layers: [
    {
      name: "base",
      version: "0.5.0",
      profile: "research",
      origins: {
        readOnlyAllow: ["https://safe.example", "https://docs.python.org"],
        writableAllow: []
      },
      actions: {
        allow: ["navigate", "connector_prepare"],
        requireApproval: ["download"],
        deny: ["exfiltrate"]
      },
      artifacts: {
        enableDocumentHandoff: true,
        quarantineOnHiddenTextMismatch: true,
        allowMimeTypes: ["application/pdf", "text/html"]
      },
      memory: {
        durableWrites: "deny",
        protectedKeys: ["user_identity", "credential_scope", "payment_context"]
      },
      toolProtocol: {
        forbidTokenPassthrough: true,
        enforceExactRedirectUri: true,
        allowedRegistrySigners: ["safebrowse-dev"],
        requireVerifiedRegistry: true,
        requireApprovalBinding: true,
        requireOauthStateBinding: true,
        taintedConnectorFlowDecision: "block",
        allowLoopbackCallbacksInDev: false
      },
      telemetry: {
        replayBundle: true,
        redactSensitiveValues: true,
        sampling: "full"
      }
    }
  ]
};

const manifest = {
  toolId: "citation-sync-safe",
  description: "Citation sync connector for scholarly cross-reference enrichment.",
  authType: "oauth" as const,
  requestedScopes: ["citation:read"],
  callbackUri: "https://safe.example/oauth/callback"
};

const verifiedRegistry: VerifiedRegistryBundle = {
  bundleId: "safebrowse-local-registry",
  version: "5",
  signer: "safebrowse-dev",
  generatedAt: "2026-03-30T00:00:00.000Z",
  publicKeyId: "safebrowse_vf_ed25519_public.pem",
  signatureVerified: true,
  entries: [
    {
      registryEntryId: "citation-sync-safe",
      adapterId: "citation-sync-safe",
      bundleId: "safebrowse-local-registry",
      bundleVersion: "5",
      signer: "safebrowse-dev",
      authType: "oauth",
      capabilities: ["citation_sync"],
      allowedTransports: ["https"],
      allowedRedirectUris: ["https://safe.example/oauth/callback"],
      allowedCallbackOrigins: ["https://safe.example"],
      allowedScopes: ["citation:read"]
    }
  ]
};

const runtime = {
  policy: compilePolicy(policyPack),
  verifiedRegistry,
  knowledgeBase: {
    promptInjectionPatterns: [],
    actionIntegrityPatterns: [],
    artifactSurfacePatterns: [],
    toolProtocolPatterns: [],
    memoryContextPatterns: [],
    trustSignalsCatalog: [],
    policyControls: [],
    incidentPlaybooks: [],
    evaluationScenarios: [],
    sourceRegistry: []
  }
};

function buildSession(): TaskSession {
  return {
    sessionId: "session-v5",
    taskId: "task-v5",
    userGoal: "Review public documentation safely",
    allowedOrigins: ["https://safe.example", "https://docs.python.org"],
    allowedVerbs: ["navigate", "connector_prepare"],
    forbiddenSinks: [],
    workflowHash: "workflow-hash-v5",
    currentStep: 0,
    createdAt: "2026-03-30T00:00:00.000Z",
    expiresAt: "2026-03-30T01:00:00.000Z",
    claimProfile: "secure_v5",
    approvalBrokerRequired: true,
    legacyRoutesDisabled: true
  };
}

describe("safebrowse core runtime v5", () => {
  it("does not mint capabilities from hidden HTML anchors", () => {
    const session = buildSession();
    const observed = compileObservationV5(
      {
        surfaceType: "html",
        url: "https://safe.example/page",
        html: `
          <html>
            <body>
              <main>Visible docs only.</main>
              <div hidden><a href="https://docs.python.org/3/tutorial/">continuity path</a></div>
            </body>
          </html>
        `
      },
      runtime
    );

    expect(observed.compiledObservation.parseStatus).toBe("compiled");
    expect(observed.plannerView.blockedChannels).toContain("hidden_text");

    const capabilities = mintCapabilitiesForObservationV5(
      session,
      observed.compiledObservation,
      observed.plannerView
    );
    expect(capabilities).toEqual([]);
  });

  it("mints visible-only navigation capabilities and requires digest-bound use", () => {
    const session = buildSession();
    const observed = compileObservationV5(
      {
        surfaceType: "html",
        url: "https://safe.example/page",
        html: `<html><body><main>Visible docs only.</main><a href="https://docs.python.org/3/tutorial/">Docs</a></body></html>`
      },
      runtime
    );

    const [capability] = mintCapabilitiesForObservationV5(
      session,
      observed.compiledObservation,
      observed.plannerView
    );
    expect(capability).toBeTruthy();
    expect(capability.visibleOnlyFlag).toBe(true);
    expect(capability.sourceNodePathHash).toBeTruthy();

    const allow = evaluateCapabilityUseV5(
      {
        sessionId: session.sessionId,
        capabilityId: capability.capabilityId,
        capabilityDigest: capability.capabilityDigest,
        parameters: {}
      },
      session,
      capability,
      {
        alreadyUsed: false
      }
    );
    expect(allow.decision).toBe("ALLOW");

    const mismatch = evaluateCapabilityUseV5(
      {
        sessionId: session.sessionId,
        capabilityId: capability.capabilityId,
        capabilityDigest: "different-digest",
        parameters: {}
      },
      session,
      capability,
      {
        alreadyUsed: false
      }
    );
    expect(mismatch.decision).toBe("BLOCK");
    expect(mismatch.reasonCodes).toContain("CAPABILITY_DIGEST_MISMATCH");
  });

  it("binds approval envelopes to connector capabilities and exact callback semantics", () => {
    const session = buildSession();
    const observed = compileObservationV5(
      {
        surfaceType: "tool_manifest",
        url: "https://safe.example/connectors/citation-sync-safe",
        toolId: manifest.toolId,
        description: manifest.description,
        authType: "oauth",
        requestedScopes: ["citation:read"],
        callbackUri: manifest.callbackUri,
        callbackOrigin: "https://safe.example"
      },
      runtime
    );

    const [capability] = mintCapabilitiesForObservationV5(
      session,
      observed.compiledObservation,
      observed.plannerView,
      {
        verifiedRegistryEntry: verifiedRegistry.entries[0],
        connectorId: manifest.toolId,
        requestedScopes: ["citation:read"],
        callbackUri: manifest.callbackUri,
        callbackOrigin: "https://safe.example"
      }
    );
    expect(capability.kind).toBe("connector_prepare");

    const { privateKey, publicKey } = generateKeyPairSync("ed25519");
    const approvalPayload = createApprovalIntentPayloadV5({
      sessionId: session.sessionId,
      workflowHash: session.workflowHash,
      capabilityId: capability.capabilityId,
      capabilityDigest: capability.capabilityDigest
    });
    const signature = signBuffer(null, Buffer.from(approvalPayload, "utf8"), privateKey).toString(
      "base64"
    );
    const verified = verifyApprovalIntentSignatureV5(approvalPayload, signature, publicKey);
    expect(verified).toBe(true);

    const issued = issueApprovalEnvelopeV5({
      session,
      capability,
      brokerSignature: signature,
      brokerSignatureVerified: verified
    });
    expect(issued.verdict.decision).toBe("ALLOW");
    expect(issued.approvalEnvelope?.connectorId).toBe("citation-sync-safe");

    const prepared = prepareToolOnboardingV5({
      session,
      capability,
      approvalEnvelope: issued.approvalEnvelope,
      verifiedRegistryEntry: verifiedRegistry.entries[0]
    });
    expect(prepared.verdict.decision).toBe("ALLOW");

    const callback = verifyToolCallbackV5({
      session,
      capability,
      approvalEnvelope: issued.approvalEnvelope,
      onboardingSession: prepared.onboardingSession,
      verifiedRegistryEntry: verifiedRegistry.entries[0],
      request: {
        sessionId: prepared.onboardingSession?.onboardingSessionId ?? "",
        callbackUri: manifest.callbackUri,
        callbackOrigin: "https://safe.example",
        state: prepared.onboardingSession?.state ?? "",
        payload: {
          code: "auth-code",
          state: prepared.onboardingSession?.state ?? ""
        }
      }
    });
    expect(callback.verdict.decision).toBe("ALLOW");
    expect(callback.connectorHandle?.connectorId).toBe("citation-sync-safe");
  });

  it("blocks approval issuance for a visible navigate capability", () => {
    const session = buildSession();
    const observed = compileObservationV5(
      {
        surfaceType: "html",
        url: "https://safe.example/page",
        html: `<html><body><a href="https://docs.python.org/3/tutorial/">Docs</a></body></html>`
      },
      runtime
    );
    const [capability] = mintCapabilitiesForObservationV5(
      session,
      observed.compiledObservation,
      observed.plannerView
    );

    const issued = issueApprovalEnvelopeV5({
      session,
      capability,
      brokerSignature: "fake",
      brokerSignatureVerified: true
    });
    expect(issued.verdict.decision).toBe("BLOCK");
    expect(issued.verdict.reasonCodes).toContain("CAPABILITY_NOT_APPROVABLE");
  });

  it("keeps v5 memory writes summary-only and allows trusted promotion with evidence", () => {
    const session = buildSession();
    const writeResult = evaluateMemoryWriteV5(
      {
        sessionId: session.sessionId,
        inputKind: "user_note",
        key: "workflow_hint",
        value: {
          note: "needs review"
        },
        durable: true
      },
      session
    );

    expect(writeResult.verdict.decision).toBe("ALLOW");
    expect(writeResult.record?.tier).toBe("candidate_durable");
    expect(writeResult.record?.summaryOnly).toBe(true);

    const promotionCapability = mintMemoryPromotionCapabilityV5(session, {
      recordId: writeResult.record?.recordId ?? "",
      sourceDigest: writeResult.record?.sourceDigest,
      sourceObservationId: writeResult.record?.sourceObservationId,
      key: writeResult.record?.key ?? "workflow_hint",
      valueDigest: writeResult.record?.sourceDigest ?? ""
    });
    expect(promotionCapability.kind).toBe("memory_promote");

    const promoted = promoteMemoryRecordV5(
      {
        sessionId: session.sessionId,
        recordId: writeResult.record?.recordId ?? "",
        validationEvidence: ["validated by reviewer"]
      },
      session,
      writeResult.record
    );
    expect(promoted.verdict.decision).toBe("ALLOW");
    expect(promoted.promotedRecord?.tier).toBe("trusted_durable");
  });
});

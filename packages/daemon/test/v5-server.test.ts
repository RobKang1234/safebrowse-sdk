import { generateKeyPairSync } from "node:crypto";

import { afterEach, describe, expect, it } from "vitest";

import {
  computeToolManifestHash,
  computeToolSchemaHash,
  type PolicyPack,
  type VerifiedRegistryBundle
} from "@safebrowse/core";
import {
  issueApprovalSignature,
  startApprovalBroker
} from "@safebrowse/approval-broker";
import { createSafeBrowseServer } from "@safebrowse/daemon";

const policyPack: PolicyPack = {
  packId: "daemon-test-pack-v5",
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
  callbackUri: "https://safe.example/oauth/callback",
  schemaDescriptions: [] as string[]
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
      allowedScopes: ["citation:read"],
      manifestHash: computeToolManifestHash(manifest),
      schemaHash: computeToolSchemaHash(manifest.schemaDescriptions)
    }
  ]
};

const servers: Array<{ close: () => Promise<void> }> = [];
const brokers: Array<{ close: () => Promise<void> }> = [];

async function startTestBroker() {
  const { privateKey } = generateKeyPairSync("ed25519");
  const privateKeyPem = privateKey.export({ format: "pem", type: "pkcs8" }).toString();
  const authToken = "test-approval-broker-token";
  const broker = await startApprovalBroker({
    host: "127.0.0.1",
    port: 0,
    privateKeyPem,
    authToken
  });

  brokers.push({
    close: () =>
      new Promise<void>((resolvePromise) => {
        broker.server.close(() => resolvePromise());
      })
  });

  return {
    baseUrl: `http://127.0.0.1:${broker.port}`,
    authToken,
    publicKeyPem: broker.publicKeyPem
  };
}

async function startTestServer(deploymentProfile: "development" | "secure_v5" = "secure_v5") {
  const broker = await startTestBroker();
  const server = await createSafeBrowseServer({
    policyPack,
    verifiedRegistry,
    deploymentProfile,
    approvalBrokerPublicKeyPem: broker.publicKeyPem,
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
  });

  await new Promise<void>((resolvePromise, rejectPromise) => {
    server.once("error", rejectPromise);
    server.listen(0, "127.0.0.1", () => resolvePromise());
  });
  const address = server.address();
  if (!address || typeof address === "string") {
    throw new Error("Missing address");
  }

  servers.push({
    close: () =>
      new Promise<void>((resolvePromise) => {
        server.close(() => resolvePromise());
      })
  });

  return {
    baseUrl: `http://127.0.0.1:${address.port}`,
    broker
  };
}

async function signApproval(
  session: Record<string, any>,
  capability: Record<string, any>,
  broker: Awaited<ReturnType<typeof startTestBroker>>
) {
  return (
    await issueApprovalSignature(broker.baseUrl, broker.authToken, {
      sessionId: session.sessionId,
      workflowHash: session.workflowHash,
      capabilityId: capability.capabilityId,
      capabilityDigest: capability.capabilityDigest
    })
  ).brokerSignature;
}

afterEach(async () => {
  await Promise.all(servers.splice(0).map((entry) => entry.close()));
  await Promise.all(brokers.splice(0).map((entry) => entry.close()));
});

describe("safebrowse daemon v5 routes", () => {
  it("disables legacy routes in secure_v5 and reports secure health posture", async () => {
    const { baseUrl } = await startTestServer();
    const health = await fetch(`${baseUrl}/health`).then((response) => response.json());

    expect(health.deploymentProfile).toBe("secure_v5");
    expect(health.claimBearingReady).toBe(true);
    expect(health.legacyRoutesEnabled).toBe(false);
    expect(health.approvalBroker.required).toBe(true);
    expect(health.approvalBroker.mode).toBe("external_service");
    expect(health.parserIsolation.enforced).toBe(true);
    expect(health.parserIsolation.mode).toBe("node_permission_process");
    expect(health.parserIsolation.permissionModelEnabled).toBe(true);
    expect(health.parserIsolation.lastCheckedAt).toBeTruthy();

    const legacy = await fetch(`${baseUrl}/v1/action`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({
        actionId: "legacy-test",
        verb: "navigate",
        targetUrl: "https://docs.python.org/3/tutorial/",
        trustSignals: {
          sourceOrigin: "https://safe.example",
          frameOrigin: "https://safe.example"
        }
      })
    }).then((response) => response.json());

    expect(legacy.error).toBe("route_disabled_in_secure_v5");
  });

  it("reuses cached parser isolation state across repeated health checks", async () => {
    const { baseUrl } = await startTestServer();
    const first = await fetch(`${baseUrl}/health`).then((response) => response.json());
    const second = await fetch(`${baseUrl}/health`).then((response) => response.json());

    expect(first.parserIsolation.lastCheckedAt).toBeTruthy();
    expect(second.parserIsolation.lastCheckedAt).toBe(first.parserIsolation.lastCheckedAt);
  });

  it("does not mint capabilities from hidden anchors on first observation", async () => {
    const { baseUrl } = await startTestServer();
    const session = await fetch(`${baseUrl}/v5/session/start`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({
        taskId: "task-v5-hidden",
        userGoal: "Review docs safely",
        allowedOrigins: ["https://safe.example", "https://docs.python.org"],
        allowedVerbs: ["navigate"],
        forbiddenSinks: []
      })
    }).then((response) => response.json());

    const observe = await fetch(`${baseUrl}/v5/observe`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({
        sessionId: session.session.sessionId,
        capture: {
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
        }
      })
    }).then((response) => response.json());

    expect(observe.plannerView.blockedChannels).toContain("hidden_text");
    expect(observe.capabilities).toEqual([]);
    expect(observe.observationVerdict.safeConstraints.authority_eligible).toBe(false);
  });

  it("requires a broker-signed approval envelope for connector onboarding", async () => {
    const { baseUrl, broker } = await startTestServer();
    const session = await fetch(`${baseUrl}/v5/session/start`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({
        taskId: "task-v5-tool",
        userGoal: "Review connector onboarding safely",
        allowedOrigins: ["https://safe.example"],
        allowedVerbs: ["connector_prepare"],
        forbiddenSinks: []
      })
    }).then((response) => response.json());

    const observe = await fetch(`${baseUrl}/v5/observe`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({
        sessionId: session.session.sessionId,
        capture: {
          surfaceType: "tool_manifest",
          url: "https://safe.example/connectors/citation-sync-safe",
          toolId: manifest.toolId,
          description: manifest.description,
          schemaDescriptions: manifest.schemaDescriptions,
          authType: "oauth",
          requestedScopes: ["citation:read"],
          callbackUri: manifest.callbackUri,
          callbackOrigin: "https://safe.example"
        }
      })
    }).then((response) => response.json());

    const capability = observe.capabilities[0];
    const brokerSignature = await signApproval(session.session, capability, broker);

    const issued = await fetch(`${baseUrl}/v5/approval/issue`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({
        sessionId: session.session.sessionId,
        capabilityId: capability.capabilityId,
        capabilityDigest: capability.capabilityDigest,
        brokerSignature
      })
    }).then((response) => response.json());

    expect(issued.verdict.decision).toBe("ALLOW");

    const prepared = await fetch(`${baseUrl}/v5/tool/prepare`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({
        sessionId: session.session.sessionId,
        approvalId: issued.approvalEnvelope.approvalId
      })
    }).then((response) => response.json());

    expect(prepared.verdict.decision).toBe("ALLOW");

    const callback = await fetch(`${baseUrl}/v5/tool/callback/verify`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({
        sessionId: session.session.sessionId,
        approvalId: issued.approvalEnvelope.approvalId,
        onboardingSessionId: prepared.onboardingSession.onboardingSessionId,
        request: {
          sessionId: prepared.onboardingSession.onboardingSessionId,
          callbackUri: manifest.callbackUri,
          callbackOrigin: "https://safe.example",
          state: prepared.onboardingSession.state,
          payload: {
            code: "auth-code",
            state: prepared.onboardingSession.state
          }
        }
      })
    }).then((response) => response.json());

    expect(callback.verdict.decision).toBe("ALLOW");
    expect(callback.connectorHandle.connectorId).toBe("citation-sync-safe");
  });

  it("reports an honest claim profile and retires stale capabilities after a later risky observation", async () => {
    const { baseUrl } = await startTestServer("development");
    const session = await fetch(`${baseUrl}/v5/session/start`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({
        taskId: "task-v5-dev",
        userGoal: "Review docs safely",
        allowedOrigins: ["https://safe.example", "https://docs.python.org"],
        allowedVerbs: ["navigate"],
        forbiddenSinks: []
      })
    }).then((response) => response.json());

    expect(session.session.claimProfile).toBeUndefined();

    const initialObserve = await fetch(`${baseUrl}/v5/observe`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({
        sessionId: session.session.sessionId,
        capture: {
          surfaceType: "html",
          url: "https://safe.example/page",
          html: `<html><body><a href="https://docs.python.org/3/tutorial/">Docs</a></body></html>`
        }
      })
    }).then((response) => response.json());

    const retiredCapability = initialObserve.capabilities[0];
    expect(retiredCapability.kind).toBe("navigate");

    const riskyObserve = await fetch(`${baseUrl}/v5/observe`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({
        sessionId: session.session.sessionId,
        capture: {
          surfaceType: "html",
          url: "https://safe.example/page-2",
          html: `<html><body><main>Visible docs only.</main><div hidden><a href="https://docs.python.org/3/tutorial/">continuity path</a></div></body></html>`
        }
      })
    }).then((response) => response.json());

    expect(riskyObserve.capabilities).toEqual([]);

    const staleUse = await fetch(`${baseUrl}/v5/capability/use`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({
        sessionId: session.session.sessionId,
        capabilityId: retiredCapability.capabilityId,
        capabilityDigest: retiredCapability.capabilityDigest,
        parameters: {}
      })
    }).then((response) => response.json());

    expect(staleUse.verdict.decision).toBe("BLOCK");
    expect(staleUse.verdict.reasonCodes).toContain("UNKNOWN_CAPABILITY");
  });

  it("requires approval-bound memory promotion and restores the prior trusted baseline on rollback", async () => {
    const { baseUrl, broker } = await startTestServer();
    const session = await fetch(`${baseUrl}/v5/session/start`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({
        taskId: "task-v5-memory",
        userGoal: "Store notes safely",
        allowedOrigins: ["https://safe.example"],
        allowedVerbs: ["memory_promote"],
        forbiddenSinks: []
      })
    }).then((response) => response.json());

    const firstWrite = await fetch(`${baseUrl}/v5/memory/write`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({
        sessionId: session.session.sessionId,
        inputKind: "user_note",
        key: "workflow_hint",
        value: { note: "baseline" },
        durable: true
      })
    }).then((response) => response.json());

    const firstPromoteBlocked = await fetch(`${baseUrl}/v5/memory/promote`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({
        sessionId: session.session.sessionId,
        recordId: firstWrite.record.recordId
      })
    }).then((response) => response.json());

    expect(firstPromoteBlocked.verdict.decision).toBe("BLOCK");
    expect(firstPromoteBlocked.verdict.reasonCodes).toContain("MEMORY_PROMOTION_CAPABILITY_REQUIRED");

    const firstSignature = await signApproval(session.session, firstWrite.promotionCapability, broker);
    const firstApproval = await fetch(`${baseUrl}/v5/approval/issue`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({
        sessionId: session.session.sessionId,
        capabilityId: firstWrite.promotionCapability.capabilityId,
        capabilityDigest: firstWrite.promotionCapability.capabilityDigest,
        brokerSignature: firstSignature
      })
    }).then((response) => response.json());

    const firstPromote = await fetch(`${baseUrl}/v5/memory/promote`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({
        sessionId: session.session.sessionId,
        recordId: firstWrite.record.recordId,
        capabilityId: firstWrite.promotionCapability.capabilityId,
        capabilityDigest: firstWrite.promotionCapability.capabilityDigest,
        approvalId: firstApproval.approvalEnvelope.approvalId
      })
    }).then((response) => response.json());

    expect(firstPromote.verdict.decision).toBe("ALLOW");

    const secondWrite = await fetch(`${baseUrl}/v5/memory/write`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({
        sessionId: session.session.sessionId,
        inputKind: "user_note",
        key: "workflow_hint",
        value: { note: "replacement" },
        durable: true
      })
    }).then((response) => response.json());

    const secondSignature = await signApproval(session.session, secondWrite.promotionCapability, broker);
    const secondApproval = await fetch(`${baseUrl}/v5/approval/issue`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({
        sessionId: session.session.sessionId,
        capabilityId: secondWrite.promotionCapability.capabilityId,
        capabilityDigest: secondWrite.promotionCapability.capabilityDigest,
        brokerSignature: secondSignature
      })
    }).then((response) => response.json());

    const secondPromote = await fetch(`${baseUrl}/v5/memory/promote`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({
        sessionId: session.session.sessionId,
        recordId: secondWrite.record.recordId,
        capabilityId: secondWrite.promotionCapability.capabilityId,
        capabilityDigest: secondWrite.promotionCapability.capabilityDigest,
        approvalId: secondApproval.approvalEnvelope.approvalId
      })
    }).then((response) => response.json());

    expect(secondPromote.verdict.decision).toBe("ALLOW");

    const rollback = await fetch(`${baseUrl}/v5/memory/rollback`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({
        sessionId: session.session.sessionId,
        recordId: secondPromote.promotedRecord.recordId,
        snapshotId: secondPromote.promotedRecord.snapshotId
      })
    }).then((response) => response.json());

    expect(rollback.verdict.decision).toBe("ALLOW");
    expect(rollback.restoredRecord.value).toEqual({ note: "baseline" });
  });

  it("blocks scope escalation, exact callback-path mismatch, approval reuse, and callback mismatch after a valid prepare", async () => {
    const { baseUrl, broker } = await startTestServer();
    const session = await fetch(`${baseUrl}/v5/session/start`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({
        taskId: "task-v5-tool-hardening",
        userGoal: "Review connector onboarding safely",
        allowedOrigins: ["https://safe.example"],
        allowedVerbs: ["connector_prepare"],
        forbiddenSinks: []
      })
    }).then((response) => response.json());

    const badScopeObserve = await fetch(`${baseUrl}/v5/observe`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({
        sessionId: session.session.sessionId,
        capture: {
          ...manifest,
          surfaceType: "tool_manifest",
          url: "https://safe.example/connectors/citation-sync-safe",
          requestedScopes: ["citation:write"],
          callbackOrigin: "https://safe.example"
        }
      })
    }).then((response) => response.json());

    expect(badScopeObserve.capabilities).toEqual([]);

    const badCallbackObserve = await fetch(`${baseUrl}/v5/observe`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({
        sessionId: session.session.sessionId,
        capture: {
          ...manifest,
          surfaceType: "tool_manifest",
          url: "https://safe.example/connectors/citation-sync-safe",
          callbackUri: "https://safe.example/oauth/callback/unexpected",
          callbackOrigin: "https://safe.example"
        }
      })
    }).then((response) => response.json());

    expect(badCallbackObserve.capabilities).toEqual([]);

    const observe = await fetch(`${baseUrl}/v5/observe`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({
        sessionId: session.session.sessionId,
        capture: {
          ...manifest,
          surfaceType: "tool_manifest",
          url: "https://safe.example/connectors/citation-sync-safe",
          callbackOrigin: "https://safe.example"
        }
      })
    }).then((response) => response.json());

    const capability = observe.capabilities[0];
    const brokerSignature = await signApproval(session.session, capability, broker);
    const approval = await fetch(`${baseUrl}/v5/approval/issue`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({
        sessionId: session.session.sessionId,
        capabilityId: capability.capabilityId,
        capabilityDigest: capability.capabilityDigest,
        brokerSignature
      })
    }).then((response) => response.json());

    const prepare = await fetch(`${baseUrl}/v5/tool/prepare`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({
        sessionId: session.session.sessionId,
        approvalId: approval.approvalEnvelope.approvalId
      })
    }).then((response) => response.json());

    expect(prepare.verdict.decision).toBe("ALLOW");

    const prepareReuse = await fetch(`${baseUrl}/v5/tool/prepare`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({
        sessionId: session.session.sessionId,
        approvalId: approval.approvalEnvelope.approvalId
      })
    }).then((response) => response.json());

    expect(prepareReuse.verdict.decision).toBe("BLOCK");
    expect(prepareReuse.verdict.reasonCodes).toContain("APPROVAL_ENVELOPE_ALREADY_USED");

    const callbackMismatch = await fetch(`${baseUrl}/v5/tool/callback/verify`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({
        sessionId: session.session.sessionId,
        approvalId: approval.approvalEnvelope.approvalId,
        onboardingSessionId: prepare.onboardingSession.onboardingSessionId,
        request: {
          sessionId: prepare.onboardingSession.onboardingSessionId,
          callbackUri: "https://safe.example/oauth/callback/unexpected",
          callbackOrigin: "https://safe.example",
          state: prepare.onboardingSession.state,
          payload: {
            code: "auth-code",
            state: prepare.onboardingSession.state
          }
        }
      })
    }).then((response) => response.json());

    expect(callbackMismatch.verdict.decision).toBe("BLOCK");
    expect(callbackMismatch.verdict.reasonCodes).toContain("CALLBACK_URI_MISMATCH");
  });

  it("does not treat non-authoritative artifacts as safe effect-bearing observations", async () => {
    const { baseUrl } = await startTestServer();
    const session = await fetch(`${baseUrl}/v5/session/start`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({
        taskId: "task-v5-artifact",
        userGoal: "Inspect a risky artifact safely",
        allowedOrigins: ["https://safe.example"],
        allowedVerbs: ["navigate"],
        forbiddenSinks: []
      })
    }).then((response) => response.json());

    const artifact = await fetch(`${baseUrl}/v5/artifact/ingest`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({
        sessionId: session.session.sessionId,
        capture: {
          surfaceType: "html",
          url: "https://safe.example/artifact",
          html: `<html><body><main>Visible docs only.</main><div hidden><a href="https://docs.python.org/3/tutorial/">continuity path</a></div></body></html>`
        }
      })
    }).then((response) => response.json());

    expect(artifact.artifactVerdict.decision).not.toBe("ALLOW");
    expect(artifact.artifactVerdict.safeConstraints.authority_eligible).toBe(false);
  });
});

import { generateKeyPairSync, sign as signBuffer } from "node:crypto";

import { afterEach, describe, expect, it } from "vitest";

import {
  createApprovalIntentPayloadV5,
  type PolicyPack,
  type VerifiedRegistryBundle
} from "@safebrowse/core";
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

const servers: Array<{ close: () => Promise<void> }> = [];

async function startTestServer() {
  const { publicKey, privateKey } = generateKeyPairSync("ed25519");
  const publicKeyPem = publicKey.export({ format: "pem", type: "spki" }).toString();
  const server = await createSafeBrowseServer({
    policyPack,
    verifiedRegistry,
    deploymentProfile: "secure_v5",
    approvalBrokerPublicKeyPem: publicKeyPem,
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
    privateKey
  };
}

afterEach(async () => {
  await Promise.all(servers.splice(0).map((entry) => entry.close()));
});

describe("safebrowse daemon v5 routes", () => {
  it("disables legacy routes in secure_v5 and reports secure health posture", async () => {
    const { baseUrl } = await startTestServer();
    const health = await fetch(`${baseUrl}/health`).then((response) => response.json());

    expect(health.deploymentProfile).toBe("secure_v5");
    expect(health.legacyRoutesEnabled).toBe(false);
    expect(health.approvalBroker.required).toBe(true);
    expect(health.parserIsolation.enforced).toBe(true);

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
    const { baseUrl, privateKey } = await startTestServer();
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
          authType: "oauth",
          requestedScopes: ["citation:read"],
          callbackUri: manifest.callbackUri,
          callbackOrigin: "https://safe.example"
        }
      })
    }).then((response) => response.json());

    const capability = observe.capabilities[0];
    const approvalPayload = createApprovalIntentPayloadV5({
      sessionId: session.session.sessionId,
      workflowHash: session.session.workflowHash,
      capabilityId: capability.capabilityId,
      capabilityDigest: capability.capabilityDigest
    });
    const brokerSignature = signBuffer(
      null,
      Buffer.from(approvalPayload, "utf8"),
      privateKey
    ).toString("base64");

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
});

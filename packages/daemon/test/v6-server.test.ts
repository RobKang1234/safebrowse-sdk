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
  packId: "daemon-test-pack-v6",
  profile: "research",
  version: "0.6.0",
  layers: [
    {
      name: "base",
      version: "0.6.0",
      profile: "research",
      origins: {
        readOnlyAllow: ["https://safe.example", "https://docs.python.org"],
        writableAllow: []
      },
      actions: {
        allow: ["navigate", "connector_prepare", "memory_promote"],
        requireApproval: ["download"],
        deny: ["exfiltrate"]
      },
      artifacts: {
        enableDocumentHandoff: true,
        quarantineOnHiddenTextMismatch: true,
        allowMimeTypes: ["application/pdf", "text/html", "application/json"]
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
  version: "6",
  signer: "safebrowse-dev",
  generatedAt: "2026-04-02T00:00:00.000Z",
  publicKeyId: "safebrowse_vf_ed25519_public.pem",
  signatureVerified: true,
  entries: [
    {
      registryEntryId: "citation-sync-safe",
      adapterId: "citation-sync-safe",
      bundleId: "safebrowse-local-registry",
      bundleVersion: "6",
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

async function startTestServer() {
  const broker = await startTestBroker();
  const server = await createSafeBrowseServer({
    policyPack,
    verifiedRegistry,
    deploymentProfile: "secure_v6",
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
  authority: Record<string, any>,
  broker: Awaited<ReturnType<typeof startTestBroker>>
) {
  return (
    await issueApprovalSignature(broker.baseUrl, broker.authToken, {
      sessionId: session.sessionId,
      workflowHash: session.workflowHash,
      capabilityId: authority.authorityId ?? authority.capabilityId ?? authority.ticketId,
      capabilityDigest:
        authority.authorityDigest ?? authority.capabilityDigest ?? authority.ticketDigest
    })
  ).brokerSignature;
}

afterEach(async () => {
  await Promise.all(servers.splice(0).map((entry) => entry.close()));
  await Promise.all(brokers.splice(0).map((entry) => entry.close()));
});

describe("safebrowse daemon v6 routes", () => {
  it("boots secure_v6 with strict defaults and actor-attributed replay", async () => {
    const { baseUrl } = await startTestServer();
    const health = await fetch(`${baseUrl}/health`).then((response) => response.json());

    expect(health.deploymentProfile).toBe("secure_v6");
    expect(health.claimBearingReady).toBe(true);
    expect(health.legacyRoutesEnabled).toBe(false);
    expect(health.approvalBroker.mode).toBe("external_service");
    expect(health.parserIsolation.configuredMode).toBe("node_permission_process");
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

    expect(legacy.error).toBe("route_disabled_in_secure_v6");

    const session = await fetch(`${baseUrl}/v6/session/start`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({
        taskId: "task-v6-replay",
        userGoal: "Review docs safely",
        allowedOrigins: ["https://safe.example", "https://docs.python.org"],
        allowedVerbs: ["navigate"],
        forbiddenSinks: []
      })
    }).then((response) => response.json());

    const observe = await fetch(`${baseUrl}/v6/observe`, {
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

    const action = await fetch(`${baseUrl}/v6/action/evaluate`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({
        sessionId: session.session.sessionId,
        authorityId: observe.authorityCandidates[0].authorityId,
        authorityDigest: observe.authorityCandidates[0].authorityDigest,
        parameters: {}
      })
    }).then((response) => response.json());

    expect(action.effectDecision.decision).toBe("ALLOW");

    const replay = await fetch(`${baseUrl}/v6/replay/bundle`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({
        sessionId: session.session.sessionId
      })
    }).then((response) => response.json());

    expect(replay.metrics.actorCounts.sdk).toBeGreaterThanOrEqual(2);
  });

  it("requires exact manifest and schema hash binding for V6 connector authority", async () => {
    const { baseUrl } = await startTestServer();
    const session = await fetch(`${baseUrl}/v6/session/start`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({
        taskId: "task-v6-hash",
        userGoal: "Review connector onboarding safely",
        allowedOrigins: ["https://safe.example"],
        allowedVerbs: ["connector_prepare"],
        forbiddenSinks: []
      })
    }).then((response) => response.json());

    const mismatchObserve = await fetch(`${baseUrl}/v6/observe`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({
        sessionId: session.session.sessionId,
        capture: {
          surfaceType: "tool_manifest",
          url: "https://safe.example/connectors/citation-sync-safe",
          toolId: manifest.toolId,
          description: `${manifest.description} Extra unsafe text.`,
          schemaDescriptions: manifest.schemaDescriptions,
          authType: "oauth",
          requestedScopes: ["citation:read"],
          callbackUri: manifest.callbackUri,
          callbackOrigin: "https://safe.example"
        }
      })
    }).then((response) => response.json());

    expect(mismatchObserve.authorityCandidates).toEqual([]);
  });

  it("allows the valid V6 connector path and blocks callback mismatch after prepare", async () => {
    const { baseUrl, broker } = await startTestServer();
    const session = await fetch(`${baseUrl}/v6/session/start`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({
        taskId: "task-v6-tool",
        userGoal: "Review connector onboarding safely",
        allowedOrigins: ["https://safe.example"],
        allowedVerbs: ["connector_prepare"],
        forbiddenSinks: []
      })
    }).then((response) => response.json());

    const observe = await fetch(`${baseUrl}/v6/observe`, {
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

    const authority = observe.authorityCandidates[0];
    const brokerSignature = await signApproval(session.session, authority, broker);
    const issued = await fetch(`${baseUrl}/v6/approval/issue`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({
        sessionId: session.session.sessionId,
        capabilityId: authority.authorityId,
        capabilityDigest: authority.authorityDigest,
        brokerSignature
      })
    }).then((response) => response.json());

    expect(issued.verdict.decision).toBe("ALLOW");
    expect(issued.approvalEnvelope.manifestHash).toBe(verifiedRegistry.entries[0].manifestHash);

    const prepared = await fetch(`${baseUrl}/v6/tool/prepare`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({
        sessionId: session.session.sessionId,
        approvalId: issued.approvalEnvelope.approvalId
      })
    }).then((response) => response.json());

    expect(prepared.verdict.decision).toBe("ALLOW");

    const callbackMismatch = await fetch(`${baseUrl}/v6/tool/callback/verify`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({
        sessionId: session.session.sessionId,
        approvalId: issued.approvalEnvelope.approvalId,
        onboardingSessionId: prepared.onboardingSession.onboardingSessionId,
        request: {
          sessionId: prepared.onboardingSession.onboardingSessionId,
          callbackUri: "https://safe.example/oauth/callback/unexpected",
          callbackOrigin: "https://safe.example",
          state: prepared.onboardingSession.state,
          payload: {
            code: "auth-code",
            state: prepared.onboardingSession.state
          }
        }
      })
    }).then((response) => response.json());

    expect(callbackMismatch.verdict.decision).toBe("BLOCK");
    expect(callbackMismatch.verdict.reasonCodes).toContain("CALLBACK_URI_MISMATCH");
  });

  it("requires corroboration for web observations and rolls back to the prior trusted baseline", async () => {
    const { baseUrl, broker } = await startTestServer();
    const session = await fetch(`${baseUrl}/v6/session/start`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({
        taskId: "task-v6-memory",
        userGoal: "Store notes safely",
        allowedOrigins: ["https://safe.example"],
        allowedVerbs: ["memory_promote"],
        forbiddenSinks: []
      })
    }).then((response) => response.json());

    const baselineStage = await fetch(`${baseUrl}/v6/memory/stage`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({
        sessionId: session.session.sessionId,
        key: "workflow_hint",
        value: { note: "baseline" },
        sourceClass: "user_note",
        durable: true
      })
    }).then((response) => response.json());

    const baselineSignature = await signApproval(session.session, baselineStage.promotionTicket, broker);
    const baselineApproval = await fetch(`${baseUrl}/v6/approval/issue`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({
        sessionId: session.session.sessionId,
        capabilityId: baselineStage.promotionTicket.ticketId,
        capabilityDigest: baselineStage.promotionTicket.ticketDigest,
        brokerSignature: baselineSignature
      })
    }).then((response) => response.json());

    const baselinePromote = await fetch(`${baseUrl}/v6/memory/promote`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({
        sessionId: session.session.sessionId,
        recordId: baselineStage.record.recordId,
        ticketId: baselineStage.promotionTicket.ticketId,
        ticketDigest: baselineStage.promotionTicket.ticketDigest,
        approvalId: baselineApproval.approvalEnvelope.approvalId
      })
    }).then((response) => response.json());

    expect(baselinePromote.verdict.decision).toBe("ALLOW");

    const webStage = await fetch(`${baseUrl}/v6/memory/stage`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({
        sessionId: session.session.sessionId,
        key: "workflow_hint",
        value: { note: "replacement" },
        sourceClass: "web_observation",
        durable: true,
        sourceObservationId: "obs-v6"
      })
    }).then((response) => response.json());

    const webSignature = await signApproval(session.session, webStage.promotionTicket, broker);
    const webApproval = await fetch(`${baseUrl}/v6/approval/issue`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({
        sessionId: session.session.sessionId,
        capabilityId: webStage.promotionTicket.ticketId,
        capabilityDigest: webStage.promotionTicket.ticketDigest,
        brokerSignature: webSignature
      })
    }).then((response) => response.json());

    const blockedPromote = await fetch(`${baseUrl}/v6/memory/promote`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({
        sessionId: session.session.sessionId,
        recordId: webStage.record.recordId,
        ticketId: webStage.promotionTicket.ticketId,
        ticketDigest: webStage.promotionTicket.ticketDigest,
        approvalId: webApproval.approvalEnvelope.approvalId
      })
    }).then((response) => response.json());

    expect(blockedPromote.verdict.decision).toBe("BLOCK");
    expect(blockedPromote.verdict.reasonCodes).toContain("CORROBORATION_REQUIRED");

    const corroboratedStage = await fetch(`${baseUrl}/v6/memory/stage`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({
        sessionId: session.session.sessionId,
        key: "workflow_hint",
        value: { note: "replacement" },
        sourceClass: "web_observation",
        durable: true,
        sourceObservationId: "obs-v6-2",
        corroboration: [{ source: "manual-review", note: "operator confirmed" }]
      })
    }).then((response) => response.json());

    const corroboratedSignature = await signApproval(
      session.session,
      corroboratedStage.promotionTicket,
      broker
    );
    const corroboratedApproval = await fetch(`${baseUrl}/v6/approval/issue`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({
        sessionId: session.session.sessionId,
        capabilityId: corroboratedStage.promotionTicket.ticketId,
        capabilityDigest: corroboratedStage.promotionTicket.ticketDigest,
        brokerSignature: corroboratedSignature
      })
    }).then((response) => response.json());

    const promoted = await fetch(`${baseUrl}/v6/memory/promote`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({
        sessionId: session.session.sessionId,
        recordId: corroboratedStage.record.recordId,
        ticketId: corroboratedStage.promotionTicket.ticketId,
        ticketDigest: corroboratedStage.promotionTicket.ticketDigest,
        approvalId: corroboratedApproval.approvalEnvelope.approvalId
      })
    }).then((response) => response.json());

    expect(promoted.verdict.decision).toBe("ALLOW");

    const rollback = await fetch(`${baseUrl}/v6/memory/rollback`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({
        sessionId: session.session.sessionId,
        recordId: promoted.promotedRecord.recordId,
        snapshotId: promoted.promotedRecord.snapshotId
      })
    }).then((response) => response.json());

    expect(rollback.verdict.decision).toBe("ALLOW");
    expect(rollback.restoredRecord.value).toEqual({ note: "baseline" });
  });
});

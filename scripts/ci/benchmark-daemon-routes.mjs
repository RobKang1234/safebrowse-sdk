import { generateKeyPairSync } from "node:crypto";
import { performance } from "node:perf_hooks";
import { mkdir, writeFile } from "node:fs/promises";
import { dirname, resolve } from "node:path";
import { pathToFileURL } from "node:url";

const repoRoot = resolve(import.meta.dirname, "..", "..");

const {
  createSafeBrowseServer
} = await import(pathToFileURL(resolve(repoRoot, "packages/daemon/dist/index.js")).href);
const {
  computeToolManifestHash,
  computeToolSchemaHash
} = await import(pathToFileURL(resolve(repoRoot, "packages/core/dist/index.js")).href);
const {
  issueApprovalSignature,
  startApprovalBroker
} = await import(pathToFileURL(resolve(repoRoot, "packages/approval-broker/dist/index.js")).href);

const emptyKnowledgeBase = {
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
};

const policyPack = {
  packId: "daemon-bench-pack",
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

const toolManifest = {
  toolId: "citation-sync-safe",
  description: "Citation sync connector for scholarly cross-reference enrichment.",
  authType: "oauth",
  requestedScopes: ["citation:read"],
  callbackUri: "https://safe.example/oauth/callback",
  schemaDescriptions: []
};

const htmlCapture = {
  surfaceType: "html",
  url: "https://safe.example/page",
  html: '<html><body><main>Visible docs only.</main><a href="https://docs.python.org/3/tutorial/">Docs</a></body></html>'
};

const toolCapture = {
  surfaceType: "tool_manifest",
  url: "https://safe.example/connectors/citation-sync-safe",
  toolId: toolManifest.toolId,
  description: toolManifest.description,
  schemaDescriptions: toolManifest.schemaDescriptions,
  authType: "oauth",
  requestedScopes: ["citation:read"],
  callbackUri: toolManifest.callbackUri,
  callbackOrigin: "https://safe.example"
};

const thresholds = {
  healthV5: { p50Ms: 10, p95Ms: 20, maxBytes: 2_000 },
  healthV6: { p50Ms: 10, p95Ms: 20, maxBytes: 2_000 },
  observeHtmlV5: { p50Ms: 25, p95Ms: 50, maxBytes: 7_000 },
  observeHtmlV6: { p50Ms: 25, p95Ms: 50, maxBytes: 7_000 },
  observeToolV5: { p50Ms: 30, p95Ms: 60, maxBytes: 7_000 },
  observeToolV6: { p50Ms: 30, p95Ms: 60, maxBytes: 7_000 },
  artifactV5: { p50Ms: 25, p95Ms: 60, maxBytes: 7_000 },
  artifactV6: { p50Ms: 25, p95Ms: 60, maxBytes: 7_000 },
  actionV5: { p50Ms: 2, p95Ms: 5, maxBytes: 3_000 },
  actionV6: { p50Ms: 2, p95Ms: 5, maxBytes: 3_000 },
  approvalIssueV5: { p50Ms: 2, p95Ms: 5, maxBytes: 2_500 },
  approvalIssueV6: { p50Ms: 2, p95Ms: 5, maxBytes: 2_500 },
  toolPrepareV5: { p50Ms: 2, p95Ms: 5, maxBytes: 5_000 },
  toolPrepareV6: { p50Ms: 2, p95Ms: 5, maxBytes: 5_000 },
  toolCallbackV5: { p50Ms: 2, p95Ms: 5, maxBytes: 2_000 },
  toolCallbackV6: { p50Ms: 2, p95Ms: 5, maxBytes: 2_000 },
  memoryWriteV5: { p50Ms: 2, p95Ms: 5, maxBytes: 2_500 },
  memoryStageV6: { p50Ms: 2, p95Ms: 5, maxBytes: 2_500 },
  memoryPromoteV5: { p50Ms: 2, p95Ms: 5, maxBytes: 3_000 },
  memoryPromoteV6: { p50Ms: 2, p95Ms: 5, maxBytes: 3_000 },
  replayBundleV6: { p50Ms: 5, p95Ms: 15, maxBytes: 80_000 }
};

function parseArgs() {
  const args = process.argv.slice(2);
  const options = {
    assertThresholds: false,
    jsonOut: undefined
  };

  for (let index = 0; index < args.length; index += 1) {
    if (args[index] === "--assert-thresholds") {
      options.assertThresholds = true;
      continue;
    }
    if (args[index] === "--json-out" && args[index + 1]) {
      options.jsonOut = resolve(args[index + 1]);
      index += 1;
    }
  }

  return options;
}

function makeRegistry(version) {
  return {
    bundleId: "safebrowse-local-registry",
    version,
    signer: "safebrowse-dev",
    generatedAt: "2026-04-02T00:00:00.000Z",
    publicKeyId: "safebrowse_vf_ed25519_public.pem",
    signatureVerified: true,
    entries: [
      {
        registryEntryId: "citation-sync-safe",
        adapterId: "citation-sync-safe",
        bundleId: "safebrowse-local-registry",
        bundleVersion: version,
        signer: "safebrowse-dev",
        authType: "oauth",
        capabilities: ["citation_sync"],
        allowedTransports: ["https"],
        allowedRedirectUris: ["https://safe.example/oauth/callback"],
        allowedCallbackOrigins: ["https://safe.example"],
        allowedScopes: ["citation:read"],
        manifestHash: computeToolManifestHash(toolManifest),
        schemaHash: computeToolSchemaHash(toolManifest.schemaDescriptions)
      }
    ]
  };
}

function summarize(values) {
  const sorted = [...values].sort((left, right) => left - right);
  const pick = (percentile) =>
    sorted[Math.min(sorted.length - 1, Math.max(0, Math.floor((sorted.length - 1) * percentile)))];
  const average = values.reduce((sum, value) => sum + value, 0) / values.length;

  return {
    avg: Number(average.toFixed(3)),
    p50: Number(pick(0.5).toFixed(3)),
    p95: Number(pick(0.95).toFixed(3)),
    min: Number(sorted[0].toFixed(3)),
    max: Number(sorted[sorted.length - 1].toFixed(3))
  };
}

async function benchmark(name, rounds, fn, warmups = 3) {
  for (let iteration = 0; iteration < warmups; iteration += 1) {
    await fn();
  }

  const timings = [];
  const bytes = [];
  for (let iteration = 0; iteration < rounds; iteration += 1) {
    const result = await fn();
    timings.push(result.ms);
    if (typeof result.bytes === "number") {
      bytes.push(result.bytes);
    }
  }

  return {
    name,
    rounds,
    latencyMs: summarize(timings),
    responseBytes: bytes.length ? summarize(bytes) : undefined
  };
}

async function postJson(url, payload) {
  const started = performance.now();
  const response = await fetch(url, {
    method: "POST",
    headers: {
      "content-type": "application/json"
    },
    body: JSON.stringify(payload)
  });
  const text = await response.text();
  if (!response.ok) {
    throw new Error(`Unexpected ${response.status} from ${url}: ${text}`);
  }
  return {
    ms: performance.now() - started,
    bytes: Buffer.byteLength(text),
    json: JSON.parse(text)
  };
}

async function getJson(url) {
  const started = performance.now();
  const response = await fetch(url);
  const text = await response.text();
  if (!response.ok) {
    throw new Error(`Unexpected ${response.status} from ${url}: ${text}`);
  }
  return {
    ms: performance.now() - started,
    bytes: Buffer.byteLength(text),
    json: JSON.parse(text)
  };
}

async function listen(server) {
  await new Promise((resolvePromise, rejectPromise) => {
    server.once("error", rejectPromise);
    server.listen(0, "127.0.0.1", () => resolvePromise());
  });
  const address = server.address();
  if (!address || typeof address === "string") {
    throw new Error("Missing server address");
  }
  return `http://127.0.0.1:${address.port}`;
}

async function closeServer(server) {
  await new Promise((resolvePromise) => {
    server.close(() => resolvePromise());
  });
}

async function startServer(profile, verifiedRegistry, brokerPublicKeyPem) {
  const server = await createSafeBrowseServer({
    policyPack,
    verifiedRegistry,
    deploymentProfile: profile,
    approvalBrokerPublicKeyPem: brokerPublicKeyPem,
    knowledgeBase: emptyKnowledgeBase
  });
  const baseUrl = await listen(server);
  return {
    server,
    baseUrl
  };
}

async function startSession(baseUrl, version, allowedVerbs) {
  const route = version === "v6" ? "/v6/session/start" : "/v5/session/start";
  const result = await postJson(`${baseUrl}${route}`, {
    taskId: `perf-${version}-${allowedVerbs.join("-")}`,
    userGoal: "Benchmark safe flows",
    allowedOrigins: ["https://safe.example", "https://docs.python.org"],
    allowedVerbs,
    forbiddenSinks: []
  });
  return result.json.session;
}

function getCapability(version, response) {
  return version === "v6" ? response.authorityCandidates[0] : response.capabilities[0];
}

function getCapabilityIds(version, capability) {
  return version === "v6"
    ? {
        id: capability.authorityId,
        digest: capability.authorityDigest
      }
    : {
        id: capability.capabilityId,
        digest: capability.capabilityDigest
      };
}

function buildApprovalIntent(session, capabilityId, capabilityDigest) {
  return {
    sessionId: session.sessionId,
    workflowHash: session.workflowHash,
    capabilityId,
    capabilityDigest
  };
}

async function measureStartup(profile, verifiedRegistry, brokerPublicKeyPem, rounds = 3) {
  return benchmark(`startup_${profile}`, rounds, async () => {
    const started = performance.now();
    const server = await createSafeBrowseServer({
      policyPack,
      verifiedRegistry,
      deploymentProfile: profile,
      approvalBrokerPublicKeyPem: brokerPublicKeyPem,
      knowledgeBase: emptyKnowledgeBase
    });
    await listen(server);
    const elapsed = performance.now() - started;
    await closeServer(server);
    return {
      ms: elapsed
    };
  }, 1);
}

function assertThreshold(name, result, budget) {
  if (!budget) {
    return [];
  }

  const failures = [];
  if (result.latencyMs.p50 > budget.p50Ms) {
    failures.push(`${name} p50 ${result.latencyMs.p50}ms exceeded ${budget.p50Ms}ms`);
  }
  if (result.latencyMs.p95 > budget.p95Ms) {
    failures.push(`${name} p95 ${result.latencyMs.p95}ms exceeded ${budget.p95Ms}ms`);
  }
  if (result.responseBytes && result.responseBytes.p95 > budget.maxBytes) {
    failures.push(`${name} response bytes ${result.responseBytes.p95} exceeded ${budget.maxBytes}`);
  }
  return failures;
}

async function main() {
  const options = parseArgs();
  const brokerAuthToken = "daemon-bench-broker-token";
  const { privateKey } = generateKeyPairSync("ed25519");
  const broker = await startApprovalBroker({
    host: "127.0.0.1",
    port: 0,
    privateKeyPem: privateKey.export({ format: "pem", type: "pkcs8" }).toString(),
    authToken: brokerAuthToken
  });
  const brokerBaseUrl = `http://${broker.host}:${broker.port}`;

  const results = {
    measuredAt: new Date().toISOString(),
    environment: {
      repoRoot,
      node: process.version
    },
    startup: {},
    routes: {},
    thresholds
  };

  let v5Server;
  let v6Server;

  try {
    results.startup.secureV5 = await measureStartup("secure_v5", makeRegistry("5"), broker.publicKeyPem);
    results.startup.secureV6 = await measureStartup("secure_v6", makeRegistry("6"), broker.publicKeyPem);

    v5Server = await startServer("secure_v5", makeRegistry("5"), broker.publicKeyPem);
    v6Server = await startServer("secure_v6", makeRegistry("6"), broker.publicKeyPem);

    results.routes.healthV5 = await benchmark("health_v5", 10, async () =>
      getJson(`${v5Server.baseUrl}/health`), 1
    );
    results.routes.healthV6 = await benchmark("health_v6", 10, async () =>
      getJson(`${v6Server.baseUrl}/health`), 1
    );

    const v5NavigateSession = await startSession(v5Server.baseUrl, "v5", ["navigate"]);
    const v6NavigateSession = await startSession(v6Server.baseUrl, "v6", ["navigate"]);
    const v5ToolSession = await startSession(v5Server.baseUrl, "v5", ["connector_prepare"]);
    const v6ToolSession = await startSession(v6Server.baseUrl, "v6", ["connector_prepare"]);
    const v5MemorySession = await startSession(v5Server.baseUrl, "v5", ["memory_promote"]);
    const v6MemorySession = await startSession(v6Server.baseUrl, "v6", ["memory_promote"]);

    results.routes.observeHtmlV5 = await benchmark("observe_html_v5", 20, async () =>
      postJson(`${v5Server.baseUrl}/v5/observe`, {
        sessionId: v5NavigateSession.sessionId,
        capture: htmlCapture
      })
    );
    results.routes.observeHtmlV6 = await benchmark("observe_html_v6", 20, async () =>
      postJson(`${v6Server.baseUrl}/v6/observe`, {
        sessionId: v6NavigateSession.sessionId,
        capture: htmlCapture
      })
    );

    results.routes.observeToolV5 = await benchmark("observe_tool_v5", 20, async () =>
      postJson(`${v5Server.baseUrl}/v5/observe`, {
        sessionId: v5ToolSession.sessionId,
        capture: toolCapture
      })
    );
    results.routes.observeToolV6 = await benchmark("observe_tool_v6", 20, async () =>
      postJson(`${v6Server.baseUrl}/v6/observe`, {
        sessionId: v6ToolSession.sessionId,
        capture: toolCapture
      })
    );

    results.routes.actionV5 = await benchmark("action_v5", 20, async () => {
      const observe = await postJson(`${v5Server.baseUrl}/v5/observe`, {
        sessionId: v5NavigateSession.sessionId,
        capture: htmlCapture
      });
      const capability = getCapability("v5", observe.json);
      const ids = getCapabilityIds("v5", capability);
      return postJson(`${v5Server.baseUrl}/v5/capability/use`, {
        sessionId: v5NavigateSession.sessionId,
        capabilityId: ids.id,
        capabilityDigest: ids.digest,
        parameters: {}
      });
    });
    results.routes.actionV6 = await benchmark("action_v6", 20, async () => {
      const observe = await postJson(`${v6Server.baseUrl}/v6/observe`, {
        sessionId: v6NavigateSession.sessionId,
        capture: htmlCapture
      });
      const capability = getCapability("v6", observe.json);
      const ids = getCapabilityIds("v6", capability);
      return postJson(`${v6Server.baseUrl}/v6/action/evaluate`, {
        sessionId: v6NavigateSession.sessionId,
        authorityId: ids.id,
        authorityDigest: ids.digest,
        parameters: {}
      });
    });

    results.routes.artifactV5 = await benchmark("artifact_v5", 20, async () =>
      postJson(`${v5Server.baseUrl}/v5/artifact/ingest`, {
        sessionId: v5NavigateSession.sessionId,
        capture: htmlCapture
      })
    );
    results.routes.artifactV6 = await benchmark("artifact_v6", 20, async () =>
      postJson(`${v6Server.baseUrl}/v6/artifact/ingest`, {
        sessionId: v6NavigateSession.sessionId,
        capture: htmlCapture
      })
    );

    results.routes.approvalIssueV5 = await benchmark("approval_issue_v5", 15, async () => {
      const observe = await postJson(`${v5Server.baseUrl}/v5/observe`, {
        sessionId: v5ToolSession.sessionId,
        capture: toolCapture
      });
      const capability = getCapability("v5", observe.json);
      const ids = getCapabilityIds("v5", capability);
      const signature = await issueApprovalSignature(
        brokerBaseUrl,
        brokerAuthToken,
        buildApprovalIntent(v5ToolSession, ids.id, ids.digest)
      );
      return postJson(`${v5Server.baseUrl}/v5/approval/issue`, {
        sessionId: v5ToolSession.sessionId,
        capabilityId: ids.id,
        capabilityDigest: ids.digest,
        brokerSignature: signature.brokerSignature
      });
    });
    results.routes.approvalIssueV6 = await benchmark("approval_issue_v6", 15, async () => {
      const observe = await postJson(`${v6Server.baseUrl}/v6/observe`, {
        sessionId: v6ToolSession.sessionId,
        capture: toolCapture
      });
      const capability = getCapability("v6", observe.json);
      const ids = getCapabilityIds("v6", capability);
      const signature = await issueApprovalSignature(
        brokerBaseUrl,
        brokerAuthToken,
        buildApprovalIntent(v6ToolSession, ids.id, ids.digest)
      );
      return postJson(`${v6Server.baseUrl}/v6/approval/issue`, {
        sessionId: v6ToolSession.sessionId,
        capabilityId: ids.id,
        capabilityDigest: ids.digest,
        brokerSignature: signature.brokerSignature
      });
    });

    results.routes.toolPrepareV5 = await benchmark("tool_prepare_v5", 15, async () => {
      const observe = await postJson(`${v5Server.baseUrl}/v5/observe`, {
        sessionId: v5ToolSession.sessionId,
        capture: toolCapture
      });
      const capability = getCapability("v5", observe.json);
      const ids = getCapabilityIds("v5", capability);
      const signature = await issueApprovalSignature(
        brokerBaseUrl,
        brokerAuthToken,
        buildApprovalIntent(v5ToolSession, ids.id, ids.digest)
      );
      const approval = await postJson(`${v5Server.baseUrl}/v5/approval/issue`, {
        sessionId: v5ToolSession.sessionId,
        capabilityId: ids.id,
        capabilityDigest: ids.digest,
        brokerSignature: signature.brokerSignature
      });
      return postJson(`${v5Server.baseUrl}/v5/tool/prepare`, {
        sessionId: v5ToolSession.sessionId,
        approvalId: approval.json.approvalEnvelope.approvalId
      });
    });
    results.routes.toolPrepareV6 = await benchmark("tool_prepare_v6", 15, async () => {
      const observe = await postJson(`${v6Server.baseUrl}/v6/observe`, {
        sessionId: v6ToolSession.sessionId,
        capture: toolCapture
      });
      const capability = getCapability("v6", observe.json);
      const ids = getCapabilityIds("v6", capability);
      const signature = await issueApprovalSignature(
        brokerBaseUrl,
        brokerAuthToken,
        buildApprovalIntent(v6ToolSession, ids.id, ids.digest)
      );
      const approval = await postJson(`${v6Server.baseUrl}/v6/approval/issue`, {
        sessionId: v6ToolSession.sessionId,
        capabilityId: ids.id,
        capabilityDigest: ids.digest,
        brokerSignature: signature.brokerSignature
      });
      return postJson(`${v6Server.baseUrl}/v6/tool/prepare`, {
        sessionId: v6ToolSession.sessionId,
        approvalId: approval.json.approvalEnvelope.approvalId
      });
    });

    results.routes.toolCallbackV5 = await benchmark("tool_callback_v5", 15, async () => {
      const observe = await postJson(`${v5Server.baseUrl}/v5/observe`, {
        sessionId: v5ToolSession.sessionId,
        capture: toolCapture
      });
      const capability = getCapability("v5", observe.json);
      const ids = getCapabilityIds("v5", capability);
      const signature = await issueApprovalSignature(
        brokerBaseUrl,
        brokerAuthToken,
        buildApprovalIntent(v5ToolSession, ids.id, ids.digest)
      );
      const approval = await postJson(`${v5Server.baseUrl}/v5/approval/issue`, {
        sessionId: v5ToolSession.sessionId,
        capabilityId: ids.id,
        capabilityDigest: ids.digest,
        brokerSignature: signature.brokerSignature
      });
      const prepare = await postJson(`${v5Server.baseUrl}/v5/tool/prepare`, {
        sessionId: v5ToolSession.sessionId,
        approvalId: approval.json.approvalEnvelope.approvalId
      });
      return postJson(`${v5Server.baseUrl}/v5/tool/callback/verify`, {
        sessionId: v5ToolSession.sessionId,
        approvalId: approval.json.approvalEnvelope.approvalId,
        onboardingSessionId: prepare.json.onboardingSession.onboardingSessionId,
        request: {
          sessionId: prepare.json.onboardingSession.onboardingSessionId,
          callbackUri: toolManifest.callbackUri,
          callbackOrigin: "https://safe.example",
          state: prepare.json.onboardingSession.state,
          payload: {
            code: "auth-code",
            state: prepare.json.onboardingSession.state
          }
        }
      });
    });
    results.routes.toolCallbackV6 = await benchmark("tool_callback_v6", 15, async () => {
      const observe = await postJson(`${v6Server.baseUrl}/v6/observe`, {
        sessionId: v6ToolSession.sessionId,
        capture: toolCapture
      });
      const capability = getCapability("v6", observe.json);
      const ids = getCapabilityIds("v6", capability);
      const signature = await issueApprovalSignature(
        brokerBaseUrl,
        brokerAuthToken,
        buildApprovalIntent(v6ToolSession, ids.id, ids.digest)
      );
      const approval = await postJson(`${v6Server.baseUrl}/v6/approval/issue`, {
        sessionId: v6ToolSession.sessionId,
        capabilityId: ids.id,
        capabilityDigest: ids.digest,
        brokerSignature: signature.brokerSignature
      });
      const prepare = await postJson(`${v6Server.baseUrl}/v6/tool/prepare`, {
        sessionId: v6ToolSession.sessionId,
        approvalId: approval.json.approvalEnvelope.approvalId
      });
      return postJson(`${v6Server.baseUrl}/v6/tool/callback/verify`, {
        sessionId: v6ToolSession.sessionId,
        approvalId: approval.json.approvalEnvelope.approvalId,
        onboardingSessionId: prepare.json.onboardingSession.onboardingSessionId,
        request: {
          sessionId: prepare.json.onboardingSession.onboardingSessionId,
          callbackUri: toolManifest.callbackUri,
          callbackOrigin: "https://safe.example",
          state: prepare.json.onboardingSession.state,
          payload: {
            code: "auth-code",
            state: prepare.json.onboardingSession.state
          }
        }
      });
    });

    results.routes.memoryWriteV5 = await benchmark("memory_write_v5", 20, async () =>
      postJson(`${v5Server.baseUrl}/v5/memory/write`, {
        sessionId: v5MemorySession.sessionId,
        inputKind: "user_note",
        key: "workflow_hint",
        value: {
          note: "baseline"
        },
        durable: true
      })
    );
    results.routes.memoryStageV6 = await benchmark("memory_stage_v6", 20, async () =>
      postJson(`${v6Server.baseUrl}/v6/memory/stage`, {
        sessionId: v6MemorySession.sessionId,
        key: "workflow_hint",
        value: {
          note: "baseline"
        },
        sourceClass: "user_note",
        durable: true
      })
    );

    results.routes.memoryPromoteV5 = await benchmark("memory_promote_v5", 20, async () => {
      const write = await postJson(`${v5Server.baseUrl}/v5/memory/write`, {
        sessionId: v5MemorySession.sessionId,
        inputKind: "user_note",
        key: "workflow_hint",
        value: {
          note: `note-${Math.random()}`
        },
        durable: true
      });
      const capability = write.json.promotionCapability;
      const signature = await issueApprovalSignature(
        brokerBaseUrl,
        brokerAuthToken,
        buildApprovalIntent(
          v5MemorySession,
          capability.capabilityId,
          capability.capabilityDigest
        )
      );
      const approval = await postJson(`${v5Server.baseUrl}/v5/approval/issue`, {
        sessionId: v5MemorySession.sessionId,
        capabilityId: capability.capabilityId,
        capabilityDigest: capability.capabilityDigest,
        brokerSignature: signature.brokerSignature
      });
      return postJson(`${v5Server.baseUrl}/v5/memory/promote`, {
        sessionId: v5MemorySession.sessionId,
        recordId: write.json.record.recordId,
        capabilityId: capability.capabilityId,
        capabilityDigest: capability.capabilityDigest,
        approvalId: approval.json.approvalEnvelope.approvalId
      });
    });
    results.routes.memoryPromoteV6 = await benchmark("memory_promote_v6", 20, async () => {
      const stage = await postJson(`${v6Server.baseUrl}/v6/memory/stage`, {
        sessionId: v6MemorySession.sessionId,
        key: "workflow_hint",
        value: {
          note: `note-${Math.random()}`
        },
        sourceClass: "user_note",
        durable: true
      });
      const ticket = stage.json.promotionTicket;
      const signature = await issueApprovalSignature(
        brokerBaseUrl,
        brokerAuthToken,
        buildApprovalIntent(v6MemorySession, ticket.ticketId, ticket.ticketDigest)
      );
      const approval = await postJson(`${v6Server.baseUrl}/v6/approval/issue`, {
        sessionId: v6MemorySession.sessionId,
        capabilityId: ticket.ticketId,
        capabilityDigest: ticket.ticketDigest,
        brokerSignature: signature.brokerSignature
      });
      return postJson(`${v6Server.baseUrl}/v6/memory/promote`, {
        sessionId: v6MemorySession.sessionId,
        recordId: stage.json.record.recordId,
        ticketId: ticket.ticketId,
        ticketDigest: ticket.ticketDigest,
        approvalId: approval.json.approvalEnvelope.approvalId
      });
    });

    for (let index = 0; index < 25; index += 1) {
      await postJson(`${v6Server.baseUrl}/v6/observe`, {
        sessionId: v6NavigateSession.sessionId,
        capture: {
          ...htmlCapture,
          url: `https://safe.example/page-${index}`
        }
      });
    }
    results.routes.replayBundleV6 = await benchmark("replay_bundle_v6", 10, async () =>
      postJson(`${v6Server.baseUrl}/v6/replay/bundle`, {
        sessionId: v6NavigateSession.sessionId
      }), 1
    );

    const failures = options.assertThresholds
      ? Object.entries(thresholds).flatMap(([name, budget]) =>
          assertThreshold(name, results.routes[name], budget)
        )
      : [];

    if (options.jsonOut) {
      await mkdir(dirname(options.jsonOut), { recursive: true });
      await writeFile(options.jsonOut, `${JSON.stringify(results, null, 2)}\n`, "utf8");
    }

    console.log(JSON.stringify(results, null, 2));

    if (failures.length > 0) {
      throw new Error(`Daemon route performance thresholds failed:\n${failures.join("\n")}`);
    }
  } finally {
    if (v5Server) {
      await closeServer(v5Server.server);
    }
    if (v6Server) {
      await closeServer(v6Server.server);
    }
    await new Promise((resolvePromise) => broker.server.close(() => resolvePromise()));
  }
}

main().catch((error) => {
  console.error(error instanceof Error ? error.message : String(error));
  process.exitCode = 1;
});

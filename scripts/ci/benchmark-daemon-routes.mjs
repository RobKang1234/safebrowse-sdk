import { generateKeyPairSync } from "node:crypto";
import { mkdir, writeFile } from "node:fs/promises";
import { dirname, resolve } from "node:path";
import { performance } from "node:perf_hooks";
import { pathToFileURL } from "node:url";

const repoRoot = resolve(import.meta.dirname, "..", "..");

const { createSafeBrowseServer } = await import(
  pathToFileURL(resolve(repoRoot, "packages/daemon/dist/index.js")).href
);
const { computeToolManifestHash, computeToolSchemaHash } = await import(
  pathToFileURL(resolve(repoRoot, "packages/core/dist/index.js")).href
);
const { issueApprovalSignature, startApprovalBroker } = await import(
  pathToFileURL(resolve(repoRoot, "packages/approval-broker/dist/index.js")).href
);

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
        requireApproval: [],
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
  html: '<html><body><main>Docs</main><a href="https://docs.python.org/3/tutorial/">Docs</a></body></html>',
  visibleText: "Docs",
  captureAttestation: {
    captureMethod: "rendered_dom",
    visibilityAttested: true,
    frameCoverage: "full",
    shadowDomCoverage: "full",
    unsupportedSubtrees: []
  }
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
  startupSecureV6: { p50Ms: 250, p95Ms: 500, maxBytes: 0 },
  healthV6: { p50Ms: 20, p95Ms: 40, maxBytes: 2500 },
  observeHtmlV6: { p50Ms: 40, p95Ms: 80, maxBytes: 9000 },
  observeToolV6: { p50Ms: 40, p95Ms: 80, maxBytes: 9000 },
  artifactV6: { p50Ms: 40, p95Ms: 80, maxBytes: 9000 },
  actionV6: { p50Ms: 10, p95Ms: 20, maxBytes: 3500 },
  approvalIssueV6: { p50Ms: 10, p95Ms: 25, maxBytes: 3500 },
  toolPrepareV6: { p50Ms: 10, p95Ms: 25, maxBytes: 6000 },
  toolCallbackV6: { p50Ms: 10, p95Ms: 25, maxBytes: 3000 },
  memoryStageV6: { p50Ms: 10, p95Ms: 20, maxBytes: 3500 },
  memoryPromoteV6: { p50Ms: 10, p95Ms: 25, maxBytes: 4500 },
  replayBundleV6: { p50Ms: 15, p95Ms: 40, maxBytes: 80000 }
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

async function benchmark(name, rounds, fn, warmups = 2) {
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

async function getJson(url) {
  const started = performance.now();
  const response = await fetch(url);
  const text = await response.text();
  return {
    ms: performance.now() - started,
    bytes: Buffer.byteLength(text),
    body: JSON.parse(text)
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
  return {
    ms: performance.now() - started,
    bytes: Buffer.byteLength(text),
    body: JSON.parse(text)
  };
}

async function closeServer(server) {
  await new Promise((resolvePromise) => {
    server.close(() => resolvePromise());
  });
}

async function startServer(verifiedRegistry, brokerPublicKeyPem) {
  const server = await createSafeBrowseServer({
    policyPack,
    verifiedRegistry,
    deploymentProfile: "secure_v6",
    approvalBrokerPublicKeyPem: brokerPublicKeyPem,
    knowledgeBase: emptyKnowledgeBase
  });

  await new Promise((resolvePromise, rejectPromise) => {
    server.once("error", rejectPromise);
    server.listen(0, "127.0.0.1", () => resolvePromise());
  });

  const address = server.address();
  return {
    server,
    baseUrl: `http://127.0.0.1:${address.port}`
  };
}

async function startSession(baseUrl, allowedVerbs, allowedPathClasses, taskPurposeClass) {
  const { body } = await postJson(`${baseUrl}/v6/session/start`, {
    taskId: `bench-${allowedVerbs.join("-")}`,
    userGoal: "Benchmark SafeBrowse V6 routes",
    taskPurposeClass,
    allowedOrigins: ["https://safe.example", "https://docs.python.org"],
    allowedVerbs,
    allowedPathClasses
  });
  return body.session;
}

async function measureStartup(verifiedRegistry, brokerPublicKeyPem, rounds = 3) {
  return benchmark("startupSecureV6", rounds, async () => {
    const started = performance.now();
    const server = await createSafeBrowseServer({
      policyPack,
      verifiedRegistry,
      deploymentProfile: "secure_v6",
      approvalBrokerPublicKeyPem: brokerPublicKeyPem,
      knowledgeBase: emptyKnowledgeBase
    });
    await closeServer(server);
    return { ms: performance.now() - started, bytes: 0 };
  }, 0);
}

function assertThreshold(name, stats, threshold) {
  if (!threshold) {
    return;
  }
  if (stats.latencyMs.p50 > threshold.p50Ms) {
    throw new Error(`${name} p50 ${stats.latencyMs.p50}ms exceeded ${threshold.p50Ms}ms`);
  }
  if (stats.latencyMs.p95 > threshold.p95Ms) {
    throw new Error(`${name} p95 ${stats.latencyMs.p95}ms exceeded ${threshold.p95Ms}ms`);
  }
  if (threshold.maxBytes && stats.responseBytes?.max > threshold.maxBytes) {
    throw new Error(`${name} response max ${stats.responseBytes.max} exceeded ${threshold.maxBytes}`);
  }
}

const options = parseArgs();
const brokerRuntime = await startApprovalBroker({
  host: "127.0.0.1",
  port: 0,
  privateKeyPem: generateKeyPairSync("ed25519").privateKey
    .export({ format: "pem", type: "pkcs8" })
    .toString(),
  authToken: "bench-approval-broker-token"
});
const broker = {
  ...brokerRuntime,
  baseUrl: `http://127.0.0.1:${brokerRuntime.port}`
};

let serverRuntime;

try {
  const results = {
    generatedAt: new Date().toISOString(),
    benchmarks: {}
  };

  results.benchmarks.startupSecureV6 = await measureStartup(makeRegistry("6"), broker.publicKeyPem);
  serverRuntime = await startServer(makeRegistry("6"), broker.publicKeyPem);

  const navigateSession = await startSession(
    serverRuntime.baseUrl,
    ["navigate"],
    ["docs_navigation"],
    "docs_navigation"
  );
  const toolSession = await startSession(
    serverRuntime.baseUrl,
    ["connector_prepare"],
    ["connector_setup"],
    "connector_setup"
  );
  const memorySession = await startSession(
    serverRuntime.baseUrl,
    ["memory_promote"],
    ["workflow_continue"],
    "workflow_continue"
  );

  results.benchmarks.healthV6 = await benchmark("healthV6", 10, () =>
    getJson(`${serverRuntime.baseUrl}/health`)
  );
  results.benchmarks.observeHtmlV6 = await benchmark("observeHtmlV6", 10, () =>
    postJson(`${serverRuntime.baseUrl}/v6/observe`, {
      sessionId: navigateSession.sessionId,
      capture: htmlCapture
    })
  );
  results.benchmarks.observeToolV6 = await benchmark("observeToolV6", 10, () =>
    postJson(`${serverRuntime.baseUrl}/v6/observe`, {
      sessionId: toolSession.sessionId,
      capture: toolCapture
    })
  );
  results.benchmarks.actionV6 = await benchmark("actionV6", 10, async () => {
    const observe = await postJson(`${serverRuntime.baseUrl}/v6/observe`, {
      sessionId: navigateSession.sessionId,
      capture: htmlCapture
    });
    return postJson(`${serverRuntime.baseUrl}/v6/action/evaluate`, {
      sessionId: navigateSession.sessionId,
      authorityId: observe.body.authorityCandidates[0].authorityId,
      authorityDigest: observe.body.authorityCandidates[0].authorityDigest,
      parameters: {}
    });
  });
  results.benchmarks.artifactV6 = await benchmark("artifactV6", 10, () =>
    postJson(`${serverRuntime.baseUrl}/v6/artifact/ingest`, {
      sessionId: navigateSession.sessionId,
      capture: htmlCapture
    })
  );
  results.benchmarks.approvalIssueV6 = await benchmark("approvalIssueV6", 10, async () => {
    const observe = await postJson(`${serverRuntime.baseUrl}/v6/observe`, {
      sessionId: toolSession.sessionId,
      capture: toolCapture
    });
    const authority = observe.body.authorityCandidates[0];
    const brokerSignature = (
      await issueApprovalSignature(broker.baseUrl, "bench-approval-broker-token", {
        sessionId: toolSession.sessionId,
        workflowHash: toolSession.workflowHash,
        capabilityId: authority.authorityId,
        capabilityDigest: authority.authorityDigest
      })
    ).brokerSignature;
    return postJson(`${serverRuntime.baseUrl}/v6/approval/issue`, {
      sessionId: toolSession.sessionId,
      capabilityId: authority.authorityId,
      capabilityDigest: authority.authorityDigest,
      brokerSignature
    });
  });
  results.benchmarks.toolPrepareV6 = await benchmark("toolPrepareV6", 10, async () => {
    const observe = await postJson(`${serverRuntime.baseUrl}/v6/observe`, {
      sessionId: toolSession.sessionId,
      capture: toolCapture
    });
    const authority = observe.body.authorityCandidates[0];
    const brokerSignature = (
      await issueApprovalSignature(broker.baseUrl, "bench-approval-broker-token", {
        sessionId: toolSession.sessionId,
        workflowHash: toolSession.workflowHash,
        capabilityId: authority.authorityId,
        capabilityDigest: authority.authorityDigest
      })
    ).brokerSignature;
    const approval = await postJson(`${serverRuntime.baseUrl}/v6/approval/issue`, {
      sessionId: toolSession.sessionId,
      capabilityId: authority.authorityId,
      capabilityDigest: authority.authorityDigest,
      brokerSignature
    });
    return postJson(`${serverRuntime.baseUrl}/v6/tool/prepare`, {
      sessionId: toolSession.sessionId,
      approvalId: approval.body.approvalEnvelope.approvalId
    });
  });
  results.benchmarks.toolCallbackV6 = await benchmark("toolCallbackV6", 10, async () => {
    const observe = await postJson(`${serverRuntime.baseUrl}/v6/observe`, {
      sessionId: toolSession.sessionId,
      capture: toolCapture
    });
    const authority = observe.body.authorityCandidates[0];
    const brokerSignature = (
      await issueApprovalSignature(broker.baseUrl, "bench-approval-broker-token", {
        sessionId: toolSession.sessionId,
        workflowHash: toolSession.workflowHash,
        capabilityId: authority.authorityId,
        capabilityDigest: authority.authorityDigest
      })
    ).brokerSignature;
    const approval = await postJson(`${serverRuntime.baseUrl}/v6/approval/issue`, {
      sessionId: toolSession.sessionId,
      capabilityId: authority.authorityId,
      capabilityDigest: authority.authorityDigest,
      brokerSignature
    });
    const prepare = await postJson(`${serverRuntime.baseUrl}/v6/tool/prepare`, {
      sessionId: toolSession.sessionId,
      approvalId: approval.body.approvalEnvelope.approvalId
    });
    return postJson(`${serverRuntime.baseUrl}/v6/tool/callback/verify`, {
      sessionId: toolSession.sessionId,
      approvalId: approval.body.approvalEnvelope.approvalId,
      onboardingSessionId: prepare.body.onboardingSession.onboardingSessionId,
      request: {
        sessionId: prepare.body.onboardingSession.onboardingSessionId,
        callbackUri: toolManifest.callbackUri,
        callbackOrigin: "https://safe.example",
        state: prepare.body.onboardingSession.state,
        payload: {
          code: "auth-code",
          state: prepare.body.onboardingSession.state
        }
      }
    });
  });
  results.benchmarks.memoryStageV6 = await benchmark("memoryStageV6", 10, () =>
    postJson(`${serverRuntime.baseUrl}/v6/memory/stage`, {
      sessionId: memorySession.sessionId,
      key: "workflow_hint",
      value: { note: "baseline" },
      sourceClass: "user_note",
      durable: true
    })
  );
  results.benchmarks.memoryPromoteV6 = await benchmark("memoryPromoteV6", 10, async () => {
    const stage = await postJson(`${serverRuntime.baseUrl}/v6/memory/stage`, {
      sessionId: memorySession.sessionId,
      key: "workflow_hint",
      value: { note: "baseline" },
      sourceClass: "user_note",
      durable: true
    });
    const brokerSignature = (
      await issueApprovalSignature(broker.baseUrl, "bench-approval-broker-token", {
        sessionId: memorySession.sessionId,
        workflowHash: memorySession.workflowHash,
        capabilityId: stage.body.promotionTicket.ticketId,
        capabilityDigest: stage.body.promotionTicket.ticketDigest
      })
    ).brokerSignature;
    const approval = await postJson(`${serverRuntime.baseUrl}/v6/approval/issue`, {
      sessionId: memorySession.sessionId,
      capabilityId: stage.body.promotionTicket.ticketId,
      capabilityDigest: stage.body.promotionTicket.ticketDigest,
      brokerSignature
    });
    return postJson(`${serverRuntime.baseUrl}/v6/memory/promote`, {
      sessionId: memorySession.sessionId,
      recordId: stage.body.record.recordId,
      ticketId: stage.body.promotionTicket.ticketId,
      ticketDigest: stage.body.promotionTicket.ticketDigest,
      approvalId: approval.body.approvalEnvelope.approvalId
    });
  });
  results.benchmarks.replayBundleV6 = await benchmark("replayBundleV6", 10, async () => {
    await postJson(`${serverRuntime.baseUrl}/v6/observe`, {
      sessionId: navigateSession.sessionId,
      capture: htmlCapture
    });
    return postJson(`${serverRuntime.baseUrl}/v6/replay/bundle`, {
      sessionId: navigateSession.sessionId
    });
  });

  if (options.assertThresholds) {
    for (const [name, stats] of Object.entries(results.benchmarks)) {
      assertThreshold(name, stats, thresholds[name]);
    }
  }

  if (options.jsonOut) {
    await mkdir(dirname(options.jsonOut), { recursive: true });
    await writeFile(options.jsonOut, JSON.stringify(results, null, 2));
  }

  console.log(JSON.stringify(results, null, 2));
} finally {
  if (serverRuntime) {
    await closeServer(serverRuntime.server);
  }
  await closeServer(broker.server);
}

import { createServer } from "node:net";
import { execFile, spawn } from "node:child_process";
import { cp, mkdtemp, mkdir, readFile, readdir, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { resolve } from "node:path";
import { pathToFileURL } from "node:url";
import { promisify } from "node:util";

const execFileAsync = promisify(execFile);
const repoRoot = resolve(import.meta.dirname, "..", "..");
const npmRunner =
  process.platform === "win32"
    ? {
        command: process.execPath,
        baseArgs: [resolve(process.execPath, "..", "node_modules", "npm", "bin", "npm-cli.js")]
      }
    : { command: "npm", baseArgs: [] };

const packageDirs = [
  resolve(repoRoot, "packages/core"),
  resolve(repoRoot, "packages/daemon"),
  resolve(repoRoot, "packages/playwright-adapter")
];

const policyPack = {
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

const emptyKnowledgeBase = {
  promptInjectionPatterns: [],
  actionIntegrityPatterns: [],
  artifactRiskPatterns: [],
  secrets: [],
  version: "test"
};

const toolManifestCapture = {
  surfaceType: "tool_manifest",
  url: "https://safe.example/connectors/citation-sync-safe",
  toolId: "citation-sync-safe",
  description: "Citation sync connector for scholarly cross-reference enrichment.",
  schemaDescriptions: [],
  authType: "oauth",
  requestedScopes: ["citation:read"],
  callbackUri: "https://safe.example/oauth/callback",
  callbackOrigin: "https://safe.example"
};

function parseArgs() {
  const args = process.argv.slice(2);
  const options = {
    subset: "packaging",
    jsonOut: undefined
  };

  for (let index = 0; index < args.length; index += 1) {
    if (args[index] === "--subset" && args[index + 1]) {
      options.subset = args[index + 1];
      index += 1;
    } else if (args[index] === "--json-out" && args[index + 1]) {
      options.jsonOut = resolve(args[index + 1]);
      index += 1;
    }
  }

  return options;
}

async function npm(args, options = {}) {
  return execFileAsync(npmRunner.command, [...npmRunner.baseArgs, ...args], {
    encoding: "utf8",
    ...options
  });
}

async function getFreePort() {
  const server = createServer();
  await new Promise((resolvePromise, rejectPromise) => {
    server.once("error", rejectPromise);
    server.listen(0, "127.0.0.1", resolvePromise);
  });
  const address = server.address();
  if (!address || typeof address === "string") {
    throw new Error("Failed to allocate an ephemeral port.");
  }
  const port = address.port;
  await new Promise((resolvePromise) => server.close(() => resolvePromise()));
  return port;
}

async function sleep(ms) {
  return new Promise((resolvePromise) => setTimeout(resolvePromise, ms));
}

async function stopProcess(child) {
  if (child.exitCode !== null || child.killed) {
    return;
  }
  await new Promise((resolvePromise) => {
    const finalize = () => resolvePromise();
    child.once("close", finalize);
    child.kill("SIGTERM");
    setTimeout(() => {
      if (child.exitCode === null) {
        child.kill("SIGKILL");
      }
    }, 1000).unref();
  });
}

function attachProcessLogBuffer(child, label) {
  const log = {
    stdout: "",
    stderr: ""
  };

  child.stdout?.on("data", (chunk) => {
    log.stdout += chunk.toString();
  });
  child.stderr?.on("data", (chunk) => {
    log.stderr += chunk.toString();
  });
  child.once("exit", (code, signal) => {
    if (code && code !== 0) {
      console.error(
        `${label} exited with code ${code}${signal ? ` (${signal})` : ""}\nSTDERR:\n${log.stderr || "<empty>"}\nSTDOUT:\n${log.stdout || "<empty>"}`
      );
    }
  });

  return log;
}

async function buildPythonWheelIfNeeded() {
  const pythonDistDir = resolve(repoRoot, "python/dist");
  await execFileAsync(process.execPath, [resolve(repoRoot, "scripts/release/build-python-artifacts.mjs")], {
    cwd: repoRoot,
    encoding: "utf8"
  });
  const refreshed = await readdir(pythonDistDir);
  const builtWheel = refreshed
    .filter((file) => file.endsWith(".whl"))
    .sort()
    .at(-1);
  if (!builtWheel) {
    throw new Error("No wheel found in python/dist after build.");
  }
  return resolve(pythonDistDir, builtWheel);
}

async function packPackage(packageDir, destination) {
  const releaseVersion = JSON.parse(
    await readFile(resolve(repoRoot, "packages/core/package.json"), "utf8")
  ).version;
  const stagedDir = resolve(destination, `${packageDir.split(/[\\/]/).pop()}-stage`);
  await cp(packageDir, stagedDir, {
    recursive: true,
    force: true,
    filter: (path) => !path.replace(/\\/g, "/").includes("/node_modules")
  });
  const manifestPath = resolve(stagedDir, "package.json");
  const manifest = JSON.parse(await readFile(manifestPath, "utf8"));
  manifest.version = releaseVersion;
  if (manifest.dependencies?.["@safebrowse/core"]) {
    manifest.dependencies["@safebrowse/core"] = releaseVersion;
  }
  await writeFile(manifestPath, `${JSON.stringify(manifest, null, 2)}\n`, "utf8");
  const { stdout } = await npm(["pack", "--json", "--pack-destination", destination], {
    cwd: stagedDir
  });
  const [payload] = JSON.parse(stdout);
  return resolve(destination, payload.filename);
}

async function waitForHealth(baseUrl) {
  for (let attempt = 0; attempt < 30; attempt += 1) {
    try {
      const response = await fetch(`${baseUrl}/health`);
      if (response.ok) {
        return response.json();
      }
    } catch {
      // ignore and retry
    }
    await sleep(250);
  }
  throw new Error(`Daemon at ${baseUrl} failed to become healthy.`);
}

async function postJson(baseUrl, path, payload) {
  let response;
  try {
    response = await fetch(`${baseUrl}${path}`, {
      method: "POST",
      headers: {
        "content-type": "application/json"
      },
      body: JSON.stringify(payload)
    });
  } catch (error) {
    throw new Error(
      `Fetch failed for ${path}: ${error instanceof Error ? error.message : String(error)}`
    );
  }
  if (!response.ok) {
    const body = await response.text();
    throw new Error(`Unexpected ${response.status} from ${path}: ${body}`);
  }
  return response.json();
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

async function loadApprovalBrokerDist() {
  return import(pathToFileURL(resolve(repoRoot, "packages/approval-broker/dist/index.js")).href);
}

async function startApprovalBrokerService(workspace) {
  const authToken = "wrapper-parity-v6-broker-token";
  const brokerRuntime = await loadApprovalBrokerDist();
  const keypair = await brokerRuntime.ensureApprovalBrokerKeypair(workspace);
  const broker = await brokerRuntime.startApprovalBroker({
    host: "127.0.0.1",
    port: 0,
    privateKeyPath: keypair.privateKeyPath,
    authToken
  });

  return {
    baseUrl: `http://127.0.0.1:${broker.port}`,
    authToken,
    publicKeyPath: keypair.publicKeyPath,
    issueSignature: async (session, authority) =>
      (
        await brokerRuntime.issueApprovalSignature(
          `http://127.0.0.1:${broker.port}`,
          authToken,
          {
            sessionId: session.sessionId,
            workflowHash: session.workflowHash,
            capabilityId: authority.authorityId ?? authority.ticketId,
            capabilityDigest: authority.authorityDigest ?? authority.ticketDigest
          }
        )
      ).brokerSignature,
    stop: () =>
      new Promise((resolvePromise) => {
        broker.server.close(() => resolvePromise());
      })
  };
}

function normalizeHealth(response) {
  return {
    deploymentProfile: response.deploymentProfile,
    claimBearingReady: response.claimBearingReady,
    legacyRoutesEnabled: response.legacyRoutesEnabled,
    approvalBrokerMode: response.approvalBroker?.mode ?? null,
    parserIsolationMode: response.parserIsolation?.mode ?? response.parserIsolation?.configuredMode ?? null
  };
}

function normalizeObserve(response) {
  return {
    parseStatus: response.compiledObservation?.parseStatus ?? null,
    authorityCandidateCount: response.authorityCandidates?.length ?? 0,
    authorityEligible: response.observationVerdict?.safeConstraints?.authority_eligible ?? null,
    blockedChannels: [...(response.plannerView?.blockedChannels ?? [])].sort(),
    riskMarkers: [...(response.plannerView?.riskMarkers ?? [])].sort()
  };
}

function normalizeAction(response) {
  return {
    observationDecision: response.observationDecision?.decision ?? null,
    authorityDecision: response.authorityDecision?.decision ?? null,
    effectDecision: response.effectDecision?.decision ?? null,
    derivedSinkClass: response.executionPlan?.derivedSinkClass ?? null,
    targetOrigin: response.executionPlan?.targetOrigin ?? null
  };
}

function normalizeApproval(response) {
  return {
    decision: response.verdict?.decision ?? null,
    reasonCodes: [...(response.verdict?.reasonCodes ?? [])].sort(),
    sinkClass: response.approvalEnvelope?.sinkClass ?? null,
    connectorId: response.approvalEnvelope?.connectorId ?? null,
    manifestHash: response.approvalEnvelope?.manifestHash ?? null,
    schemaHash: response.approvalEnvelope?.schemaHash ?? null
  };
}

function normalizeToolPrepare(response) {
  return {
    decision: response.verdict?.decision ?? null,
    reasonCodes: [...(response.verdict?.reasonCodes ?? [])].sort(),
    connectorId: response.onboardingSession?.connectorId ?? null
  };
}

function normalizeCallback(response) {
  return {
    decision: response.verdict?.decision ?? null,
    reasonCodes: [...(response.verdict?.reasonCodes ?? [])].sort(),
    connectorId: response.connectorHandle?.connectorId ?? null
  };
}

function normalizeMemoryStage(response) {
  return {
    decision: response.verdict?.decision ?? null,
    reasonCodes: [...(response.verdict?.reasonCodes ?? [])].sort(),
    tier: response.record?.tier ?? null,
    sourceClass: response.record?.sourceClass ?? null,
    promotionTicketKind: response.promotionTicket ? "memory_promote" : null
  };
}

function normalizeMemoryPromote(response) {
  return {
    decision: response.verdict?.decision ?? null,
    reasonCodes: [...(response.verdict?.reasonCodes ?? [])].sort(),
    tier: response.promotedRecord?.tier ?? null
  };
}

function normalizeMemoryRollback(response) {
  return {
    decision: response.verdict?.decision ?? null,
    reasonCodes: [...(response.verdict?.reasonCodes ?? [])].sort(),
    restoredValue: response.restoredRecord?.value ?? null
  };
}

function normalizeReplay(response) {
  return {
    actorCounts: response.metrics?.actorCounts ?? {},
    eventCount: response.events?.length ?? null
  };
}

function normalizeLegacyRoute(response, status) {
  return {
    status,
    error: response?.error ?? null,
    claimProfile: response?.claimProfile ?? null
  };
}

function assertDeepEqual(label, left, right) {
  if (JSON.stringify(left) !== JSON.stringify(right)) {
    throw new Error(
      `${label} mismatch.\nLEFT=${JSON.stringify(left, null, 2)}\nRIGHT=${JSON.stringify(right, null, 2)}`
    );
  }
}

async function runV6Cases(baseUrl, makeObservePayload, makeActionPayload, signApproval) {
  const results = {};

  results.strict_health = {
    health: normalizeHealth(await fetch(`${baseUrl}/health`).then((response) => response.json()))
  };

  {
    const session = await postJson(baseUrl, "/v6/session/start", {
      taskId: "parity-v6-visible",
      userGoal: "Review docs safely",
      allowedOrigins: ["https://safe.example", "https://docs.python.org"],
      allowedVerbs: ["navigate"],
      forbiddenSinks: []
    });
    const observe = await postJson(
      baseUrl,
      "/v6/observe",
      makeObservePayload(session.session.sessionId, {
        url: "https://safe.example/review",
        visibleText: "Visible docs only. Docs",
        html: "<main>Visible docs only.</main><a href=\"https://docs.python.org/3/tutorial/\">Docs</a>"
      })
    );
    const authority = observe.authorityCandidates[0];
    if (!authority) {
      throw new Error(`visible_navigation produced no authority candidate: ${JSON.stringify(observe, null, 2)}`);
    }
    const action = await postJson(
      baseUrl,
      "/v6/action/evaluate",
      makeActionPayload(session.session.sessionId, authority.authorityId, authority.authorityDigest)
    );
    results.visible_navigation = {
      observe: normalizeObserve(observe),
      action: normalizeAction(action)
    };
  }

  {
    const session = await postJson(baseUrl, "/v6/session/start", {
      taskId: "parity-v6-hash",
      userGoal: "Review connector onboarding safely",
      allowedOrigins: ["https://safe.example"],
      allowedVerbs: ["connector_prepare"],
      forbiddenSinks: []
    });
    const observe = await postJson(baseUrl, "/v6/observe", {
      sessionId: session.session.sessionId,
      capture: {
        ...toolManifestCapture,
        description: `${toolManifestCapture.description} Extra unsafe text.`
      }
    });
    results.manifest_hash_mismatch = {
      observe: normalizeObserve(observe)
    };
  }

  {
    const session = await postJson(baseUrl, "/v6/session/start", {
      taskId: "parity-v6-tool",
      userGoal: "Review connector onboarding safely",
      allowedOrigins: ["https://safe.example"],
      allowedVerbs: ["connector_prepare"],
      forbiddenSinks: []
    });
const observe = await postJson(baseUrl, "/v6/observe", {
      sessionId: session.session.sessionId,
      capture: toolManifestCapture
    });
    const authority = observe.authorityCandidates[0];
    if (!authority) {
      throw new Error(`signed_connector_prepare produced no authority candidate: ${JSON.stringify(observe, null, 2)}`);
    }
    const approval = await postJson(baseUrl, "/v6/approval/issue", {
      sessionId: session.session.sessionId,
      capabilityId: authority.authorityId,
      capabilityDigest: authority.authorityDigest,
      brokerSignature: await signApproval(session.session, authority)
    });
    const prepare = await postJson(baseUrl, "/v6/tool/prepare", {
      sessionId: session.session.sessionId,
      approvalId: approval.approvalEnvelope.approvalId
    });
    const callback = await postJson(baseUrl, "/v6/tool/callback/verify", {
      sessionId: session.session.sessionId,
      approvalId: approval.approvalEnvelope.approvalId,
      onboardingSessionId: prepare.onboardingSession.onboardingSessionId,
      request: {
        sessionId: prepare.onboardingSession.onboardingSessionId,
        callbackUri: "https://safe.example/oauth/callback",
        callbackOrigin: "https://safe.example",
        state: prepare.onboardingSession.state,
        payload: {
          code: "auth-code",
          state: prepare.onboardingSession.state
        }
      }
    });
    results.signed_connector_prepare = {
      observe: normalizeObserve(observe),
      approval: normalizeApproval(approval),
      prepare: normalizeToolPrepare(prepare),
      callback: normalizeCallback(callback)
    };
  }

  {
    const session = await postJson(baseUrl, "/v6/session/start", {
      taskId: "parity-v6-memory",
      userGoal: "Store notes safely",
      allowedOrigins: ["https://safe.example"],
      allowedVerbs: ["memory_promote"],
      forbiddenSinks: []
    });
    const baselineStage = await postJson(baseUrl, "/v6/memory/stage", {
      sessionId: session.session.sessionId,
      key: "workflow_hint",
      value: { note: "baseline" },
      sourceClass: "user_note",
      durable: true
    });
    const baselineApproval = await postJson(baseUrl, "/v6/approval/issue", {
      sessionId: session.session.sessionId,
      capabilityId: baselineStage.promotionTicket.ticketId,
      capabilityDigest: baselineStage.promotionTicket.ticketDigest,
      brokerSignature: await signApproval(session.session, baselineStage.promotionTicket)
    });
    const baselinePromote = await postJson(baseUrl, "/v6/memory/promote", {
      sessionId: session.session.sessionId,
      recordId: baselineStage.record.recordId,
      ticketId: baselineStage.promotionTicket.ticketId,
      ticketDigest: baselineStage.promotionTicket.ticketDigest,
      approvalId: baselineApproval.approvalEnvelope.approvalId
    });
    const blockedStage = await postJson(baseUrl, "/v6/memory/stage", {
      sessionId: session.session.sessionId,
      key: "workflow_hint",
      value: { note: "replacement" },
      sourceClass: "web_observation",
      durable: true,
      sourceObservationId: "obs-v6-uncorroborated"
    });
    const blockedApproval = await postJson(baseUrl, "/v6/approval/issue", {
      sessionId: session.session.sessionId,
      capabilityId: blockedStage.promotionTicket.ticketId,
      capabilityDigest: blockedStage.promotionTicket.ticketDigest,
      brokerSignature: await signApproval(session.session, blockedStage.promotionTicket)
    });
    const blockedPromote = await postJson(baseUrl, "/v6/memory/promote", {
      sessionId: session.session.sessionId,
      recordId: blockedStage.record.recordId,
      ticketId: blockedStage.promotionTicket.ticketId,
      ticketDigest: blockedStage.promotionTicket.ticketDigest,
      approvalId: blockedApproval.approvalEnvelope.approvalId
    });
    const corroboratedStage = await postJson(baseUrl, "/v6/memory/stage", {
      sessionId: session.session.sessionId,
      key: "workflow_hint",
      value: { note: "replacement" },
      sourceClass: "web_observation",
      durable: true,
      sourceObservationId: "obs-v6-corroborated",
      corroboration: [{ source: "manual-review", note: "operator confirmed" }]
    });
    const corroboratedApproval = await postJson(baseUrl, "/v6/approval/issue", {
      sessionId: session.session.sessionId,
      capabilityId: corroboratedStage.promotionTicket.ticketId,
      capabilityDigest: corroboratedStage.promotionTicket.ticketDigest,
      brokerSignature: await signApproval(session.session, corroboratedStage.promotionTicket)
    });
    const promoted = await postJson(baseUrl, "/v6/memory/promote", {
      sessionId: session.session.sessionId,
      recordId: corroboratedStage.record.recordId,
      ticketId: corroboratedStage.promotionTicket.ticketId,
      ticketDigest: corroboratedStage.promotionTicket.ticketDigest,
      approvalId: corroboratedApproval.approvalEnvelope.approvalId
    });
    const rollback = await postJson(baseUrl, "/v6/memory/rollback", {
      sessionId: session.session.sessionId,
      recordId: promoted.promotedRecord.recordId,
      snapshotId: promoted.promotedRecord.snapshotId
    });
    results.memory_rollback = {
      baselineStage: normalizeMemoryStage(baselineStage),
      baselinePromote: normalizeMemoryPromote(baselinePromote),
      blockedStage: normalizeMemoryStage(blockedStage),
      blockedPromote: normalizeMemoryPromote(blockedPromote),
      corroboratedStage: normalizeMemoryStage(corroboratedStage),
      corroboratedPromote: normalizeMemoryPromote(promoted),
      rollback: normalizeMemoryRollback(rollback)
    };
  }

  {
    const session = await postJson(baseUrl, "/v6/session/start", {
      taskId: "parity-v6-replay",
      userGoal: "Review docs safely",
      allowedOrigins: ["https://safe.example", "https://docs.python.org"],
      allowedVerbs: ["navigate"],
      forbiddenSinks: []
    });
    const observe = await postJson(
      baseUrl,
      "/v6/observe",
      makeObservePayload(session.session.sessionId, {
        url: "https://safe.example/review",
        visibleText: "Visible docs only. Docs",
        html: "<main>Visible docs only.</main><a href=\"https://docs.python.org/3/tutorial/\">Docs</a>"
      })
    );
    const authority = observe.authorityCandidates[0];
    if (!authority) {
      throw new Error(`replay_bundle produced no authority candidate: ${JSON.stringify(observe, null, 2)}`);
    }
    await postJson(
      baseUrl,
      "/v6/action/evaluate",
      makeActionPayload(session.session.sessionId, authority.authorityId, authority.authorityDigest)
    );
    const replay = await postJson(baseUrl, "/v6/replay/bundle", {
      sessionId: session.session.sessionId
    });
    results.replay_bundle = {
      replay: normalizeReplay(replay)
    };
  }

  {
    const response = await fetch(`${baseUrl}/v1/action`, {
      method: "POST",
      headers: {
        "content-type": "application/json"
      },
      body: JSON.stringify({
        actionId: "legacy-test",
        verb: "navigate",
        targetUrl: "https://docs.python.org/3/tutorial/",
        trustSignals: {
          sourceOrigin: "https://safe.example",
          frameOrigin: "https://safe.example"
        }
      })
    });
    const payload = await response.json();
    results.legacy_route_disabled = {
      legacy: normalizeLegacyRoute(payload, response.status)
    };
  }

  return results;
}

async function buildVerifiedRegistry(runtime) {
  return {
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
        manifestHash: runtime.computeToolManifestHash(toolManifestCapture),
        schemaHash: runtime.computeToolSchemaHash(toolManifestCapture.schemaDescriptions),
        allowedTransports: ["https"],
        allowedRedirectUris: ["https://safe.example/oauth/callback"],
        allowedCallbackOrigins: ["https://safe.example"],
        allowedScopes: ["citation:read"]
      }
    ]
  };
}

async function startWorkspaceDaemon(publicKeyPem) {
  const coreRuntime = await import(pathToFileURL(resolve(repoRoot, "packages/core/dist/index.js")).href);
  const daemonRuntime = await import(pathToFileURL(resolve(repoRoot, "packages/daemon/dist/index.js")).href);
  const verifiedRegistry = await buildVerifiedRegistry(coreRuntime);
  const server = await daemonRuntime.createSafeBrowseServer({
    policyPack,
    verifiedRegistry,
    deploymentProfile: "secure_v6",
    approvalBrokerPublicKeyPem: publicKeyPem,
    knowledgeBase: emptyKnowledgeBase
  });
  const baseUrl = await listen(server);
  const health = await waitForHealth(baseUrl);
  if (health?.claimBearingReady !== true) {
    throw new Error(`workspace daemon did not report claimBearingReady=true: ${JSON.stringify(health)}`);
  }
  return {
    baseUrl,
    stop: () => closeServer(server)
  };
}

async function runPythonLane(baseUrl, wheelPath, tempDir, brokerBaseUrl, brokerAuthToken) {
  const pythonTarget = resolve(tempDir, "python-target-v6");
  const resultsPath = resolve(tempDir, "python-v6-results.json");
  const scriptPath = resolve(tempDir, "python-v6-parity.py");
  await mkdir(pythonTarget, { recursive: true });

  await execFileAsync(
    process.platform === "win32" ? "py" : "python3",
    ["-m", "pip", "install", "--no-deps", "--target", pythonTarget, wheelPath],
    {
      cwd: repoRoot,
      encoding: "utf8"
    }
  );

  const script = [
    "import json, sys",
    "from pathlib import Path",
    "from urllib import error, request",
    `sys.path.insert(0, ${JSON.stringify(pythonTarget)})`,
    "from safebrowse_client import SafeBrowseClient, build_html_surface_capture",
    `client = SafeBrowseClient(${JSON.stringify(baseUrl)})`,
    `tool_manifest_capture = ${JSON.stringify(toolManifestCapture)}`,
    `broker_url = ${JSON.stringify(brokerBaseUrl + "/v6/approval/sign")}`,
    `broker_token = ${JSON.stringify(brokerAuthToken)}`,
    "",
    "def sign_approval(session, authority):",
    "    payload = json.dumps({",
    "        'sessionId': session['sessionId'],",
    "        'workflowHash': session['workflowHash'],",
    "        'capabilityId': authority.get('authorityId') or authority.get('ticketId'),",
    "        'capabilityDigest': authority.get('authorityDigest') or authority.get('ticketDigest'),",
    "    }).encode('utf-8')",
    "    req = request.Request(broker_url, data=payload, headers={'Content-Type': 'application/json', 'Authorization': 'Bearer ' + broker_token}, method='POST')",
    "    with request.urlopen(req, timeout=10.0) as response:",
    "        return json.loads(response.read().decode('utf-8'))['brokerSignature']",
    "",
    "def post_raw(path, payload):",
    `    req = request.Request(${JSON.stringify(baseUrl)} + path, data=json.dumps(payload).encode('utf-8'), headers={'Content-Type': 'application/json'}, method='POST')`,
    "    try:",
    "        with request.urlopen(req, timeout=10.0) as response:",
    "            return response.status, json.loads(response.read().decode('utf-8'))",
    "    except error.HTTPError as exc:",
    "        return exc.code, json.loads(exc.read().decode('utf-8'))",
    "",
    "results = {}",
    "health = client.health()",
    "results['strict_health'] = {'health': {'deploymentProfile': health.get('deploymentProfile'), 'claimBearingReady': health.get('claimBearingReady'), 'legacyRoutesEnabled': health.get('legacyRoutesEnabled'), 'approvalBrokerMode': health.get('approvalBroker', {}).get('mode'), 'parserIsolationMode': health.get('parserIsolation', {}).get('mode') or health.get('parserIsolation', {}).get('configuredMode')}}",
    "",
    "session = client.start_session({'taskId': 'py-v6-visible', 'userGoal': 'Review docs safely', 'allowedOrigins': ['https://safe.example', 'https://docs.python.org'], 'allowedVerbs': ['navigate'], 'forbiddenSinks': []})['session']",
    "observe = client.observe({'sessionId': session['sessionId'], 'capture': build_html_surface_capture(url='https://safe.example/review', visible_text='Visible docs only. Docs', html='<main>Visible docs only.</main><a href=\"https://docs.python.org/3/tutorial/\">Docs</a>')})",
    "authority = observe['authorityCandidates'][0]",
    "action = client.action({'sessionId': session['sessionId'], 'authorityId': authority['authorityId'], 'authorityDigest': authority['authorityDigest'], 'parameters': {}})",
    "results['visible_navigation'] = {'observe': {'parseStatus': observe.get('compiledObservation', {}).get('parseStatus'), 'authorityCandidateCount': len(observe.get('authorityCandidates', [])), 'authorityEligible': observe.get('observationVerdict', {}).get('safeConstraints', {}).get('authority_eligible'), 'blockedChannels': sorted(observe.get('plannerView', {}).get('blockedChannels', [])), 'riskMarkers': sorted(observe.get('plannerView', {}).get('riskMarkers', []))}, 'action': {'observationDecision': action.get('observationDecision', {}).get('decision'), 'authorityDecision': action.get('authorityDecision', {}).get('decision'), 'effectDecision': action.get('effectDecision', {}).get('decision'), 'derivedSinkClass': action.get('executionPlan', {}).get('derivedSinkClass'), 'targetOrigin': action.get('executionPlan', {}).get('targetOrigin')}}",
    "",
    "session = client.start_session({'taskId': 'py-v6-hash', 'userGoal': 'Review connector onboarding safely', 'allowedOrigins': ['https://safe.example'], 'allowedVerbs': ['connector_prepare'], 'forbiddenSinks': []})['session']",
    "observe = client.observe({'sessionId': session['sessionId'], 'capture': {**tool_manifest_capture, 'description': tool_manifest_capture['description'] + ' Extra unsafe text.'}})",
    "results['manifest_hash_mismatch'] = {'observe': {'parseStatus': observe.get('compiledObservation', {}).get('parseStatus'), 'authorityCandidateCount': len(observe.get('authorityCandidates', [])), 'authorityEligible': observe.get('observationVerdict', {}).get('safeConstraints', {}).get('authority_eligible'), 'blockedChannels': sorted(observe.get('plannerView', {}).get('blockedChannels', [])), 'riskMarkers': sorted(observe.get('plannerView', {}).get('riskMarkers', []))}}",
    "",
    "session = client.start_session({'taskId': 'py-v6-tool', 'userGoal': 'Review connector onboarding safely', 'allowedOrigins': ['https://safe.example'], 'allowedVerbs': ['connector_prepare'], 'forbiddenSinks': []})['session']",
    "observe = client.observe({'sessionId': session['sessionId'], 'capture': tool_manifest_capture})",
    "authority = observe['authorityCandidates'][0]",
    "approval = client.approval_issue({'sessionId': session['sessionId'], 'capabilityId': authority['authorityId'], 'capabilityDigest': authority['authorityDigest'], 'brokerSignature': sign_approval(session, authority)})",
    "prepare = client.tool_prepare({'sessionId': session['sessionId'], 'approvalId': approval['approvalEnvelope']['approvalId']})",
    "callback = client.tool_callback_verify({'sessionId': session['sessionId'], 'approvalId': approval['approvalEnvelope']['approvalId'], 'onboardingSessionId': prepare['onboardingSession']['onboardingSessionId'], 'request': {'sessionId': prepare['onboardingSession']['onboardingSessionId'], 'callbackUri': 'https://safe.example/oauth/callback', 'callbackOrigin': 'https://safe.example', 'state': prepare['onboardingSession']['state'], 'payload': {'code': 'auth-code', 'state': prepare['onboardingSession']['state']}}})",
    "results['signed_connector_prepare'] = {'observe': {'parseStatus': observe.get('compiledObservation', {}).get('parseStatus'), 'authorityCandidateCount': len(observe.get('authorityCandidates', [])), 'authorityEligible': observe.get('observationVerdict', {}).get('safeConstraints', {}).get('authority_eligible'), 'blockedChannels': sorted(observe.get('plannerView', {}).get('blockedChannels', [])), 'riskMarkers': sorted(observe.get('plannerView', {}).get('riskMarkers', []))}, 'approval': {'decision': approval.get('verdict', {}).get('decision'), 'reasonCodes': sorted(approval.get('verdict', {}).get('reasonCodes', [])), 'sinkClass': approval.get('approvalEnvelope', {}).get('sinkClass'), 'connectorId': approval.get('approvalEnvelope', {}).get('connectorId'), 'manifestHash': approval.get('approvalEnvelope', {}).get('manifestHash'), 'schemaHash': approval.get('approvalEnvelope', {}).get('schemaHash')}, 'prepare': {'decision': prepare.get('verdict', {}).get('decision'), 'reasonCodes': sorted(prepare.get('verdict', {}).get('reasonCodes', [])), 'connectorId': prepare.get('onboardingSession', {}).get('connectorId')}, 'callback': {'decision': callback.get('verdict', {}).get('decision'), 'reasonCodes': sorted(callback.get('verdict', {}).get('reasonCodes', [])), 'connectorId': callback.get('connectorHandle', {}).get('connectorId')}}",
    "",
    "session = client.start_session({'taskId': 'py-v6-memory', 'userGoal': 'Store notes safely', 'allowedOrigins': ['https://safe.example'], 'allowedVerbs': ['memory_promote'], 'forbiddenSinks': []})['session']",
    "baseline_stage = client.memory_stage({'sessionId': session['sessionId'], 'key': 'workflow_hint', 'value': {'note': 'baseline'}, 'sourceClass': 'user_note', 'durable': True})",
    "baseline_approval = client.approval_issue({'sessionId': session['sessionId'], 'capabilityId': baseline_stage['promotionTicket']['ticketId'], 'capabilityDigest': baseline_stage['promotionTicket']['ticketDigest'], 'brokerSignature': sign_approval(session, baseline_stage['promotionTicket'])})",
    "baseline_promote = client.memory_promote({'sessionId': session['sessionId'], 'recordId': baseline_stage['record']['recordId'], 'ticketId': baseline_stage['promotionTicket']['ticketId'], 'ticketDigest': baseline_stage['promotionTicket']['ticketDigest'], 'approvalId': baseline_approval['approvalEnvelope']['approvalId']})",
    "blocked_stage = client.memory_stage({'sessionId': session['sessionId'], 'key': 'workflow_hint', 'value': {'note': 'replacement'}, 'sourceClass': 'web_observation', 'durable': True, 'sourceObservationId': 'obs-v6-uncorroborated'})",
    "blocked_approval = client.approval_issue({'sessionId': session['sessionId'], 'capabilityId': blocked_stage['promotionTicket']['ticketId'], 'capabilityDigest': blocked_stage['promotionTicket']['ticketDigest'], 'brokerSignature': sign_approval(session, blocked_stage['promotionTicket'])})",
    "blocked_promote = client.memory_promote({'sessionId': session['sessionId'], 'recordId': blocked_stage['record']['recordId'], 'ticketId': blocked_stage['promotionTicket']['ticketId'], 'ticketDigest': blocked_stage['promotionTicket']['ticketDigest'], 'approvalId': blocked_approval['approvalEnvelope']['approvalId']})",
    "corroborated_stage = client.memory_stage({'sessionId': session['sessionId'], 'key': 'workflow_hint', 'value': {'note': 'replacement'}, 'sourceClass': 'web_observation', 'durable': True, 'sourceObservationId': 'obs-v6-corroborated', 'corroboration': [{'source': 'manual-review', 'note': 'operator confirmed'}]})",
    "corroborated_approval = client.approval_issue({'sessionId': session['sessionId'], 'capabilityId': corroborated_stage['promotionTicket']['ticketId'], 'capabilityDigest': corroborated_stage['promotionTicket']['ticketDigest'], 'brokerSignature': sign_approval(session, corroborated_stage['promotionTicket'])})",
    "corroborated_promote = client.memory_promote({'sessionId': session['sessionId'], 'recordId': corroborated_stage['record']['recordId'], 'ticketId': corroborated_stage['promotionTicket']['ticketId'], 'ticketDigest': corroborated_stage['promotionTicket']['ticketDigest'], 'approvalId': corroborated_approval['approvalEnvelope']['approvalId']})",
    "rollback = client.memory_rollback({'sessionId': session['sessionId'], 'recordId': corroborated_promote['promotedRecord']['recordId'], 'snapshotId': corroborated_promote['promotedRecord']['snapshotId']})",
    "results['memory_rollback'] = {'baselineStage': {'decision': baseline_stage.get('verdict', {}).get('decision'), 'reasonCodes': sorted(baseline_stage.get('verdict', {}).get('reasonCodes', [])), 'tier': baseline_stage.get('record', {}).get('tier'), 'sourceClass': baseline_stage.get('record', {}).get('sourceClass'), 'promotionTicketKind': 'memory_promote' if baseline_stage.get('promotionTicket') else None}, 'baselinePromote': {'decision': baseline_promote.get('verdict', {}).get('decision'), 'reasonCodes': sorted(baseline_promote.get('verdict', {}).get('reasonCodes', [])), 'tier': baseline_promote.get('promotedRecord', {}).get('tier')}, 'blockedStage': {'decision': blocked_stage.get('verdict', {}).get('decision'), 'reasonCodes': sorted(blocked_stage.get('verdict', {}).get('reasonCodes', [])), 'tier': blocked_stage.get('record', {}).get('tier'), 'sourceClass': blocked_stage.get('record', {}).get('sourceClass'), 'promotionTicketKind': 'memory_promote' if blocked_stage.get('promotionTicket') else None}, 'blockedPromote': {'decision': blocked_promote.get('verdict', {}).get('decision'), 'reasonCodes': sorted(blocked_promote.get('verdict', {}).get('reasonCodes', [])), 'tier': blocked_promote.get('promotedRecord', {}).get('tier')}, 'corroboratedStage': {'decision': corroborated_stage.get('verdict', {}).get('decision'), 'reasonCodes': sorted(corroborated_stage.get('verdict', {}).get('reasonCodes', [])), 'tier': corroborated_stage.get('record', {}).get('tier'), 'sourceClass': corroborated_stage.get('record', {}).get('sourceClass'), 'promotionTicketKind': 'memory_promote' if corroborated_stage.get('promotionTicket') else None}, 'corroboratedPromote': {'decision': corroborated_promote.get('verdict', {}).get('decision'), 'reasonCodes': sorted(corroborated_promote.get('verdict', {}).get('reasonCodes', [])), 'tier': corroborated_promote.get('promotedRecord', {}).get('tier')}, 'rollback': {'decision': rollback.get('verdict', {}).get('decision'), 'reasonCodes': sorted(rollback.get('verdict', {}).get('reasonCodes', [])), 'restoredValue': rollback.get('restoredRecord', {}).get('value')}}",
    "",
    "session = client.start_session({'taskId': 'py-v6-replay', 'userGoal': 'Review docs safely', 'allowedOrigins': ['https://safe.example', 'https://docs.python.org'], 'allowedVerbs': ['navigate'], 'forbiddenSinks': []})['session']",
    "observe = client.observe({'sessionId': session['sessionId'], 'capture': build_html_surface_capture(url='https://safe.example/review', visible_text='Visible docs only. Docs', html='<main>Visible docs only.</main><a href=\"https://docs.python.org/3/tutorial/\">Docs</a>')})",
    "authority = observe['authorityCandidates'][0]",
    "client.action({'sessionId': session['sessionId'], 'authorityId': authority['authorityId'], 'authorityDigest': authority['authorityDigest'], 'parameters': {}})",
    "replay = client.replay_bundle({'sessionId': session['sessionId']})",
    "results['replay_bundle'] = {'replay': {'actorCounts': replay.get('metrics', {}).get('actorCounts', {}), 'eventCount': len(replay.get('events', []))}}",
    "",
    "status, legacy = post_raw('/v1/action', {'actionId': 'legacy-test', 'verb': 'navigate', 'targetUrl': 'https://docs.python.org/3/tutorial/', 'trustSignals': {'sourceOrigin': 'https://safe.example', 'frameOrigin': 'https://safe.example'}})",
    "results['legacy_route_disabled'] = {'legacy': {'status': status, 'error': legacy.get('error'), 'claimProfile': legacy.get('claimProfile')}}",
    `Path(${JSON.stringify(resultsPath)}).write_text(json.dumps(results, indent=2), encoding='utf-8')`
  ].join("\n");
  await writeFile(scriptPath, script, "utf8");
  await execFileAsync(process.platform === "win32" ? "py" : "python3", [scriptPath], {
    cwd: repoRoot,
    encoding: "utf8"
  });
  return JSON.parse(await readFile(resultsPath, "utf8"));
}

async function runNpmLane(packDir, publicKeyPath, signApproval) {
  const installDir = resolve(packDir, "npm-install-v6");
  await mkdir(installDir, { recursive: true });
  await writeFile(
    resolve(installDir, "package.json"),
    `${JSON.stringify({ name: "safebrowse-parity-v6", private: true, type: "module" }, null, 2)}\n`,
    "utf8"
  );

  const tarballs = [];
  for (const packageDir of packageDirs) {
    tarballs.push(await packPackage(packageDir, packDir));
  }
  await npm(["install", "--no-package-lock", "--ignore-scripts", ...tarballs], {
    cwd: installDir
  });
  const coreRuntime = await import(
    pathToFileURL(resolve(installDir, "node_modules/@safebrowse/core/dist/index.js")).href
  );
  const daemonRuntime = await import(
    pathToFileURL(resolve(installDir, "node_modules/@safebrowse/daemon/dist/index.js")).href
  );
  const verifiedRegistry = await buildVerifiedRegistry(coreRuntime);
  const originalCwd = process.cwd();
  let server;
  try {
    process.chdir(installDir);
    const approvalBrokerPublicKeyPem = await readFile(publicKeyPath, "utf8");
    server = await daemonRuntime.createSafeBrowseServer({
      policyPack,
      verifiedRegistry,
      deploymentProfile: "secure_v6",
      approvalBrokerPublicKeyPem,
      knowledgeBase: emptyKnowledgeBase
    });
  } finally {
    process.chdir(originalCwd);
  }

  try {
    const baseUrl = await listen(server);
    const health = await waitForHealth(baseUrl);
    if (health?.claimBearingReady !== true) {
      throw new Error(`npm-installed daemon did not report claimBearingReady=true: ${JSON.stringify(health)}`);
    }
    const adapter = await import(
      pathToFileURL(resolve(installDir, "node_modules/@safebrowse/playwright-adapter/dist/index.js")).href
    );

    return await runV6Cases(
      baseUrl,
      (sessionId, snapshot) => adapter.buildObservePayloadV6(sessionId, snapshot),
      (sessionId, authorityId, authorityDigest) =>
        adapter.buildActionEvaluatePayloadV6(sessionId, { authorityId, authorityDigest }),
      signApproval
    ).catch((error) => {
      throw new Error(`npm lane failed: ${error instanceof Error ? error.message : String(error)}`);
    });
  } finally {
    await closeServer(server);
  }
}

async function main() {
  const options = parseArgs();
  const workspace = await mkdtemp(resolve(tmpdir(), "safebrowse-v6-parity-"));

  try {
    const broker = await startApprovalBrokerService(workspace);
    const directDaemon = await startWorkspaceDaemon(
      await readFile(broker.publicKeyPath, "utf8")
    );
    try {
      console.error("Running direct V6 parity lane...");
      const directResults = await runV6Cases(
        directDaemon.baseUrl,
        (sessionId, snapshot) => ({
          sessionId,
          capture: {
            surfaceType: "html",
            url: snapshot.url,
            frameUrl: snapshot.url,
            html: snapshot.html,
            visibleText: snapshot.visibleText,
            captureAttestation: {
              captureMethod: "rendered_dom",
              visibilityAttested: true,
              frameCoverage: "full",
              shadowDomCoverage: "full",
              unsupportedSubtrees: []
            }
          }
        }),
        (sessionId, authorityId, authorityDigest) => ({
          sessionId,
          authorityId,
          authorityDigest,
          parameters: {}
        }),
        (session, authority) => broker.issueSignature(session, authority)
      );

      console.error("Running Python V6 parity lane...");
      const wheelPath = await buildPythonWheelIfNeeded();
      const pythonResults = await runPythonLane(
        directDaemon.baseUrl,
        wheelPath,
        workspace,
        broker.baseUrl,
        broker.authToken
      );

      console.error("Running npm V6 parity lane...");
      const npmResults = await runNpmLane(
        workspace,
        broker.publicKeyPath,
        (session, authority) => broker.issueSignature(session, authority)
      );

      assertDeepEqual("python/direct wrapper parity", pythonResults, directResults);
      assertDeepEqual("npm/direct wrapper parity", npmResults, directResults);

      const summary = {
        subset: options.subset,
        status: "ok",
        cases: Object.keys(directResults),
        direct: directResults,
        python: pythonResults,
        npm: npmResults
      };

      if (options.jsonOut) {
        await writeFile(options.jsonOut, `${JSON.stringify(summary, null, 2)}\n`, "utf8");
      }

      console.log(JSON.stringify(summary, null, 2));
    } finally {
      await directDaemon.stop();
      await broker.stop();
    }
  } finally {
    await rm(workspace, { recursive: true, force: true });
  }
}

main().catch((error) => {
  console.error(error instanceof Error ? error.message : String(error));
  process.exitCode = 1;
});

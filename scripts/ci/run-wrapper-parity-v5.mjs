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
  authType: "oauth",
  requestedScopes: ["citation:read"],
  callbackUri: "https://safe.example/oauth/callback",
  callbackOrigin: "https://safe.example"
};

function parseArgs() {
  const args = process.argv.slice(2);
  const options = {
    subset: "full",
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
  const authToken = "wrapper-parity-broker-token";
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
    issueSignature: async (session, capability) =>
      (
        await brokerRuntime.issueApprovalSignature(
          `http://127.0.0.1:${broker.port}`,
          authToken,
          {
            sessionId: session.sessionId,
            workflowHash: session.workflowHash,
            capabilityId: capability.capabilityId,
            capabilityDigest: capability.capabilityDigest
          }
        )
      ).brokerSignature,
    stop: () =>
      new Promise((resolvePromise) => {
        broker.server.close(() => resolvePromise());
      })
  };
}

function normalizeObserve(response) {
  return {
    parseStatus: response.compiledObservation?.parseStatus ?? null,
    authorityEligible: response.observationVerdict?.safeConstraints?.authority_eligible ?? null,
    blockedChannels: [...(response.plannerView?.blockedChannels ?? [])].sort(),
    capabilityKinds: [...(response.capabilities ?? [])].map((entry) => entry.kind).sort(),
    riskMarkers: [...(response.plannerView?.riskMarkers ?? [])].sort()
  };
}

function normalizeAction(response) {
  return {
    decision: response.verdict?.decision ?? null,
    reasonCodes: [...(response.verdict?.reasonCodes ?? [])].sort(),
    derivedSinkClass: response.executionPlan?.derivedSinkClass ?? null,
    targetOrigin: response.executionPlan?.targetOrigin ?? null
  };
}

function normalizeApproval(response) {
  return {
    decision: response.verdict?.decision ?? null,
    reasonCodes: [...(response.verdict?.reasonCodes ?? [])].sort(),
    sinkClass: response.approvalEnvelope?.sinkClass ?? null,
    connectorId: response.approvalEnvelope?.connectorId ?? null
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

function normalizeMemoryWrite(response) {
  return {
    decision: response.verdict?.decision ?? null,
    reasonCodes: [...(response.verdict?.reasonCodes ?? [])].sort(),
    tier: response.record?.tier ?? null,
    promotionKind: response.promotionCapability?.kind ?? null
  };
}

function normalizeMemoryPromote(response) {
  return {
    decision: response.verdict?.decision ?? null,
    reasonCodes: [...(response.verdict?.reasonCodes ?? [])].sort(),
    tier: response.promotedRecord?.tier ?? null
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

async function buildVerifiedRegistry(runtime) {
  return {
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
        manifestHash: runtime.computeToolManifestHash(toolManifestCapture),
        schemaHash: runtime.computeToolSchemaHash(toolManifestCapture.schemaDescriptions)
      }
    ]
  };
}

async function runV5Cases(baseUrl, makeHtmlCapture, signApproval, subset) {
  const caseIds =
    subset === "packaging"
      ? ["hidden_html", "visible_navigation"]
      : [
          "hidden_html",
          "visible_navigation",
          "navigate_cannot_issue_connector_approval",
          "unsigned_connector_approval",
          "signed_connector_prepare",
          "callback_mismatch",
          "legacy_route_disabled"
        ];

  const results = {};

  if (caseIds.includes("hidden_html")) {
    const session = await postJson(baseUrl, "/v5/session/start", {
      taskId: "parity-hidden",
      userGoal: "Review docs safely",
      allowedOrigins: ["https://safe.example", "https://docs.python.org"],
      allowedVerbs: ["navigate"],
      forbiddenSinks: []
    });
    const observe = await postJson(baseUrl, "/v5/observe", {
      sessionId: session.session.sessionId,
      capture: makeHtmlCapture({
        html: "<main>Visible docs only.</main><div hidden><a href=\"https://docs.python.org/3/tutorial/\">continuity path</a></div>",
        visibleText: "Visible docs only.",
        hiddenText: ["continuity path"]
      })
    });
    results.hidden_html = {
      observe: normalizeObserve(observe)
    };
  }

  if (caseIds.includes("visible_navigation")) {
    const session = await postJson(baseUrl, "/v5/session/start", {
      taskId: "parity-visible",
      userGoal: "Review docs safely",
      allowedOrigins: ["https://safe.example", "https://docs.python.org"],
      allowedVerbs: ["navigate"],
      forbiddenSinks: []
    });
    const observe = await postJson(baseUrl, "/v5/observe", {
      sessionId: session.session.sessionId,
      capture: makeHtmlCapture({
        html: "<main>Visible docs only.</main><a href=\"https://docs.python.org/3/tutorial/\">Docs</a>",
        visibleText: "Visible docs only. Docs"
      })
    });
    const capability = observe.capabilities[0];
    const action = await postJson(baseUrl, "/v5/capability/use", {
      sessionId: session.session.sessionId,
      capabilityId: capability.capabilityId,
      capabilityDigest: capability.capabilityDigest,
      parameters: {}
    });
    results.visible_navigation = {
      observe: normalizeObserve(observe),
      action: normalizeAction(action)
    };
  }

  if (caseIds.includes("navigate_cannot_issue_connector_approval")) {
    const session = await postJson(baseUrl, "/v5/session/start", {
      taskId: "parity-nav-approval",
      userGoal: "Reject connector onboarding from plain visible navigation.",
      allowedOrigins: ["https://safe.example", "https://docs.python.org"],
      allowedVerbs: ["navigate", "connector_prepare"],
      forbiddenSinks: []
    });
    const observe = await postJson(baseUrl, "/v5/observe", {
      sessionId: session.session.sessionId,
      capture: makeHtmlCapture({
        html: "<main>Visible docs only.</main><a href=\"https://docs.python.org/3/tutorial/\">Docs</a>",
        visibleText: "Visible docs only. Docs"
      })
    });
    const capability = observe.capabilities[0];
    const approval = await postJson(baseUrl, "/v5/approval/issue", {
      sessionId: session.session.sessionId,
      capabilityId: capability.capabilityId,
      capabilityDigest: capability.capabilityDigest,
      brokerSignature: await signApproval(session.session, capability)
    });
    results.navigate_cannot_issue_connector_approval = {
      observe: normalizeObserve(observe),
      approval: normalizeApproval(approval)
    };
  }

  if (caseIds.includes("unsigned_connector_approval")) {
    const session = await postJson(baseUrl, "/v5/session/start", {
      taskId: "parity-tool-unsigned",
      userGoal: "Review connector onboarding safely",
      allowedOrigins: ["https://safe.example"],
      allowedVerbs: ["connector_prepare"],
      forbiddenSinks: []
    });
    const observe = await postJson(baseUrl, "/v5/observe", {
      sessionId: session.session.sessionId,
      capture: toolManifestCapture
    });
    const capability = observe.capabilities[0];
    const approval = await postJson(baseUrl, "/v5/approval/issue", {
      sessionId: session.session.sessionId,
      capabilityId: capability.capabilityId,
      capabilityDigest: capability.capabilityDigest,
      brokerSignature: "invalid-signature"
    });
    results.unsigned_connector_approval = {
      observe: normalizeObserve(observe),
      approval: normalizeApproval(approval)
    };
  }

  if (caseIds.includes("signed_connector_prepare")) {
    const session = await postJson(baseUrl, "/v5/session/start", {
      taskId: "parity-tool",
      userGoal: "Review connector onboarding safely",
      allowedOrigins: ["https://safe.example"],
      allowedVerbs: ["connector_prepare"],
      forbiddenSinks: []
    });
    const observe = await postJson(baseUrl, "/v5/observe", {
      sessionId: session.session.sessionId,
      capture: toolManifestCapture
    });
    const capability = observe.capabilities[0];
    const brokerSignature = await signApproval(session.session, capability);
    const approval = await postJson(baseUrl, "/v5/approval/issue", {
      sessionId: session.session.sessionId,
      capabilityId: capability.capabilityId,
      capabilityDigest: capability.capabilityDigest,
      brokerSignature
    });
    const prepare = await postJson(baseUrl, "/v5/tool/prepare", {
      sessionId: session.session.sessionId,
      approvalId: approval.approvalEnvelope.approvalId
    });
    const callback = await postJson(baseUrl, "/v5/tool/callback/verify", {
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

  if (caseIds.includes("callback_mismatch")) {
    const session = await postJson(baseUrl, "/v5/session/start", {
      taskId: "parity-tool-mismatch",
      userGoal: "Reject callback mismatches after valid prepare.",
      allowedOrigins: ["https://safe.example"],
      allowedVerbs: ["connector_prepare"],
      forbiddenSinks: []
    });
    const observe = await postJson(baseUrl, "/v5/observe", {
      sessionId: session.session.sessionId,
      capture: toolManifestCapture
    });
    const capability = observe.capabilities[0];
    const approval = await postJson(baseUrl, "/v5/approval/issue", {
      sessionId: session.session.sessionId,
      capabilityId: capability.capabilityId,
      capabilityDigest: capability.capabilityDigest,
      brokerSignature: await signApproval(session.session, capability)
    });
    const prepare = await postJson(baseUrl, "/v5/tool/prepare", {
      sessionId: session.session.sessionId,
      approvalId: approval.approvalEnvelope.approvalId
    });
    const callback = await postJson(baseUrl, "/v5/tool/callback/verify", {
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
    });
    results.callback_mismatch = {
      observe: normalizeObserve(observe),
      approval: normalizeApproval(approval),
      prepare: normalizeToolPrepare(prepare),
      callback: normalizeCallback(callback)
    };
  }

  if (caseIds.includes("legacy_route_disabled")) {
    const response = await fetch(`${baseUrl}/v1/action`, {
      method: "POST",
      headers: {
        "content-type": "application/json"
      },
      body: JSON.stringify({
        actionId: "legacy-test",
        verb: "navigate",
        targetUrl: "https://docs.python.org/3/tutorial/"
      })
    });
    const payload = await response.json();
    results.legacy_route_disabled = {
      legacy: normalizeLegacyRoute(payload, response.status)
    };
  }

  return results;
}

async function startWorkspaceDaemon(publicKeyPath) {
  const coreRuntime = await import(pathToFileURL(resolve(repoRoot, "packages/core/dist/index.js")).href);
  const daemonRuntime = await import(pathToFileURL(resolve(repoRoot, "packages/daemon/dist/index.js")).href);
  const verifiedRegistry = await buildVerifiedRegistry(coreRuntime);
  const approvalBrokerPublicKeyPem = await readFile(publicKeyPath, "utf8");
  const server = await daemonRuntime.createSafeBrowseServer({
    policyPack,
    verifiedRegistry,
    deploymentProfile: "secure_v5",
    approvalBrokerPublicKeyPem,
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

async function runPythonLane(baseUrl, wheelPath, tempDir, subset, brokerBaseUrl, brokerAuthToken) {
  const pythonTarget = resolve(tempDir, "python-target");
  const resultsPath = resolve(tempDir, "python-results.json");
  const scriptPath = resolve(tempDir, "python-parity.py");
  await mkdir(pythonTarget, { recursive: true });

  await execFileAsync(
    process.platform === "win32" ? "py" : "python3",
    ["-m", "pip", "install", "--no-deps", "--target", pythonTarget, wheelPath],
    {
      cwd: repoRoot,
      encoding: "utf8"
    }
  );

  const script = `import json, os, subprocess, sys
from pathlib import Path
from urllib import error, request

sys.path.insert(0, ${JSON.stringify(pythonTarget)})
from safebrowse_client import SafeBrowseClient, build_html_surface_capture

client = SafeBrowseClient(${JSON.stringify(baseUrl)})
results = {}
subset = ${JSON.stringify(subset)}
broker_base_url = ${JSON.stringify(brokerBaseUrl)}
broker_auth_token = ${JSON.stringify(brokerAuthToken)}
tool_manifest_capture = ${JSON.stringify(toolManifestCapture)}


def sign_payload(payload: str) -> str:
    req = request.Request(
        broker_base_url + "/v5/approval/sign",
        data=payload.encode("utf-8"),
        headers={
            "Content-Type": "application/json",
            "Authorization": "Bearer " + broker_auth_token,
        },
        method="POST",
    )
    with request.urlopen(req, timeout=10.0) as response:
        return json.loads(response.read().decode("utf-8"))["brokerSignature"]


def normalize_observe(response: dict) -> dict:
    return {
        "parseStatus": response.get("compiledObservation", {}).get("parseStatus"),
        "authorityEligible": response.get("observationVerdict", {}).get("safeConstraints", {}).get("authority_eligible"),
        "blockedChannels": sorted(response.get("plannerView", {}).get("blockedChannels", [])),
        "capabilityKinds": sorted([entry["kind"] for entry in response.get("capabilities", [])]),
        "riskMarkers": sorted(response.get("plannerView", {}).get("riskMarkers", [])),
    }


def normalize_action(response: dict) -> dict:
    return {
        "decision": response.get("verdict", {}).get("decision"),
        "reasonCodes": sorted(response.get("verdict", {}).get("reasonCodes", [])),
        "derivedSinkClass": response.get("executionPlan", {}).get("derivedSinkClass"),
        "targetOrigin": response.get("executionPlan", {}).get("targetOrigin"),
    }


def normalize_approval(response: dict) -> dict:
    return {
        "decision": response.get("verdict", {}).get("decision"),
        "reasonCodes": sorted(response.get("verdict", {}).get("reasonCodes", [])),
        "sinkClass": response.get("approvalEnvelope", {}).get("sinkClass"),
        "connectorId": response.get("approvalEnvelope", {}).get("connectorId"),
    }


def normalize_tool_prepare(response: dict) -> dict:
    return {
        "decision": response.get("verdict", {}).get("decision"),
        "reasonCodes": sorted(response.get("verdict", {}).get("reasonCodes", [])),
        "connectorId": response.get("onboardingSession", {}).get("connectorId"),
    }


def normalize_callback(response: dict) -> dict:
    return {
        "decision": response.get("verdict", {}).get("decision"),
        "reasonCodes": sorted(response.get("verdict", {}).get("reasonCodes", [])),
        "connectorId": response.get("connectorHandle", {}).get("connectorId"),
    }


def normalize_legacy(response: dict, status: int) -> dict:
    return {
        "status": status,
        "error": response.get("error"),
        "claimProfile": response.get("claimProfile"),
    }


def post_raw(path: str, payload: dict) -> tuple[int, dict]:
    req = request.Request(
        ${JSON.stringify(baseUrl)} + path,
        data=json.dumps(payload).encode("utf-8"),
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    try:
        with request.urlopen(req, timeout=10.0) as response:
            return response.status, json.loads(response.read().decode("utf-8"))
    except error.HTTPError as exc:
        return exc.code, json.loads(exc.read().decode("utf-8"))


if subset in ("full", "packaging"):
    session = client.start_session_v5({"taskId": "py-hidden", "userGoal": "Review docs safely", "allowedOrigins": ["https://safe.example", "https://docs.python.org"], "allowedVerbs": ["navigate"], "forbiddenSinks": []})["session"]
    observe = client.observe_v5({"sessionId": session["sessionId"], "capture": build_html_surface_capture(url="https://safe.example/review", visible_text="Visible docs only.", html="<main>Visible docs only.</main><div hidden><a href=\\"https://docs.python.org/3/tutorial/\\">continuity path</a></div>", hidden_text=["continuity path"])})
    results["hidden_html"] = {"observe": normalize_observe(observe)}

    session = client.start_session_v5({"taskId": "py-visible", "userGoal": "Review docs safely", "allowedOrigins": ["https://safe.example", "https://docs.python.org"], "allowedVerbs": ["navigate"], "forbiddenSinks": []})["session"]
    observe = client.observe_v5({"sessionId": session["sessionId"], "capture": build_html_surface_capture(url="https://safe.example/review", visible_text="Visible docs only. Docs", html="<main>Visible docs only.</main><a href=\\"https://docs.python.org/3/tutorial/\\">Docs</a>")})
    capability = observe["capabilities"][0]
    action = client.action_v5({"sessionId": session["sessionId"], "capabilityId": capability["capabilityId"], "capabilityDigest": capability["capabilityDigest"], "parameters": {}})
    results["visible_navigation"] = {"observe": normalize_observe(observe), "action": normalize_action(action)}

if subset == "full":
    session = client.start_session_v5({"taskId": "py-nav-approval", "userGoal": "Reject connector onboarding from visible navigation.", "allowedOrigins": ["https://safe.example", "https://docs.python.org"], "allowedVerbs": ["navigate", "connector_prepare"], "forbiddenSinks": []})["session"]
    observe = client.observe_v5({"sessionId": session["sessionId"], "capture": build_html_surface_capture(url="https://safe.example/review", visible_text="Visible docs only. Docs", html="<main>Visible docs only.</main><a href=\\"https://docs.python.org/3/tutorial/\\">Docs</a>")})
    capability = observe["capabilities"][0]
    approval = client.approval_issue_v5({"sessionId": session["sessionId"], "capabilityId": capability["capabilityId"], "capabilityDigest": capability["capabilityDigest"], "brokerSignature": sign_payload(json.dumps({"capabilityDigest": capability["capabilityDigest"], "capabilityId": capability["capabilityId"], "expiresInSeconds": 600, "sessionId": session["sessionId"], "workflowHash": session["workflowHash"]}))})
    results["navigate_cannot_issue_connector_approval"] = {"observe": normalize_observe(observe), "approval": normalize_approval(approval)}

    session = client.start_session_v5({"taskId": "py-tool-unsigned", "userGoal": "Reject unsigned connector approval.", "allowedOrigins": ["https://safe.example"], "allowedVerbs": ["connector_prepare"], "forbiddenSinks": []})["session"]
    observe = client.observe_v5({"sessionId": session["sessionId"], "capture": tool_manifest_capture})
    capability = observe["capabilities"][0]
    approval = client.approval_issue_v5({"sessionId": session["sessionId"], "capabilityId": capability["capabilityId"], "capabilityDigest": capability["capabilityDigest"], "brokerSignature": "invalid-signature"})
    results["unsigned_connector_approval"] = {"observe": normalize_observe(observe), "approval": normalize_approval(approval)}

    session = client.start_session_v5({"taskId": "py-tool", "userGoal": "Review connector onboarding safely", "allowedOrigins": ["https://safe.example"], "allowedVerbs": ["connector_prepare"], "forbiddenSinks": []})["session"]
    observe = client.observe_v5({"sessionId": session["sessionId"], "capture": tool_manifest_capture})
    capability = observe["capabilities"][0]
    payload = json.dumps({"capabilityDigest": capability["capabilityDigest"], "capabilityId": capability["capabilityId"], "expiresInSeconds": 600, "sessionId": session["sessionId"], "workflowHash": session["workflowHash"]})
    approval = client.approval_issue_v5({"sessionId": session["sessionId"], "capabilityId": capability["capabilityId"], "capabilityDigest": capability["capabilityDigest"], "brokerSignature": sign_payload(payload)})
    prepare = client.tool_prepare_v5({"sessionId": session["sessionId"], "approvalId": approval["approvalEnvelope"]["approvalId"]})
    callback = client.tool_callback_verify_v5({"sessionId": session["sessionId"], "approvalId": approval["approvalEnvelope"]["approvalId"], "onboardingSessionId": prepare["onboardingSession"]["onboardingSessionId"], "request": {"sessionId": prepare["onboardingSession"]["onboardingSessionId"], "callbackUri": "https://safe.example/oauth/callback", "callbackOrigin": "https://safe.example", "state": prepare["onboardingSession"]["state"], "payload": {"code": "auth-code", "state": prepare["onboardingSession"]["state"]}}})
    results["signed_connector_prepare"] = {"observe": normalize_observe(observe), "approval": normalize_approval(approval), "prepare": normalize_tool_prepare(prepare), "callback": normalize_callback(callback)}

    session = client.start_session_v5({"taskId": "py-callback-mismatch", "userGoal": "Reject callback mismatch after prepare.", "allowedOrigins": ["https://safe.example"], "allowedVerbs": ["connector_prepare"], "forbiddenSinks": []})["session"]
    observe = client.observe_v5({"sessionId": session["sessionId"], "capture": tool_manifest_capture})
    capability = observe["capabilities"][0]
    payload = json.dumps({"capabilityDigest": capability["capabilityDigest"], "capabilityId": capability["capabilityId"], "expiresInSeconds": 600, "sessionId": session["sessionId"], "workflowHash": session["workflowHash"]})
    approval = client.approval_issue_v5({"sessionId": session["sessionId"], "capabilityId": capability["capabilityId"], "capabilityDigest": capability["capabilityDigest"], "brokerSignature": sign_payload(payload)})
    prepare = client.tool_prepare_v5({"sessionId": session["sessionId"], "approvalId": approval["approvalEnvelope"]["approvalId"]})
    callback = client.tool_callback_verify_v5({"sessionId": session["sessionId"], "approvalId": approval["approvalEnvelope"]["approvalId"], "onboardingSessionId": prepare["onboardingSession"]["onboardingSessionId"], "request": {"sessionId": prepare["onboardingSession"]["onboardingSessionId"], "callbackUri": "https://safe.example/oauth/callback/unexpected", "callbackOrigin": "https://safe.example", "state": prepare["onboardingSession"]["state"], "payload": {"code": "auth-code", "state": prepare["onboardingSession"]["state"]}}})
    results["callback_mismatch"] = {"observe": normalize_observe(observe), "approval": normalize_approval(approval), "prepare": normalize_tool_prepare(prepare), "callback": normalize_callback(callback)}

    legacy_status, legacy = post_raw("/v1/action", {"actionId": "legacy-test", "verb": "navigate", "targetUrl": "https://docs.python.org/3/tutorial/"})
    results["legacy_route_disabled"] = {"legacy": normalize_legacy(legacy, legacy_status)}

Path(${JSON.stringify(resultsPath)}).write_text(json.dumps(results, indent=2), encoding="utf-8")
`;
  await writeFile(scriptPath, script, "utf8");
  await execFileAsync(process.platform === "win32" ? "py" : "python3", [scriptPath], {
    cwd: repoRoot,
    encoding: "utf8"
  });
  return JSON.parse(await readFile(resultsPath, "utf8"));
}

async function runNpmLane(packDir, publicKeyPath, signApproval, subset) {
  const installDir = resolve(packDir, "npm-install");
  await mkdir(installDir, { recursive: true });
  await writeFile(
    resolve(installDir, "package.json"),
    `${JSON.stringify({ name: "safebrowse-parity", private: true, type: "module" }, null, 2)}\n`,
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
      deploymentProfile: "secure_v5",
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
    const makeHtmlCapture = ({ html, visibleText, hiddenText = [] }) =>
      adapter.createSurfaceCaptureFromSnapshot({
        url: "https://safe.example/review",
        visibleText,
        html,
        hiddenText
      });
    try {
      return await runV5Cases(baseUrl, makeHtmlCapture, signApproval, subset);
    } catch (error) {
      throw new Error(`npm lane failed: ${error instanceof Error ? error.message : String(error)}`);
    }
  } finally {
    await closeServer(server);
  }
}

async function main() {
  const options = parseArgs();
  const workspace = await mkdtemp(resolve(tmpdir(), "safebrowse-v5-parity-"));

  try {
    const broker = await startApprovalBrokerService(workspace);
    const directDaemon = await startWorkspaceDaemon(broker.publicKeyPath);
    try {
      console.error("Running direct V5 parity lane...");
      const directResults = await runV5Cases(
        directDaemon.baseUrl,
        ({ html, visibleText, hiddenText = [] }) => ({
          surfaceType: "html",
          url: "https://safe.example/review",
          frameUrl: "https://safe.example/review",
          html,
          visibleText,
          hiddenText
        }),
        (session, capability) => broker.issueSignature(session, capability),
        options.subset
      );

      console.error("Running Python V5 parity lane...");
      const wheelPath = await buildPythonWheelIfNeeded();
      const pythonResults = await runPythonLane(
        directDaemon.baseUrl,
        wheelPath,
        workspace,
        options.subset,
        broker.baseUrl,
        broker.authToken
      );
      console.error("Running npm V5 parity lane...");
      const npmResults = await runNpmLane(
        workspace,
        broker.publicKeyPath,
        (session, capability) => broker.issueSignature(session, capability),
        options.subset
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

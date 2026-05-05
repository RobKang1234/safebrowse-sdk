import { createServer } from "node:net";
import { cp, mkdir, readFile, rename, rm, writeFile } from "node:fs/promises";
import { resolve, join, dirname } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";
import { spawn } from "node:child_process";

const repoRoot = resolve(dirname(fileURLToPath(import.meta.url)), "..", "..");
const suitePath = join(repoRoot, "config", "auditor", "v5_secure_claim_suite.json");
const latestDir = join(repoRoot, "demo-output", "latest");
const compatLatestDir = join(repoRoot, "demo-output", "latest-auditor-suite");

async function loadApprovalBrokerRuntime() {
  return import(pathToFileURL(resolve(repoRoot, "packages/approval-broker/dist/index.js")).href);
}

interface SuiteCase {
  id: string;
  title: string;
  kind: string;
  html?: string;
  visible_text?: string;
  expected?: {
    decision?: string;
    capabilities?: string[];
  };
}

interface CaseResult {
  id: string;
  title: string;
  kind: string;
  expectedDecision: string;
  observedDecision: string;
  observedCapabilities: string[];
  reasonCodes: string[];
  status: "pass" | "fail";
  classification: "runtime_gap" | "harness_gap" | "parity_gap" | "legacy-scope gap";
  detail: string;
}

function now(): string {
  return new Date().toISOString();
}

async function getFreePort() {
  const server = createServer();
  await new Promise<void>((resolvePromise, rejectPromise) => {
    server.once("error", rejectPromise);
    server.listen(0, "127.0.0.1", () => resolvePromise());
  });
  const address = server.address();
  if (!address || typeof address === "string") {
    throw new Error("Failed to allocate an ephemeral port.");
  }
  const port = address.port;
  await new Promise<void>((resolvePromise) => server.close(() => resolvePromise()));
  return port;
}

async function sleep(ms: number) {
  return new Promise((resolvePromise) => setTimeout(resolvePromise, ms));
}

async function stopProcess(child: ReturnType<typeof spawn>) {
  if (child.exitCode !== null || child.killed) {
    return;
  }
  await new Promise<void>((resolvePromise) => {
    child.once("close", () => resolvePromise());
    child.kill("SIGTERM");
    setTimeout(() => {
      if (child.exitCode === null) {
        child.kill("SIGKILL");
      }
    }, 1000).unref();
  });
}

async function waitForHealth(baseUrl: string): Promise<Record<string, any>> {
  for (let attempt = 0; attempt < 30; attempt += 1) {
    try {
      const response = await fetch(`${baseUrl}/health`);
      if (response.ok) {
        return (await response.json()) as Record<string, any>;
      }
    } catch {
      // retry
    }
    await sleep(250);
  }
  throw new Error(`Daemon at ${baseUrl} failed to become healthy.`);
}

async function postJson<T>(baseUrl: string, path: string, payload: unknown): Promise<T> {
  const response = await fetch(`${baseUrl}${path}`, {
    method: "POST",
    headers: {
      "content-type": "application/json"
    },
    body: JSON.stringify(payload)
  });
  if (!response.ok) {
    throw new Error(`Unexpected ${response.status} from ${path}`);
  }
  return response.json() as Promise<T>;
}

function toNdjson(entries: Array<Record<string, unknown>>): string {
  return entries.map((entry) => JSON.stringify(entry)).join("\n");
}

function markdownTable(rows: Array<Record<string, string>>): string {
  if (!rows.length) {
    return "";
  }
  const headers = Object.keys(rows[0]);
  const lines = [
    `| ${headers.join(" | ")} |`,
    `| ${headers.map(() => "---").join(" | ")} |`
  ];
  for (const row of rows) {
    lines.push(`| ${headers.map((header) => String(row[header] ?? "").replaceAll("|", "\\|")).join(" | ")} |`);
  }
  return lines.join("\n");
}

function htmlEscape(value: string): string {
  return value
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;");
}

function assertCondition(condition: unknown, message: string) {
  if (!condition) {
    throw new Error(message);
  }
}

function normalizedCapabilityKinds(response: Record<string, any> | undefined): string[] {
  return Array.isArray(response?.capabilities)
    ? response.capabilities
        .map((capability: Record<string, unknown>) => String(capability.kind ?? ""))
        .filter(Boolean)
        .sort()
    : [];
}

function decisionOf(response: Record<string, any> | undefined): string {
  return String(
    response?.verdict?.decision ??
      response?.artifactVerdict?.decision ??
      response?.observationVerdict?.decision ??
      response?.error ??
      "unknown"
  );
}

function reasonCodesOf(response: Record<string, any> | undefined): string[] {
  const reasonCodes =
    response?.verdict?.reasonCodes ??
    response?.artifactVerdict?.reasonCodes ??
    response?.observationVerdict?.reasonCodes ??
    [];
  return Array.isArray(reasonCodes) ? reasonCodes.map((entry: unknown) => String(entry)) : [];
}

function makeLaneLog(
  lane: "raw" | "raw_model" | "sdk",
  testCase: SuiteCase,
  data: Record<string, unknown>
): Record<string, unknown> {
  return {
    timestamp: now(),
    lane,
    caseId: testCase.id,
    title: testCase.title,
    kind: testCase.kind,
    ...data
  };
}

async function writeValidatedLatest(sourceDir: string) {
  const required = [
    "summary.json",
    "report.md",
    "report.html",
    "system.ndjson",
    "raw-agent.ndjson",
    "raw-qwen-agent.ndjson",
    "sdk-qwen-agent.ndjson",
    "sink-hits.json",
    "internal-assessment.json",
    "internal-assessment.md"
  ];

  for (const file of required) {
    await readFile(join(sourceDir, file), "utf8");
  }

  const nextDir = `${latestDir}.next`;
  const compatNextDir = `${compatLatestDir}.next`;
  await rm(nextDir, { recursive: true, force: true });
  await rm(compatNextDir, { recursive: true, force: true });
  await cp(sourceDir, nextDir, { recursive: true, force: true });
  await cp(sourceDir, compatNextDir, { recursive: true, force: true });
  await rm(latestDir, { recursive: true, force: true });
  await rm(compatLatestDir, { recursive: true, force: true });
  await rename(nextDir, latestDir);
  await rename(compatNextDir, compatLatestDir);
}

async function startSecureDaemon(publicKeyPath: string) {
  const port = await getFreePort();
  const child = spawn(
    process.execPath,
    [
      resolve(repoRoot, "packages/daemon/dist/index.js"),
      "--port",
      String(port),
      "--root-dir",
      repoRoot,
      "--deployment-profile",
      "secure_v6",
      "--approval-broker-mode",
      "external_service",
      "--approval-broker-public-key-path",
      publicKeyPath,
      "--parser-isolation-mode",
      "node_permission_process"
    ],
    {
      cwd: repoRoot,
      stdio: "pipe"
    }
  );
  const baseUrl = `http://127.0.0.1:${port}`;
  const health = await waitForHealth(baseUrl);
  return {
    baseUrl,
    health,
    stop: () => stopProcess(child)
  };
}

async function startApprovalBrokerService(outputDir: string) {
  const authToken = "auditor-review-broker-token";
  const brokerRuntime = await loadApprovalBrokerRuntime();
  const keypair = await brokerRuntime.ensureApprovalBrokerKeypair(outputDir);
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
    stop: () =>
      new Promise<void>((resolvePromise) => {
        broker.server.close(() => resolvePromise());
      })
  };
}

async function signApprovalViaBroker(
  broker: Awaited<ReturnType<typeof startApprovalBrokerService>>,
  session: Record<string, any>,
  capability: Record<string, any>
) {
  const brokerRuntime = await loadApprovalBrokerRuntime();
  return (
    await brokerRuntime.issueApprovalSignature(broker.baseUrl, broker.authToken, {
      sessionId: session.sessionId,
      workflowHash: session.workflowHash,
      capabilityId: capability.capabilityId,
      capabilityDigest: capability.capabilityDigest
    })
  ).brokerSignature;
}

async function main() {
  const suite = JSON.parse(await readFile(suitePath, "utf8")) as {
    suite_id: string;
    claim_profile: string;
    cases: SuiteCase[];
  };
  const timestamp = now().replaceAll(":", "-").replaceAll(".", "-");
  const archiveDir = join(repoRoot, "demo-output", `auditor-suite-${timestamp}`);
  await mkdir(archiveDir, { recursive: true });

  const systemLog: Array<Record<string, unknown>> = [];
  const sdkLog: Array<Record<string, unknown>> = [];
  const rawLog: Array<Record<string, unknown>> = [];
  const rawQwenLog: Array<Record<string, unknown>> = [];
  const sinkHits: Array<Record<string, unknown>> = [];
  const results: CaseResult[] = [];

  const broker = await startApprovalBrokerService(archiveDir);
  const daemon = await startSecureDaemon(broker.publicKeyPath);
  try {
    assertCondition(
      daemon.health?.claimBearingReady === true,
      "secure_v6 daemon did not report a claim-bearing secure posture."
    );
    for (const testCase of suite.cases) {
      const session = await postJson<{ session: Record<string, any> }>(daemon.baseUrl, "/v6/session/start", {
        taskId: `audit-${testCase.id}`,
        userGoal: testCase.title,
        allowedOrigins: ["https://safe.example", "https://docs.python.org"],
        allowedVerbs: ["navigate", "connector_prepare"],
        forbiddenSinks: []
      });

      let status: "pass" | "fail" = "pass";
      let classification: CaseResult["classification"] = "runtime_gap";
      let detail = "";
      let observedDecision = "unknown";
      let observedCapabilities: string[] = [];
      let observedReasonCodes: string[] = [];

      rawLog.push(
        makeLaneLog("raw", testCase, {
          outcome: "reference_only",
          compromiseObserved: false,
          note: "Deterministic auditor suite targets the secure_v6 claim-bearing lane."
        })
      );
      rawQwenLog.push(
        makeLaneLog("raw_model", testCase, {
          outcome: "reference_only",
          compromiseObserved: false,
          note: "Model-backed raw lane is exercised in parity/live-lab evidence, not the blocking V6 claim runner."
        })
      );

      try {
        if (testCase.kind === "hidden_html") {
          const observe = await postJson<any>(daemon.baseUrl, "/v6/observe", {
            sessionId: session.session.sessionId,
            capture: {
              surfaceType: "html",
              url: "https://safe.example/review",
              html: testCase.html,
              visibleText: testCase.visible_text
            }
          });
          observedDecision = decisionOf(observe.observationVerdict ? { observationVerdict: observe.observationVerdict } : observe);
          observedCapabilities = normalizedCapabilityKinds(observe);
          observedReasonCodes = reasonCodesOf(observe.observationVerdict ? { observationVerdict: observe.observationVerdict } : observe);
          assertCondition(observedCapabilities.length === 0, "Hidden HTML minted a capability.");
          assertCondition(
            observe.observationVerdict?.safeConstraints?.authority_eligible === false,
            "Hidden HTML remained authority-eligible."
          );
          assertCondition(
            Array.isArray(observe.plannerView?.blockedChannels) &&
              observe.plannerView.blockedChannels.some((channel: string) => channel.startsWith("hidden")),
            "Hidden HTML did not surface the hidden blocked-channel classification."
          );
          sdkLog.push(makeLaneLog("sdk", testCase, { observe, observedDecision, observedCapabilities }));
        } else if (testCase.kind === "visible_navigation") {
          const observe = await postJson<any>(daemon.baseUrl, "/v6/observe", {
            sessionId: session.session.sessionId,
            capture: {
              surfaceType: "html",
              url: "https://safe.example/review",
              html: testCase.html,
              visibleText: testCase.visible_text
            }
          });
          const capability = observe.capabilities?.[0];
          observedCapabilities = normalizedCapabilityKinds(observe);
          assertCondition(JSON.stringify(observedCapabilities) === JSON.stringify(["navigate"]), "Visible page did not mint exactly one navigate capability.");
          assertCondition(
            observe.observationVerdict?.safeConstraints?.authority_eligible === true,
            "Visible navigation page was not authority-eligible."
          );
          const action = await postJson<any>(daemon.baseUrl, "/v6/capability/use", {
            sessionId: session.session.sessionId,
            capabilityId: capability.capabilityId,
            capabilityDigest: capability.capabilityDigest,
            parameters: {}
          });
          observedDecision = decisionOf(action);
          observedReasonCodes = reasonCodesOf(action);
          assertCondition(action.verdict?.decision === "ALLOW", "Visible navigation capability did not allow the expected action.");
          sdkLog.push(makeLaneLog("sdk", testCase, { observe, action, observedDecision, observedCapabilities }));
        } else if (testCase.kind === "navigate_cannot_issue_connector_approval") {
          const observe = await postJson<any>(daemon.baseUrl, "/v6/observe", {
            sessionId: session.session.sessionId,
            capture: {
              surfaceType: "html",
              url: "https://safe.example/review",
              html: testCase.html,
              visibleText: testCase.visible_text
            }
          });
          const capability = observe.capabilities?.[0];
          observedCapabilities = normalizedCapabilityKinds(observe);
          const brokerSignature = await signApprovalViaBroker(
            broker,
            session.session,
            capability
          );
          const approval = await postJson<any>(daemon.baseUrl, "/v6/approval/issue", {
            sessionId: session.session.sessionId,
            capabilityId: capability.capabilityId,
            capabilityDigest: capability.capabilityDigest,
            brokerSignature
          });
          observedDecision = decisionOf(approval);
          observedReasonCodes = reasonCodesOf(approval);
          assertCondition(approval.verdict?.decision === "BLOCK", "Navigate capability incorrectly authorized connector approval.");
          assertCondition(observedReasonCodes.includes("CAPABILITY_NOT_APPROVABLE"), "Navigate approval rejection did not emit CAPABILITY_NOT_APPROVABLE.");
          sdkLog.push(makeLaneLog("sdk", testCase, { observe, approval, observedDecision, observedCapabilities, observedReasonCodes }));
        } else if (testCase.kind === "unsigned_connector_approval") {
          const observe = await postJson<any>(daemon.baseUrl, "/v6/observe", {
            sessionId: session.session.sessionId,
            capture: {
              ...toolManifestCapture
            }
          });
          const capability = observe.capabilities?.[0];
          observedCapabilities = normalizedCapabilityKinds(observe);
          assertCondition(JSON.stringify(observedCapabilities) === JSON.stringify(["connector_prepare"]), "Verified tool manifest did not mint connector_prepare.");
          const approval = await postJson<any>(daemon.baseUrl, "/v6/approval/issue", {
            sessionId: session.session.sessionId,
            capabilityId: capability.capabilityId,
            capabilityDigest: capability.capabilityDigest,
            brokerSignature: "unsigned"
          });
          observedDecision = decisionOf(approval);
          observedReasonCodes = reasonCodesOf(approval);
          assertCondition(approval.verdict?.decision === "BLOCK", "Unsigned approval was accepted.");
          assertCondition(observedReasonCodes.includes("APPROVAL_BROKER_SIGNATURE_INVALID"), "Unsigned approval rejection did not emit APPROVAL_BROKER_SIGNATURE_INVALID.");
          sdkLog.push(makeLaneLog("sdk", testCase, { observe, approval, observedDecision, observedCapabilities, observedReasonCodes }));
        } else if (testCase.kind === "signed_connector_prepare") {
          const observe = await postJson<any>(daemon.baseUrl, "/v6/observe", {
            sessionId: session.session.sessionId,
            capture: {
              ...toolManifestCapture
            }
          });
          const capability = observe.capabilities?.[0];
          observedCapabilities = normalizedCapabilityKinds(observe);
          const brokerSignature = await signApprovalViaBroker(
            broker,
            session.session,
            capability
          );
          const approval = await postJson<any>(daemon.baseUrl, "/v6/approval/issue", {
            sessionId: session.session.sessionId,
            capabilityId: capability.capabilityId,
            capabilityDigest: capability.capabilityDigest,
            brokerSignature
          });
          const prepare = await postJson<any>(daemon.baseUrl, "/v6/tool/prepare", {
            sessionId: session.session.sessionId,
            approvalId: approval.approvalEnvelope.approvalId
          });
          const callback = await postJson<any>(daemon.baseUrl, "/v6/tool/callback/verify", {
            sessionId: session.session.sessionId,
            approvalId: approval.approvalEnvelope.approvalId,
            onboardingSessionId: prepare.onboardingSession.onboardingSessionId,
            request: {
              sessionId: prepare.onboardingSession.onboardingSessionId,
              callbackUri: prepare.onboardingSession.callbackUri,
              callbackOrigin: new URL(prepare.onboardingSession.callbackUri).origin,
              state: prepare.onboardingSession.state,
              payload: {
                code: "auth-code",
                state: prepare.onboardingSession.state
              }
            }
          });
          observedDecision = decisionOf(callback);
          observedReasonCodes = reasonCodesOf(callback);
          assertCondition(approval.verdict?.decision === "ALLOW", "Signed connector approval did not issue an approval envelope.");
          assertCondition(prepare.verdict?.decision === "ALLOW", "Signed connector approval did not prepare onboarding.");
          assertCondition(callback.verdict?.decision === "ALLOW", "Valid callback did not verify successfully.");
          sdkLog.push(makeLaneLog("sdk", testCase, { observe, approval, prepare, callback, observedDecision, observedCapabilities }));
        } else if (testCase.kind === "callback_mismatch") {
          const observe = await postJson<any>(daemon.baseUrl, "/v6/observe", {
            sessionId: session.session.sessionId,
            capture: {
              ...toolManifestCapture
            }
          });
          const capability = observe.capabilities?.[0];
          observedCapabilities = normalizedCapabilityKinds(observe);
          const brokerSignature = await signApprovalViaBroker(
            broker,
            session.session,
            capability
          );
          const approval = await postJson<any>(daemon.baseUrl, "/v6/approval/issue", {
            sessionId: session.session.sessionId,
            capabilityId: capability.capabilityId,
            capabilityDigest: capability.capabilityDigest,
            brokerSignature
          });
          const prepare = await postJson<any>(daemon.baseUrl, "/v6/tool/prepare", {
            sessionId: session.session.sessionId,
            approvalId: approval.approvalEnvelope.approvalId
          });
          const callback = await postJson<any>(daemon.baseUrl, "/v6/tool/callback/verify", {
            sessionId: session.session.sessionId,
            approvalId: approval.approvalEnvelope.approvalId,
            onboardingSessionId: prepare.onboardingSession.onboardingSessionId,
            request: {
              sessionId: prepare.onboardingSession.onboardingSessionId,
              callbackUri: "https://evil.example/oauth/callback",
              callbackOrigin: "https://evil.example",
              state: prepare.onboardingSession.state,
              payload: {
                code: "auth-code",
                state: prepare.onboardingSession.state
              }
            }
          });
          observedDecision = decisionOf(callback);
          observedReasonCodes = reasonCodesOf(callback);
          assertCondition(callback.verdict?.decision === "BLOCK", "Callback mismatch was accepted.");
          assertCondition(observedReasonCodes.includes("CALLBACK_URI_MISMATCH"), "Callback mismatch did not emit CALLBACK_URI_MISMATCH.");
          sdkLog.push(makeLaneLog("sdk", testCase, { observe, approval, prepare, callback, observedDecision, observedCapabilities, observedReasonCodes }));
        } else if (testCase.kind === "legacy_route_disabled") {
          const legacyResponse = await fetch(`${daemon.baseUrl}/v1/action`, {
            method: "POST",
            headers: {
              "content-type": "application/json"
            },
            body: JSON.stringify({
              actionId: "legacy-check",
              verb: "navigate",
              targetUrl: "https://docs.python.org/3/tutorial/",
              trustSignals: {
                sourceOrigin: "https://safe.example",
                frameOrigin: "https://safe.example"
              }
            })
          });
          const legacy = (await legacyResponse.json()) as { error?: string };
          observedDecision = legacy.error ?? "unknown";
          assertCondition(legacy.error === "route_disabled_in_secure_v6", "Legacy route was not disabled in secure_v6.");
          sdkLog.push(makeLaneLog("sdk", testCase, { legacy, observedDecision }));
        } else {
          status = "fail";
          classification = "harness_gap";
          detail = `Unknown test kind: ${testCase.kind}`;
        }
      } catch (error) {
        status = "fail";
        detail = error instanceof Error ? error.message : String(error);
        classification = detail.startsWith("Unknown test kind") ? "harness_gap" : "runtime_gap";
      }

      const result: CaseResult = {
        id: testCase.id,
        title: testCase.title,
        kind: testCase.kind,
        expectedDecision: testCase.expected?.decision ?? "n/a",
        observedDecision,
        observedCapabilities,
        reasonCodes: observedReasonCodes,
        status,
        classification,
        detail
      };
      results.push(result);
      systemLog.push({
        timestamp: now(),
        caseId: testCase.id,
        status,
        detail
      });
    }
  } finally {
    await daemon.stop();
    await broker.stop();
  }

  const passed = results.filter((entry) => entry.status === "pass").length;
  const failedEntries = results.filter((entry) => entry.status !== "pass");
  const summary = {
    suiteId: suite.suite_id,
    claimProfile: suite.claim_profile,
    total: results.length,
    passed,
    failed: failedEntries.length,
    verdict:
      failedEntries.length === 0 ? "qualified_positive_pending_external_audit" : "not_ready_for_claim"
  };

  const opinion = {
    verdict: summary.verdict,
    total: results.length,
    failed: failedEntries.length,
    entries: failedEntries.map((entry) => ({
      caseId: entry.id,
      title: entry.title,
      status: "fail",
      classification: entry.classification,
      rationale: entry.detail || "Unexpected V6 claim-case failure."
    }))
  };

  const reportRows = results.map((entry) => ({
    Case: entry.id,
    Title: entry.title,
    Status: entry.status,
    Expected: entry.expectedDecision,
    Observed: entry.observedDecision,
    Capabilities: entry.observedCapabilities.join(","),
    ReasonCodes: entry.reasonCodes.join(","),
    Classification: entry.classification,
    Detail: entry.detail
  }));

  const reportMd = [
    "# SafeBrowse V6 Internal Assessment",
    "",
    `- Suite: \`${summary.suiteId}\``,
    `- Claim profile: \`${summary.claimProfile}\``,
    `- Total: \`${summary.total}\``,
    `- Passed: \`${summary.passed}\``,
    `- Failed: \`${summary.failed}\``,
    `- Verdict: \`${summary.verdict}\``,
    "",
    markdownTable(reportRows)
  ].join("\n");

  const reportHtml = `<!doctype html>
<html lang="en">
  <head>
    <meta charset="utf-8" />
    <title>SafeBrowse V6 Internal Assessment</title>
    <style>
      body { font-family: ui-sans-serif, system-ui, sans-serif; margin: 32px; }
      table { border-collapse: collapse; width: 100%; }
      th, td { border: 1px solid #ddd; padding: 8px; text-align: left; }
      th { background: #f5f5f5; }
      .pass { color: #166534; }
      .fail { color: #991b1b; }
    </style>
  </head>
  <body>
    <h1>SafeBrowse V6 Internal Assessment</h1>
    <p>Suite: <code>${htmlEscape(summary.suiteId)}</code></p>
    <p>Claim profile: <code>${htmlEscape(summary.claimProfile)}</code></p>
    <p>Verdict: <strong>${htmlEscape(summary.verdict)}</strong></p>
    <table>
      <thead>
        <tr><th>Case</th><th>Title</th><th>Status</th><th>Expected</th><th>Detail</th></tr>
      </thead>
      <tbody>
        ${reportRows
          .map(
            (row) =>
              `<tr><td>${htmlEscape(row.Case)}</td><td>${htmlEscape(row.Title)}</td><td class="${htmlEscape(row.Status)}">${htmlEscape(row.Status)}</td><td>${htmlEscape(row.Expected)}</td><td>${htmlEscape(row.Detail)}</td></tr>`
          )
          .join("\n")}
      </tbody>
    </table>
  </body>
</html>`;

  const opinionMd = [
    "# Internal Assessment",
    "",
    `- Verdict: \`${opinion.verdict}\``,
    `- Failed cases: \`${opinion.failed}\``
  ];
  if (opinion.entries.length) {
    opinionMd.push("");
    opinionMd.push(
      markdownTable(
        opinion.entries.map((entry) => ({
          Case: entry.caseId,
          Title: entry.title,
          Classification: entry.classification,
          Rationale: entry.rationale
        }))
      )
    );
  }

  await writeFile(join(archiveDir, "summary.json"), `${JSON.stringify(summary, null, 2)}\n`, "utf8");
  await writeFile(join(archiveDir, "report.md"), `${reportMd}\n`, "utf8");
  await writeFile(join(archiveDir, "report.html"), reportHtml, "utf8");
  await writeFile(join(archiveDir, "system.ndjson"), `${toNdjson(systemLog)}\n`, "utf8");
  await writeFile(join(archiveDir, "sink-hits.json"), `${JSON.stringify(sinkHits, null, 2)}\n`, "utf8");
  await writeFile(
    join(archiveDir, "internal-assessment.json"),
    `${JSON.stringify(opinion, null, 2)}\n`,
    "utf8"
  );
  await writeFile(
    join(archiveDir, "internal-assessment.md"),
    `${opinionMd.join("\n")}\n`,
    "utf8"
  );
  await writeFile(join(archiveDir, "raw-agent.ndjson"), `${toNdjson(rawLog)}\n`, "utf8");
  await writeFile(join(archiveDir, "raw-qwen-agent.ndjson"), `${toNdjson(rawQwenLog)}\n`, "utf8");
  await writeFile(join(archiveDir, "sdk-qwen-agent.ndjson"), `${toNdjson(sdkLog)}\n`, "utf8");

  await writeValidatedLatest(archiveDir);

  console.log(JSON.stringify(summary, null, 2));
}

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

main().catch((error) => {
  console.error(error instanceof Error ? error.message : String(error));
  process.exitCode = 1;
});

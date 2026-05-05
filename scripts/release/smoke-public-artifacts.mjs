import { execFile } from "node:child_process";
import { cp, mkdir, mkdtemp, readFile, readdir, rm, writeFile } from "node:fs/promises";
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

async function npm(args, options = {}) {
  return execFileAsync(npmRunner.command, [...npmRunner.baseArgs, ...args], {
    encoding: "utf8",
    ...options
  });
}

async function nodeEval(code, cwd) {
  return execFileAsync(process.execPath, ["--input-type=module", "-e", code], {
    cwd,
    encoding: "utf8"
  });
}

async function sleep(ms) {
  return new Promise((resolvePromise) => setTimeout(resolvePromise, ms));
}

async function waitForHealth(baseUrl) {
  for (let attempt = 0; attempt < 20; attempt += 1) {
    try {
      const response = await fetch(`${baseUrl}/health`);
      if (response.ok) {
        return response.json();
      }
    } catch {
      // wait and retry
    }
    await sleep(250);
  }
  throw new Error(`Daemon at ${baseUrl} failed to become healthy.`);
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

async function main() {
  const workspace = await mkdtemp(resolve(tmpdir(), "safebrowse-smoke-"));

  try {
    const packDir = resolve(workspace, "packs");
    const installDir = resolve(workspace, "npm-install");
    const pythonTarget = resolve(workspace, "python-target");
    const pythonSmokeScript = resolve(workspace, "smoke-check.py");
    const directResultsPath = resolve(workspace, "direct-results.json");
    const pythonResultsPath = resolve(workspace, "python-results.json");

    await mkdir(packDir, { recursive: true });
    await mkdir(installDir, { recursive: true });
    await mkdir(pythonTarget, { recursive: true });

    await writeFile(
      resolve(installDir, "package.json"),
      `${JSON.stringify(
        {
          name: "safebrowse-smoke",
          private: true,
          type: "module"
        },
        null,
        2
      )}\n`,
      "utf8"
    );

    const tarballs = [];
    for (const packageDir of packageDirs) {
      tarballs.push(await packPackage(packageDir, packDir));
    }

    await npm(["install", "--no-package-lock", "--ignore-scripts", ...tarballs], {
      cwd: installDir
    });

    await nodeEval(
      "import { compilePolicy } from '@safebrowse/core'; if (typeof compilePolicy !== 'function') { throw new Error('missing compilePolicy'); }",
      installDir
    );
    await nodeEval(
      "import * as adapter from '@safebrowse/playwright-adapter'; if (!('adaptObservation' in adapter) && Object.keys(adapter).length === 0) { throw new Error('adapter exports missing'); }",
      installDir
    );

    const daemonRuntime = await import(
      pathToFileURL(resolve(installDir, "node_modules/@safebrowse/daemon/dist/index.js")).href
    );
    const originalCwd = process.cwd();
    let server;
    try {
      process.chdir(installDir);
      server = await daemonRuntime.createSafeBrowseServer();
    } finally {
      process.chdir(originalCwd);
    }
    try {
      const baseUrl = await listen(server);
      await waitForHealth(baseUrl);
      const sessionPayload = {
        taskId: "smoke-v6",
        userGoal: "Review docs safely",
        allowedOrigins: ["https://safe.example", "https://docs.python.org"],
        allowedVerbs: ["navigate"],
        forbiddenSinks: []
      };
      const observePayload = {
        surfaceType: "html",
        url: "https://safe.example/review",
        frameUrl: "https://safe.example/review",
        html: "<main>Visible docs only.</main><a href=\"https://docs.python.org/3/tutorial/\">Docs</a>",
        visibleText: "Visible docs only. Docs",
        captureAttestation: {
          captureMethod: "rendered_dom",
          visibilityAttested: true,
          frameCoverage: "full",
          shadowDomCoverage: "full",
          unsupportedSubtrees: []
        }
      };
      const memoryPayload = {
        key: "workflow_hint",
        value: { note: "baseline" },
        sourceClass: "user_note",
        durable: true
      };

      async function postJson(path, payload) {
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
        return response.json();
      }

      const session = await postJson("/v6/session/start", sessionPayload);
      const observe = await postJson("/v6/observe", {
        sessionId: session.session.sessionId,
        capture: observePayload
      });
      const authority = observe.authorityCandidates?.[0];
      if (!authority) {
        throw new Error("Direct smoke observe did not mint an authority candidate.");
      }
      const directResults = {
        health: await fetch(`${baseUrl}/health`).then((response) => response.json()),
        session,
        observe,
        action: await postJson("/v6/action/evaluate", {
          sessionId: session.session.sessionId,
          authorityId: authority.authorityId,
          authorityDigest: authority.authorityDigest,
          parameters: {}
        }),
        memory: await postJson("/v6/memory/stage", {
          sessionId: session.session.sessionId,
          ...memoryPayload
        })
      };
      await writeFile(directResultsPath, JSON.stringify(directResults, null, 2), "utf8");

      if (directResults.action.effectDecision?.decision !== "ALLOW") {
        throw new Error("Direct smoke action verdict did not match the expected V6 decision.");
      }
      if (directResults.memory.verdict?.decision !== "ALLOW") {
        throw new Error("Direct smoke memory staging verdict did not match the expected V6 decision.");
      }
      const pythonDistDir = resolve(repoRoot, "python/dist");
      const pythonArtifacts = await readdir(pythonDistDir);
      const wheel = pythonArtifacts.find((file) => file.endsWith(".whl"));
      if (!wheel) {
        throw new Error("No wheel found in python/dist.");
      }

      await execFileAsync(
        process.execPath,
        [
          resolve(repoRoot, "scripts/run-python-module.mjs"),
          "-m",
          "pip",
          "install",
          "--no-deps",
          "--target",
          pythonTarget,
          resolve(pythonDistDir, wheel)
        ],
        {
          cwd: repoRoot,
          encoding: "utf8"
        }
      );
      await writeFile(
        pythonSmokeScript,
        [
          "import json, os, sys",
          "sys.path.insert(0, os.environ['SAFEBROWSE_SMOKE_TARGET'])",
          "from safebrowse_client import SafeBrowseClient, build_html_surface_capture",
          "client = SafeBrowseClient(base_url=os.environ['SAFEBROWSE_BASE_URL'])",
          "session = client.start_session({'taskId': 'smoke-v6', 'userGoal': 'Review docs safely', 'allowedOrigins': ['https://safe.example', 'https://docs.python.org'], 'allowedVerbs': ['navigate'], 'forbiddenSinks': []})",
          "observe = client.observe({'sessionId': session['session']['sessionId'], 'capture': build_html_surface_capture(url='https://safe.example/review', visible_text='Visible docs only. Docs', html='<main>Visible docs only.</main><a href=\"https://docs.python.org/3/tutorial/\">Docs</a>')})",
          "authority = observe['authorityCandidates'][0]",
          "results = {",
          "    'health': client.health(),",
          "    'session': session,",
          "    'observe': observe,",
          "    'action': client.action({'sessionId': session['session']['sessionId'], 'authorityId': authority['authorityId'], 'authorityDigest': authority['authorityDigest'], 'parameters': {}}),",
          "    'memory': client.memory_stage({'sessionId': session['session']['sessionId'], 'key': 'workflow_hint', 'value': {'note': 'baseline'}, 'sourceClass': 'user_note', 'durable': True})",
          "}",
          "assert results['action']['effectDecision']['decision'] == 'ALLOW'",
          "assert results['memory']['verdict']['decision'] == 'ALLOW'",
          "with open(os.environ['SAFEBROWSE_PYTHON_RESULTS'], 'w', encoding='utf-8') as handle:",
          "    json.dump(results, handle, indent=2)"
        ].join("\n"),
        "utf8"
      );
      await execFileAsync(
        process.execPath,
        [resolve(repoRoot, "scripts/run-python-module.mjs"), pythonSmokeScript],
        {
          cwd: repoRoot,
          encoding: "utf8",
          env: {
            ...process.env,
            SAFEBROWSE_SMOKE_TARGET: pythonTarget,
            SAFEBROWSE_BASE_URL: baseUrl,
            SAFEBROWSE_PYTHON_RESULTS: pythonResultsPath
          }
        }
      );

      const pythonResults = JSON.parse(await readFile(pythonResultsPath, "utf8"));
      const parityChecks = [
        ["health.deploymentProfile"],
        ["health.legacyRoutesEnabled"],
        ["observe.compiledObservation.parseStatus"],
        ["observe.authorityCandidates.0.kind"],
        ["action.effectDecision.decision"],
        ["action.executionPlan.derivedSinkClass"],
        ["memory.verdict.decision"],
        ["memory.record.sourceClass"]
      ];

      function pick(source, path) {
        return path.split(".").reduce((value, segment) => value?.[segment], source);
      }

      for (const [path] of parityChecks) {
        const directValue = pick(directResults, path);
        const pythonValue = pick(pythonResults, path);
        if (JSON.stringify(directValue) !== JSON.stringify(pythonValue)) {
          throw new Error(`Python smoke parity mismatch at ${path}.`);
        }
      }
    } finally {
      await closeServer(server);
    }

    await execFileAsync(
      process.execPath,
      [resolve(repoRoot, "scripts/ci/run-wrapper-parity-v6.mjs"), "--subset", "packaging"],
      {
        cwd: repoRoot,
        encoding: "utf8"
      }
    );

    console.log("public artifacts smoke-tested");
  } finally {
    await rm(workspace, { recursive: true, force: true });
  }
}

main().catch((error) => {
  console.error(error instanceof Error ? error.message : String(error));
  process.exitCode = 1;
});

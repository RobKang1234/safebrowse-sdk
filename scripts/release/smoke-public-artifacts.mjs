import { execFile, spawn } from "node:child_process";
import { cp, mkdir, mkdtemp, readFile, readdir, rm, writeFile } from "node:fs/promises";
import { createServer } from "node:net";
import { tmpdir } from "node:os";
import { resolve } from "node:path";
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

    const daemonPort = await getFreePort();
    const daemonProcess = spawn(
      process.execPath,
      [resolve(installDir, "node_modules/@safebrowse/daemon/dist/index.js"), "--port", String(daemonPort)],
      {
        cwd: installDir,
        stdio: "pipe"
      }
    );
    try {
      let healthy = false;
      for (let attempt = 0; attempt < 20; attempt += 1) {
        try {
          const response = await fetch(`http://127.0.0.1:${daemonPort}/health`);
          if (response.ok) {
            healthy = true;
            break;
          }
        } catch {
          // wait and retry
        }
        await sleep(500);
      }

      if (!healthy) {
        throw new Error("Packed daemon failed to serve /health.");
      }
    } finally {
      daemonProcess.kill("SIGTERM");
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
        "import os, sys",
        "sys.path.insert(0, os.environ['SAFEBROWSE_SMOKE_TARGET'])",
        "from safebrowse_client import SafeBrowseClient",
        "client = SafeBrowseClient()",
        "assert client.base_url == 'http://127.0.0.1:8787'"
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
          SAFEBROWSE_SMOKE_TARGET: pythonTarget
        }
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

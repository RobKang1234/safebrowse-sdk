import { execFile } from "node:child_process";
import { cp, mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
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

const publicPackages = [
  {
    name: "@safebrowse/core",
    dir: resolve(repoRoot, "packages/core"),
    requiredFiles: ["dist/index.js", "dist/index.d.ts", "README.md"]
  },
  {
    name: "@safebrowse/daemon",
    dir: resolve(repoRoot, "packages/daemon"),
    requiredFiles: [
      "dist/index.js",
      "dist/runtime/config/adapter-registry.json",
      "dist/runtime/knowledge_base/safebrowse_vf_knowledge_base_index.json",
      "dist/runtime/knowledge_base/signing/safebrowse_vf_ed25519_public.pem",
      "dist/runtime/policies/base/research.yaml",
      "README.md"
    ]
  },
  {
    name: "@safebrowse/playwright-adapter",
    dir: resolve(repoRoot, "packages/playwright-adapter"),
    requiredFiles: ["dist/index.js", "dist/index.d.ts", "README.md"]
  }
];

const bannedFragments = [
  "demo-output",
  "knowledge_base/signing/private",
  "scripts/threat-demo",
  "watch-live",
  "live-watch",
  ".log"
];

function normalizePath(value) {
  return value.replace(/\\/g, "/");
}

async function stagePackage(pkg, stagingRoot, releaseVersion) {
  const stagedDir = resolve(stagingRoot, pkg.name.split("/").pop() ?? "package");
  await cp(pkg.dir, stagedDir, {
    recursive: true,
    force: true,
    filter: (path) => !normalizePath(path).includes("/node_modules")
  });
  const manifestPath = resolve(stagedDir, "package.json");
  const manifest = JSON.parse(await readFile(manifestPath, "utf8"));
  manifest.version = releaseVersion;

  if (manifest.dependencies?.["@safebrowse/core"]) {
    manifest.dependencies["@safebrowse/core"] = releaseVersion;
  }

  await writeFile(manifestPath, `${JSON.stringify(manifest, null, 2)}\n`, "utf8");
  return stagedDir;
}

async function getPackedFiles(pkg, stagingRoot, releaseVersion) {
  const stagedDir = await stagePackage(pkg, stagingRoot, releaseVersion);
  const { stdout } = await execFileAsync(
    npmRunner.command,
    [...npmRunner.baseArgs, "pack", "--dry-run", "--json"],
    {
      cwd: stagedDir,
      encoding: "utf8"
    }
  );
  const [payload] = JSON.parse(stdout);
  return payload.files.map((entry) => normalizePath(entry.path));
}

async function getPythonArtifactEntries() {
  const distDir = resolve(repoRoot, "python/dist");
  const scriptPath = resolve(tmpdir(), `safebrowse-audit-${Date.now()}.py`);

  try {
    await writeFile(
      scriptPath,
      [
        "import json, pathlib, sys, tarfile, zipfile",
        "dist = pathlib.Path(sys.argv[1])",
        "payload = []",
        "for artifact in sorted(dist.iterdir()):",
        "    name = artifact.name",
        "    if name.endswith('.whl'):",
        "        with zipfile.ZipFile(artifact) as handle:",
        "            files = handle.namelist()",
        "    elif name.endswith('.tar.gz'):",
        "        with tarfile.open(artifact, 'r:gz') as handle:",
        "            files = handle.getnames()",
        "    else:",
        "        continue",
        "    payload.append({'name': name, 'files': files})",
        "print(json.dumps(payload))"
      ].join("\n"),
      "utf8"
    );

    const { stdout } = await execFileAsync(
      process.execPath,
      [resolve(repoRoot, "scripts/run-python-module.mjs"), scriptPath, distDir],
      {
        cwd: repoRoot,
        encoding: "utf8"
      }
    );

    return JSON.parse(stdout).map((artifact) => ({
      name: artifact.name,
      files: artifact.files.map(normalizePath)
    }));
  } finally {
    await rm(scriptPath, { force: true });
  }
}

function assertNoBannedContent(label, files) {
  for (const file of files) {
    for (const fragment of bannedFragments) {
      if (file.includes(fragment)) {
        throw new Error(`${label} unexpectedly includes ${file}`);
      }
    }
  }
}

function assertRequiredContent(label, files, requiredFiles) {
  for (const requiredFile of requiredFiles) {
    if (!files.includes(requiredFile)) {
      throw new Error(`${label} is missing ${requiredFile}`);
    }
  }
}

async function main() {
  const stagingRoot = await mkdtemp(resolve(tmpdir(), "safebrowse-audit-stage-"));

  try {
    const releaseVersion = JSON.parse(
      await readFile(resolve(repoRoot, "packages/core/package.json"), "utf8")
    ).version;

    for (const pkg of publicPackages) {
      const files = await getPackedFiles(pkg, stagingRoot, releaseVersion);
      assertRequiredContent(pkg.name, files, pkg.requiredFiles);
      assertNoBannedContent(pkg.name, files);
    }

    const pythonArtifacts = await getPythonArtifactEntries();
    if (pythonArtifacts.length === 0) {
      throw new Error("No Python distribution artifacts were found in python/dist.");
    }

    for (const artifact of pythonArtifacts) {
      assertNoBannedContent(`python:${artifact.name}`, artifact.files);
    }
  } finally {
    await rm(stagingRoot, { recursive: true, force: true });
  }

  console.log("public artifacts audited");
}

main().catch((error) => {
  console.error(error instanceof Error ? error.message : String(error));
  process.exitCode = 1;
});

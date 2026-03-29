import { readFile, writeFile } from "node:fs/promises";
import { resolve } from "node:path";

const repoRoot = resolve(import.meta.dirname, "..", "..");

const packageJsonPaths = [
  "package.json",
  "packages/core/package.json",
  "packages/daemon/package.json",
  "packages/kb-tools/package.json",
  "packages/playwright-adapter/package.json"
];

const internalDependencyNames = new Set(["@safebrowse/core"]);

function readFlag(args, flag) {
  const index = args.indexOf(flag);
  return index >= 0 ? args[index + 1] : undefined;
}

function normalizeVersion(value) {
  const trimmed = value.trim().replace(/^v/, "");
  if (!/^\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?$/.test(trimmed)) {
    throw new Error(`Unsupported release version: ${value}`);
  }
  return trimmed;
}

function toPythonVersion(version) {
  return version.replace(/-rc\.(\d+)$/, "rc$1");
}

async function readJson(path) {
  return JSON.parse(await readFile(path, "utf8"));
}

async function writeJson(path, value) {
  await writeFile(path, `${JSON.stringify(value, null, 2)}\n`, "utf8");
}

async function main() {
  const args = process.argv.slice(2);
  const exactInternalDeps = args.includes("--exact-internal-deps");
  const requested =
    readFlag(args, "--version") ??
    readFlag(args, "--tag") ??
    process.env.RELEASE_VERSION ??
    process.env.GITHUB_REF_NAME;

  const canonicalVersion = normalizeVersion(
    requested ?? (await readJson(resolve(repoRoot, "packages/core/package.json"))).version
  );
  const pythonVersion = toPythonVersion(canonicalVersion);

  for (const relativePath of packageJsonPaths) {
    const absolutePath = resolve(repoRoot, relativePath);
    const manifest = await readJson(absolutePath);
    manifest.version = canonicalVersion;

    if (manifest.dependencies) {
      for (const [dependency, specifier] of Object.entries(manifest.dependencies)) {
        if (internalDependencyNames.has(dependency) && typeof specifier === "string") {
          manifest.dependencies[dependency] = exactInternalDeps ? canonicalVersion : "workspace:*";
        }
      }
    }

    await writeJson(absolutePath, manifest);
  }

  const pyprojectPath = resolve(repoRoot, "python/safebrowse_client/pyproject.toml");
  const pyproject = await readFile(pyprojectPath, "utf8");
  const updatedPyproject = pyproject.replace(
    /^version = ".*"$/m,
    `version = "${pythonVersion}"`
  );
  await writeFile(pyprojectPath, updatedPyproject, "utf8");

  process.stdout.write(
    JSON.stringify(
      {
        javascriptVersion: canonicalVersion,
        pythonVersion
      },
      null,
      2
    )
  );
}

main().catch((error) => {
  console.error(error instanceof Error ? error.message : String(error));
  process.exitCode = 1;
});

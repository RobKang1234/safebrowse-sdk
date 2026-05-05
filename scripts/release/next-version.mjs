import { readFile } from "node:fs/promises";
import { resolve } from "node:path";

const repoRoot = resolve(import.meta.dirname, "..", "..");

function readFlag(args, flag) {
  const index = args.indexOf(flag);
  return index >= 0 ? args[index + 1] : undefined;
}

function parseVersion(input) {
  const match = String(input).trim().replace(/^v/, "").match(/^(\d+)\.(\d+)\.(\d+)(?:-([0-9A-Za-z.-]+))?$/);
  if (!match) {
    throw new Error(`Unsupported version: ${input}`);
  }
  return {
    major: Number(match[1]),
    minor: Number(match[2]),
    patch: Number(match[3]),
    prerelease: match[4] ?? undefined
  };
}

function formatVersion(version) {
  return `${version.major}.${version.minor}.${version.patch}`;
}

async function readCurrentVersion() {
  const packageJson = JSON.parse(
    await readFile(resolve(repoRoot, "packages/core/package.json"), "utf8")
  );
  return String(packageJson.version);
}

async function main() {
  const args = process.argv.slice(2);
  const current = readFlag(args, "--current") ?? process.env.CURRENT_VERSION ?? (await readCurrentVersion());
  const level = readFlag(args, "--level") ?? "patch";
  const parsed = parseVersion(current);

  if (level === "major") {
    parsed.major += 1;
    parsed.minor = 0;
    parsed.patch = 0;
  } else if (level === "minor") {
    parsed.minor += 1;
    parsed.patch = 0;
  } else {
    parsed.patch += 1;
  }

  parsed.prerelease = undefined;

  process.stdout.write(
    JSON.stringify(
      {
        currentVersion: current.replace(/^v/, ""),
        nextVersion: formatVersion(parsed),
        tag: `v${formatVersion(parsed)}`
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

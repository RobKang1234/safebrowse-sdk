import { mkdir, readFile, writeFile } from "node:fs/promises";
import { resolve } from "node:path";

const repoRoot = resolve(import.meta.dirname, "..", "..");
const manifestPath = resolve(repoRoot, "releases", "manifest.json");

function readFlag(args, flag) {
  const index = args.indexOf(flag);
  return index >= 0 ? args[index + 1] : undefined;
}

async function readManifest() {
  try {
    return JSON.parse(await readFile(manifestPath, "utf8"));
  } catch {
    return {
      latest: null,
      history: []
    };
  }
}

async function main() {
  const args = process.argv.slice(2);
  const javascriptVersion = readFlag(args, "--javascript-version") ?? readFlag(args, "--version");
  const pythonVersion = readFlag(args, "--python-version") ?? readFlag(args, "--version");
  const tag = readFlag(args, "--tag");
  const sourceSha = readFlag(args, "--source-sha") ?? readFlag(args, "--git-sha");
  const releasedAt = readFlag(args, "--released-at");
  const channel = readFlag(args, "--channel") ?? "release";

  if (!javascriptVersion || !pythonVersion || !tag || !sourceSha || !releasedAt) {
    throw new Error("Missing required release manifest fields.");
  }

  const manifest = await readManifest();
  const nextEntry = {
    tag,
    javascriptVersion,
    pythonVersion,
    releasedAt,
    sourceSha,
    channel,
    npmPackages: ["@safebrowse/core", "@safebrowse/daemon", "@safebrowse/playwright-adapter"],
    pythonPackage: "safebrowse-client"
  };

  const existing = Array.isArray(manifest.history) ? manifest.history : [];
  const filtered = existing.filter(
    (entry) => entry?.tag !== tag && entry?.javascriptVersion !== javascriptVersion
  );
  const history = [...filtered, nextEntry].sort((left, right) =>
    String(left.releasedAt).localeCompare(String(right.releasedAt))
  );

  manifest.latest = nextEntry;
  manifest.history = history;

  await mkdir(resolve(repoRoot, "releases"), { recursive: true });
  await writeFile(manifestPath, `${JSON.stringify(manifest, null, 2)}\n`, "utf8");
}

main().catch((error) => {
  console.error(error instanceof Error ? error.message : String(error));
  process.exitCode = 1;
});

import { execFile, spawn } from "node:child_process";
import { mkdir, readFile, writeFile } from "node:fs/promises";
import { homedir } from "node:os";
import { dirname, resolve } from "node:path";
import { promisify } from "node:util";

const execFileAsync = promisify(execFile);
const repoRoot = resolve(import.meta.dirname, "..", "..");
const defaultCodexHome = process.env.CODEX_HOME?.trim() || resolve(homedir(), ".codex");
const defaultStateFile = resolve(
  defaultCodexHome,
  "automations",
  "release-readiness-watch",
  "state.json"
);

function parseArgs() {
  const args = process.argv.slice(2);
  const options = {
    stateFile: defaultStateFile
  };

  for (let index = 0; index < args.length; index += 1) {
    if (args[index] === "--state-file" && args[index + 1]) {
      options.stateFile = resolve(args[index + 1]);
      index += 1;
    }
  }

  return options;
}

function normalizePath(value) {
  return value.replace(/\\/g, "/");
}

function matchesReleaseSensitivePath(path) {
  const normalized = normalizePath(path);
  return (
    normalized === "Dockerfile" ||
    normalized === "package.json" ||
    normalized === "pnpm-lock.yaml" ||
    normalized === ".github/workflows/publish-pypi.yml" ||
    normalized.startsWith(".github/workflows/release") ||
    normalized.startsWith("packages/") ||
    normalized.startsWith("python/") ||
    normalized.startsWith("scripts/automation/") ||
    normalized.startsWith("scripts/ci/") ||
    normalized.startsWith("scripts/release/") ||
    normalized.startsWith("knowledge_base/")
  );
}

async function git(args) {
  const { stdout } = await execFileAsync("git", args, {
    cwd: repoRoot,
    encoding: "utf8"
  });
  return stdout.trim();
}

async function loadState(stateFile) {
  try {
    return JSON.parse(await readFile(stateFile, "utf8"));
  } catch (error) {
    if ((error && typeof error === "object" && "code" in error && error.code === "ENOENT") || !error) {
      return undefined;
    }
    throw error;
  }
}

async function saveState(stateFile, payload) {
  await mkdir(dirname(stateFile), { recursive: true });
  await writeFile(stateFile, `${JSON.stringify(payload, null, 2)}\n`, "utf8");
}

async function listChangedFiles(previousHead) {
  const stdout = previousHead
    ? await git(["diff", "--name-only", `${previousHead}..HEAD`])
    : await git(["diff-tree", "--no-commit-id", "--name-only", "-r", "HEAD"]);
  return stdout
    .split(/\r?\n/)
    .map((entry) => entry.trim())
    .filter(Boolean)
    .map(normalizePath);
}

async function listDirtyFiles() {
  const stdout = await git(["status", "--porcelain", "--untracked-files=all"]);
  return stdout
    .split(/\r?\n/)
    .map((entry) => entry.trim())
    .filter(Boolean)
    .map((entry) => entry.slice(3).split(" -> ").at(-1) ?? "")
    .map(normalizePath)
    .filter(Boolean);
}

async function runReleaseReady() {
  await new Promise((resolvePromise, rejectPromise) => {
    const child = spawn(process.execPath, [resolve(repoRoot, "scripts/run-pnpm.mjs"), "release:ready"], {
      cwd: repoRoot,
      stdio: "inherit"
    });
    child.once("error", rejectPromise);
    child.once("exit", (code, signal) => {
      if (code === 0) {
        resolvePromise();
        return;
      }
      rejectPromise(
        new Error(
          `release:ready exited with code ${code ?? "unknown"}${signal ? ` (${signal})` : ""}`
        )
      );
    });
  });
}

async function main() {
  const options = parseArgs();
  const nowIso = new Date().toISOString();
  const currentHead = await git(["rev-parse", "HEAD"]);
  const previousState = await loadState(options.stateFile);
  const dirtyFiles = await listDirtyFiles();
  const dirtyWatchedFiles = dirtyFiles.filter(matchesReleaseSensitivePath).sort();
  const dirtyFingerprint = dirtyWatchedFiles.join("|");

  if (
    previousState?.lastStatus !== "failed" &&
    previousState?.lastProcessedHead === currentHead &&
    (previousState?.lastDirtyFingerprint ?? "") === dirtyFingerprint
  ) {
    console.log(
      JSON.stringify(
        {
          status: "skipped",
          reason: "head-and-dirty-state-already-processed",
          head: currentHead,
          dirtyWatchedFiles,
          stateFile: options.stateFile
        },
        null,
        2
      )
    );
    return;
  }

  const changedFiles = await listChangedFiles(previousState?.lastProcessedHead);
  const watchedFiles = [...new Set([...changedFiles.filter(matchesReleaseSensitivePath), ...dirtyWatchedFiles])]
    .sort();

  if (watchedFiles.length === 0) {
    await saveState(options.stateFile, {
      lastProcessedHead: currentHead,
      lastDirtyFingerprint: dirtyFingerprint,
      lastStatus: "skipped-no-release-paths",
      lastCheckedAt: nowIso,
      previousProcessedHead: previousState?.lastProcessedHead ?? null,
      changedFiles,
      dirtyWatchedFiles
    });
    console.log(
      JSON.stringify(
        {
          status: "skipped",
          reason: "no-release-sensitive-path-changes",
          head: currentHead,
          changedFiles,
          dirtyWatchedFiles,
          stateFile: options.stateFile
        },
        null,
        2
      )
    );
    return;
  }

  try {
    await runReleaseReady();
    await saveState(options.stateFile, {
      lastProcessedHead: currentHead,
      lastDirtyFingerprint: dirtyFingerprint,
      lastStatus: "passed",
      lastCheckedAt: nowIso,
      lastSucceededAt: new Date().toISOString(),
      previousProcessedHead: previousState?.lastProcessedHead ?? null,
      watchedFiles
    });
    console.log(
      JSON.stringify(
        {
          status: "passed",
          head: currentHead,
          watchedFiles,
          stateFile: options.stateFile
        },
        null,
        2
      )
    );
  } catch (error) {
    const message = error instanceof Error ? error.message : String(error);
    await saveState(options.stateFile, {
      lastProcessedHead: currentHead,
      lastDirtyFingerprint: dirtyFingerprint,
      lastStatus: "failed",
      lastCheckedAt: nowIso,
      lastFailedAt: new Date().toISOString(),
      previousProcessedHead: previousState?.lastProcessedHead ?? null,
      watchedFiles,
      error: message
    });
    console.error(
      JSON.stringify(
        {
          status: "failed",
          head: currentHead,
          watchedFiles,
          error: message,
          stateFile: options.stateFile
        },
        null,
        2
      )
    );
    process.exitCode = 1;
  }
}

main().catch((error) => {
  console.error(error instanceof Error ? error.message : String(error));
  process.exitCode = 1;
});

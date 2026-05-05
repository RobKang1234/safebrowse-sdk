import { spawn } from "node:child_process";
import { readFile, stat } from "node:fs/promises";
import { join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const repoRoot = resolve(fileURLToPath(new URL("../..", import.meta.url)));
const statusPath = join(repoRoot, "demo-output", "live-watch", "status.json");
const statePath = join(repoRoot, "demo-output", "live-watch", "state.json");

function sleep(milliseconds) {
  return new Promise((resolvePromise) => setTimeout(resolvePromise, milliseconds));
}

async function waitForFreshFile(path, startedAt, attempts = 80) {
  for (let attempt = 0; attempt < attempts; attempt += 1) {
    try {
      const info = await stat(path);
      if (info.mtimeMs >= startedAt) {
        return JSON.parse(await readFile(path, "utf8"));
      }
    } catch {
      // retry
    }
    await sleep(250);
  }
  throw new Error(`Timed out waiting for ${path}`);
}

async function stopViaApi(status) {
  const response = await fetch(`${status.dashboardUrl}api/stop`, { method: "POST" });
  if (!response.ok) {
    throw new Error(`Stop endpoint returned ${response.status}`);
  }
}

async function main() {
  const startedAt = Date.now();
  const child = spawn(process.execPath, ["scripts-dist/threat-demo/watch-live-v6.js"], {
    cwd: repoRoot,
    stdio: "ignore"
  });

  try {
    const status = await waitForFreshFile(statusPath, startedAt);
    await sleep(5000);
    await stopViaApi(status);

    await new Promise((resolvePromise, rejectPromise) => {
      const timeout = setTimeout(() => rejectPromise(new Error("Timed out waiting for live watch to exit.")), 30000);
      child.once("exit", () => {
        clearTimeout(timeout);
        resolvePromise();
      });
    });

    const finalStatus = JSON.parse(await readFile(statusPath, "utf8"));
    const finalState = JSON.parse(await readFile(statePath, "utf8"));

    if (finalStatus.status !== "stopped") {
      throw new Error(`Expected stopped status, received ${finalStatus.status}`);
    }
    if (!finalStatus.finalized || finalStatus.finalizing) {
      throw new Error("Final status did not report a finalized, non-finalizing run.");
    }
    if (finalState.control.status !== "stopped" || !finalState.control.finalized) {
      throw new Error("Final state control block did not report a finalized stopped run.");
    }
    if (finalState.stats.activeThreats !== 0) {
      throw new Error(`Expected zero active threats after finalize, received ${finalState.stats.activeThreats}`);
    }

    console.log(
      JSON.stringify(
        {
          status: "ok",
          finalizedAt: finalStatus.finalizedAt,
          retiredThreats: finalState.stats.retiredThreats,
          completedComparisons:
            finalState.stats.containedThreats +
            finalState.stats.modelCompromises +
            finalState.stats.sdkBypasses
        },
        null,
        2
      )
    );
  } finally {
    if (child.exitCode === null) {
      child.kill("SIGKILL");
    }
  }
}

main().catch((error) => {
  console.error(error instanceof Error ? error.message : String(error));
  process.exitCode = 1;
});

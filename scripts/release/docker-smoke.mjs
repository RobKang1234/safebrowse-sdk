import { execFile } from "node:child_process";
import { createServer } from "node:net";
import { resolve } from "node:path";
import { promisify } from "node:util";

const execFileAsync = promisify(execFile);
const repoRoot = resolve(import.meta.dirname, "..", "..");
const dockerCommand = "docker";

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
  const { port } = address;
  await new Promise((resolvePromise) => server.close(() => resolvePromise()));
  return port;
}

async function sleep(ms) {
  return new Promise((resolvePromise) => setTimeout(resolvePromise, ms));
}

async function main() {
  const imageTag = `safebrowse-daemon:smoke-${Date.now()}`;
  const hostPort = await getFreePort();
  let containerId = "";

  try {
    await execFileAsync(dockerCommand, ["build", "-t", imageTag, "."], {
      cwd: repoRoot,
      encoding: "utf8"
    });

    const runResult = await execFileAsync(
      dockerCommand,
      ["run", "-d", "-p", `${hostPort}:8787`, imageTag],
      {
        cwd: repoRoot,
        encoding: "utf8"
      }
    );
    containerId = runResult.stdout.trim();

    let healthy = false;
    for (let attempt = 0; attempt < 30; attempt += 1) {
      try {
        const response = await fetch(`http://127.0.0.1:${hostPort}/health`);
        if (response.ok) {
          healthy = true;
          break;
        }
      } catch {
        // wait and retry
      }
      await sleep(1000);
    }

    if (!healthy) {
      throw new Error("Docker smoke test failed to reach /health.");
    }

    const userResult = await execFileAsync(
      dockerCommand,
      [
        "exec",
        containerId,
        "node",
        "-e",
        "process.stdout.write(String(process.getuid ? process.getuid() : -1))"
      ],
      {
        cwd: repoRoot,
        encoding: "utf8"
      }
    );
    if (userResult.stdout.trim() === "0") {
      throw new Error("Docker smoke test detected a root runtime user.");
    }

    console.log(`docker smoke passed on port ${hostPort}`);
  } finally {
    if (containerId) {
      await execFileAsync(dockerCommand, ["rm", "-f", containerId], {
        cwd: repoRoot,
        encoding: "utf8"
      }).catch(() => undefined);
    }
    await execFileAsync(dockerCommand, ["rmi", "-f", imageTag], {
      cwd: repoRoot,
      encoding: "utf8"
    }).catch(() => undefined);
  }
}

main().catch((error) => {
  console.error(error instanceof Error ? error.message : String(error));
  process.exitCode = 1;
});

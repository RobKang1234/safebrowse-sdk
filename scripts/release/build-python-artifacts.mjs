import { rm } from "node:fs/promises";
import { resolve } from "node:path";
import { execFile } from "node:child_process";
import { promisify } from "node:util";

const execFileAsync = promisify(execFile);
const repoRoot = resolve(import.meta.dirname, "..", "..");

async function main() {
  const cleanupPaths = [
    resolve(repoRoot, "python/dist"),
    resolve(repoRoot, "python/safebrowse_client/build"),
    resolve(repoRoot, "python/safebrowse_client/src/safebrowse_client.egg-info")
  ];

  await Promise.all(cleanupPaths.map((path) => rm(path, { recursive: true, force: true })));

  await execFileAsync(
    process.execPath,
    [
      resolve(repoRoot, "scripts/run-python-module.mjs"),
      "-m",
      "build",
      "python/safebrowse_client",
      "-o",
      "python/dist"
    ],
    {
      cwd: repoRoot,
      encoding: "utf8"
    }
  );

  console.log("python artifacts built");
}

main().catch((error) => {
  console.error(error instanceof Error ? error.message : String(error));
  process.exitCode = 1;
});

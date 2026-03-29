import { readdir } from "node:fs/promises";
import { resolve } from "node:path";
import { execFile } from "node:child_process";
import { promisify } from "node:util";

const execFileAsync = promisify(execFile);
const repoRoot = resolve(import.meta.dirname, "..", "..");

async function main() {
  const distDir = resolve(repoRoot, "python/dist");
  const artifacts = (await readdir(distDir))
    .filter((file) => file.endsWith(".whl") || file.endsWith(".tar.gz"))
    .map((file) => resolve(distDir, file));

  if (artifacts.length === 0) {
    throw new Error("No Python distribution artifacts were found in python/dist.");
  }

  await execFileAsync(
    process.execPath,
    [resolve(repoRoot, "scripts/run-python-module.mjs"), "-m", "twine", "check", ...artifacts],
    {
      cwd: repoRoot,
      encoding: "utf8"
    }
  );

  console.log("python artifacts checked");
}

main().catch((error) => {
  console.error(error instanceof Error ? error.message : String(error));
  process.exitCode = 1;
});

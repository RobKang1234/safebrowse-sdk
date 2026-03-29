import { cp, mkdir, rm } from "node:fs/promises";
import { resolve } from "node:path";
import process from "node:process";

const packageRoot = resolve(import.meta.dirname, "..");
const repoRoot = resolve(packageRoot, "..", "..");
const outputRoot = resolve(packageRoot, "dist", "runtime");

async function copyTree(source, target, filter) {
  await cp(source, target, {
    recursive: true,
    force: true,
    filter
  });
}

async function main() {
  await rm(outputRoot, { recursive: true, force: true });
  await mkdir(outputRoot, { recursive: true });

  await copyTree(resolve(repoRoot, "config"), resolve(outputRoot, "config"));
  await copyTree(resolve(repoRoot, "policies"), resolve(outputRoot, "policies"));
  await copyTree(resolve(repoRoot, "knowledge_base"), resolve(outputRoot, "knowledge_base"), (path) => {
    const normalized = path.replace(/\\/g, "/");
    return !normalized.includes("/knowledge_base/signing/private");
  });
}

main().catch((error) => {
  console.error(error instanceof Error ? error.message : String(error));
  process.exitCode = 1;
});

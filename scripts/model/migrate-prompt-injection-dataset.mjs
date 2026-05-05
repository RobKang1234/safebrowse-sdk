import { createHash } from "node:crypto";
import { mkdir, readdir, readFile, rename, stat, writeFile } from "node:fs/promises";
import { homedir } from "node:os";
import { join, resolve } from "node:path";

const repoRoot = resolve(import.meta.dirname, "..", "..");
const datasetDir = resolve(repoRoot, "model", "prompt_injection_ml_dataset");
const manifestPath = resolve(datasetDir, "manifest.json");
const keepNames = new Set([
  "README.md",
  "manifest.json",
  "training_recipe_additional_v2_rtx4060ti_8gb.json",
  "training_recipe_additional_v2_rtx4060ti_8gb.md",
  "training_recipe.json",
  "training_recipe.md"
]);

function defaultDataRoot() {
  return join(homedir(), ".safebrowse", "private_data");
}

async function fileSha256(path) {
  const hash = createHash("sha256");
  const handle = await readFile(path);
  hash.update(handle);
  return hash.digest("hex");
}

async function collectStorageFiles(root, relativePrefix = "") {
  const entries = [];
  for (const dirent of await readdir(root, { withFileTypes: true })) {
    const relativePath = relativePrefix ? `${relativePrefix}/${dirent.name}` : dirent.name;
    const absolutePath = resolve(root, dirent.name);
    if (dirent.isDirectory()) {
      entries.push(...(await collectStorageFiles(absolutePath, relativePath)));
      continue;
    }
    const fileStat = await stat(absolutePath);
    const lower = relativePath.toLowerCase();
    let split = "train";
    if (lower.includes("valid_")) {
      split = "valid";
    } else if (lower.includes("test_")) {
      split = "test";
    } else if (lower.includes("rendered_sample")) {
      split = "rendered_sample";
    }
    entries.push({
      split,
      relative_path: relativePath.replaceAll("\\", "/"),
      size_bytes: fileStat.size,
      sha256: await fileSha256(absolutePath)
    });
  }
  return entries.sort((left, right) => left.relative_path.localeCompare(right.relative_path));
}

async function main() {
  const manifest = JSON.parse(await readFile(manifestPath, "utf8"));
  const dataRoot = resolve(process.env.SAFEBROWSE_DATA_ROOT || defaultDataRoot());
  const privateDatasetDir = resolve(dataRoot, "prompt_injection_ml_dataset");

  await mkdir(privateDatasetDir, { recursive: true });

  const moved = [];
  for (const dirent of await readdir(datasetDir, { withFileTypes: true })) {
    if (keepNames.has(dirent.name)) {
      continue;
    }
    const sourcePath = resolve(datasetDir, dirent.name);
    const targetPath = resolve(privateDatasetDir, dirent.name);
    await rename(sourcePath, targetPath);
    moved.push(dirent.name);
  }

  const files = await collectStorageFiles(privateDatasetDir);
  manifest.storage = {
    data_root_env: "SAFEBROWSE_DATA_ROOT",
    default_private_root: "~/.safebrowse/private_data",
    dataset_subdir: "prompt_injection_ml_dataset",
    layout: "manifest-only in repo; JSONL payloads live under the private data root",
    files
  };

  await writeFile(manifestPath, `${JSON.stringify(manifest, null, 2)}\n`, "utf8");

  console.log(
    JSON.stringify(
      {
        dataRoot,
        privateDatasetDir,
        movedEntries: moved,
        indexedFiles: files.length
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

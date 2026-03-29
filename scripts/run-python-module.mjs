import { spawnSync } from "node:child_process";

const args = process.argv.slice(2);
const candidates = process.platform === "win32" ? ["py", "python"] : ["python3", "python"];

for (const command of candidates) {
  const result = spawnSync(command, args, {
    stdio: "inherit",
    shell: process.platform === "win32"
  });

  if (!result.error) {
    process.exit(result.status ?? 0);
  }
}

console.error(`Unable to find a Python launcher. Tried: ${candidates.join(", ")}`);
process.exit(1);

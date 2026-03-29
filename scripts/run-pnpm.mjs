import { spawnSync } from "node:child_process";

const args = process.argv.slice(2);
const isWindows = process.platform === "win32";
const whichCommand = isWindows ? "where.exe" : "which";
const candidates = [
  { command: "pnpm", args },
  { command: "corepack", args: ["pnpm", ...args] }
];

for (const candidate of candidates) {
  const availability = spawnSync(whichCommand, [candidate.command], {
    stdio: "ignore",
    shell: isWindows
  });

  if (availability.status !== 0) {
    continue;
  }

  const result = spawnSync(candidate.command, candidate.args, {
    stdio: "inherit",
    shell: isWindows
  });

  if (!result.error) {
    process.exit(result.status ?? 0);
  }
}

console.error("Unable to find pnpm. Tried: pnpm, corepack pnpm");
process.exit(1);

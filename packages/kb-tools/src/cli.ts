import { buildBundleDefaults, buildKnowledgeBundle, describeBuildResult, verifyKnowledgeBundle } from "./bundle.js";

function readFlag(args: string[], flag: string): string | undefined {
  const index = args.indexOf(flag);
  return index >= 0 ? args[index + 1] : undefined;
}

function hasFlag(args: string[], flag: string): boolean {
  return args.includes(flag);
}

async function main(): Promise<void> {
  const [command = "build-bundle", ...args] = process.argv.slice(2);
  const defaults = buildBundleDefaults();

  if (command === "build-bundle") {
    const result = await buildKnowledgeBundle({
      ...defaults,
      kbDir: readFlag(args, "--kb-dir") ?? defaults.kbDir,
      indexFile: readFlag(args, "--index") ?? defaults.indexFile,
      outputZip: readFlag(args, "--out-zip") ?? defaults.outputZip,
      outputZipSig: readFlag(args, "--out-zip-sig") ?? defaults.outputZipSig,
      outputIndexSig: readFlag(args, "--out-index-sig") ?? defaults.outputIndexSig,
      publicKeyOut: readFlag(args, "--public-key-out") ?? defaults.publicKeyOut,
      privateKeyOut: readFlag(args, "--private-key-out") ?? defaults.privateKeyOut,
      generateDevKey: hasFlag(args, "--generate-dev-key") || defaults.generateDevKey
    });
    console.log(describeBuildResult(result.outputZip));
    return;
  }

  if (command === "verify-bundle") {
    const verified = await verifyKnowledgeBundle({
      indexFile: readFlag(args, "--index") ?? defaults.indexFile,
      outputZip: readFlag(args, "--out-zip") ?? defaults.outputZip,
      outputZipSig: readFlag(args, "--out-zip-sig") ?? defaults.outputZipSig,
      outputIndexSig: readFlag(args, "--out-index-sig") ?? defaults.outputIndexSig,
      publicKeyPath: readFlag(args, "--public-key") ?? defaults.publicKeyOut
    });
    console.log(verified ? "verified" : "verification_failed");
    if (!verified) {
      process.exitCode = 1;
    }
    return;
  }

  throw new Error(`Unknown command: ${command}`);
}

void main();


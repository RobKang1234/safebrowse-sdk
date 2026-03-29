import {
  createPrivateKey,
  createPublicKey,
  generateKeyPairSync,
  sign as signBuffer,
  verify as verifyBuffer
} from "node:crypto";
import { mkdir, readFile, readdir, writeFile } from "node:fs/promises";
import { basename, dirname, join, resolve } from "node:path";

import { zipSync } from "fflate";

export interface BuildKnowledgeBundleOptions {
  kbDir: string;
  indexFile: string;
  outputZip: string;
  outputZipSig: string;
  outputIndexSig: string;
  publicKeyOut?: string;
  privateKeyOut?: string;
  privateKeyPem?: string;
  generateDevKey?: boolean;
}

export interface VerifyKnowledgeBundleOptions {
  indexFile: string;
  outputZip: string;
  outputZipSig: string;
  outputIndexSig: string;
  publicKeyPem?: string;
  publicKeyPath?: string;
}

async function writeIfRequested(path: string | undefined, contents: string): Promise<void> {
  if (!path) {
    return;
  }
  await mkdir(dirname(path), { recursive: true });
  await writeFile(path, contents, "utf8");
}

async function loadSigningKey(options: BuildKnowledgeBundleOptions): Promise<{
  privateKeyPem?: string;
  publicKeyPem?: string;
}> {
  if (options.privateKeyPem) {
    const privateKey = createPrivateKey(options.privateKeyPem);
    const publicKey = createPublicKey(privateKey);
    return {
      privateKeyPem: options.privateKeyPem,
      publicKeyPem: publicKey.export({ format: "pem", type: "spki" }).toString()
    };
  }

  if (options.privateKeyOut) {
    try {
      const privateKeyPem = await readFile(options.privateKeyOut, "utf8");
      const privateKey = createPrivateKey(privateKeyPem);
      const publicKey = createPublicKey(privateKey);
      return {
        privateKeyPem,
        publicKeyPem: publicKey.export({ format: "pem", type: "spki" }).toString()
      };
    } catch {
      // fall through
    }
  }

  if (!options.generateDevKey) {
    return {};
  }

  const { privateKey, publicKey } = generateKeyPairSync("ed25519");
  const privateKeyPem = privateKey.export({ format: "pem", type: "pkcs8" }).toString();
  const publicKeyPem = publicKey.export({ format: "pem", type: "spki" }).toString();
  await writeIfRequested(options.privateKeyOut, privateKeyPem);
  return { privateKeyPem, publicKeyPem };
}

async function collectKnowledgeFiles(kbDir: string): Promise<Record<string, Uint8Array>> {
  const files = await readdir(kbDir);
  const payloads = await Promise.all(
    files
      .filter((file) => file.endsWith(".json"))
      .map(async (file) => {
        const contents = await readFile(join(kbDir, file));
        return [file, new Uint8Array(contents)] as const;
      })
  );

  return Object.fromEntries(payloads);
}

function toBase64Signature(buffer: Uint8Array, privateKeyPem: string): string {
  return signBuffer(null, buffer, createPrivateKey(privateKeyPem)).toString("base64");
}

export async function buildKnowledgeBundle(
  options: BuildKnowledgeBundleOptions
): Promise<{
  outputZip: string;
  outputZipSig?: string;
  outputIndexSig?: string;
  publicKeyPem?: string;
}> {
  const knowledgeFiles = await collectKnowledgeFiles(options.kbDir);
  const zipped = Buffer.from(zipSync(knowledgeFiles, { level: 9 }));
  await writeFile(options.outputZip, zipped);

  const { privateKeyPem, publicKeyPem } = await loadSigningKey(options);
  if (publicKeyPem && options.publicKeyOut) {
    await writeIfRequested(options.publicKeyOut, publicKeyPem);
  }

  if (!privateKeyPem) {
    return {
      outputZip: options.outputZip,
      publicKeyPem
    };
  }

  const indexBytes = await readFile(options.indexFile);
  const zipSignature = toBase64Signature(zipped, privateKeyPem);
  const indexSignature = toBase64Signature(indexBytes, privateKeyPem);

  await writeFile(options.outputZipSig, `${zipSignature}\n`, "utf8");
  await writeFile(options.outputIndexSig, `${indexSignature}\n`, "utf8");

  return {
    outputZip: options.outputZip,
    outputZipSig: options.outputZipSig,
    outputIndexSig: options.outputIndexSig,
    publicKeyPem
  };
}

export async function verifyKnowledgeBundle(
  options: VerifyKnowledgeBundleOptions
): Promise<boolean> {
  const publicKeyPem =
    options.publicKeyPem ??
    (options.publicKeyPath ? await readFile(options.publicKeyPath, "utf8") : undefined);

  if (!publicKeyPem) {
    throw new Error("A public key is required to verify the knowledge bundle.");
  }

  const publicKey = createPublicKey(publicKeyPem);
  const [indexBytes, indexSig, zipBytes, zipSig] = await Promise.all([
    readFile(options.indexFile),
    readFile(options.outputIndexSig, "utf8"),
    readFile(options.outputZip),
    readFile(options.outputZipSig, "utf8")
  ]);

  return (
    verifyBuffer(null, indexBytes, publicKey, Buffer.from(indexSig.trim(), "base64")) &&
    verifyBuffer(null, zipBytes, publicKey, Buffer.from(zipSig.trim(), "base64"))
  );
}

export function buildBundleDefaults(rootDir = process.cwd()): BuildKnowledgeBundleOptions {
  const kbDir = resolve(rootDir, "knowledge_base");
  const signingDir = resolve(kbDir, "signing");
  return {
    kbDir,
    indexFile: resolve(kbDir, "safebrowse_vf_knowledge_base_index.json"),
    outputZip: resolve(kbDir, "safebrowse_vf_knowledge_bases.zip"),
    outputZipSig: resolve(kbDir, "safebrowse_vf_knowledge_bases.zip.sig"),
    outputIndexSig: resolve(kbDir, "safebrowse_vf_knowledge_base_index.json.sig"),
    publicKeyOut: resolve(signingDir, "safebrowse_vf_ed25519_public.pem"),
    privateKeyOut: resolve(signingDir, "private", "safebrowse_vf_ed25519_private.pem"),
    privateKeyPem: process.env.SAFEBROWSE_SIGNING_PRIVATE_KEY_PEM,
    generateDevKey: false
  };
}

export function describeBuildResult(outputZip: string): string {
  return `Built ${basename(outputZip)}`;
}

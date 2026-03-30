import { createPublicKey, verify as verifyBuffer } from "node:crypto";
import { readFile } from "node:fs/promises";
import { resolve } from "node:path";

import type { VerifiedRegistryBundle, VerifiedRegistryEntry } from "@safebrowse/core";

interface RawRegistryAdapter {
  registryEntryId?: string;
  adapterId?: string;
  package?: string;
  mode?: string;
  authType?: "none" | "oauth" | "api_key";
  capabilities?: string[];
  allowedTransports?: string[];
  allowedRedirectUris?: string[];
  allowedCallbackOrigins?: string[];
  allowedScopes?: string[];
  manifestHash?: string;
  schemaHash?: string;
  expiresAt?: string;
  signer?: string;
  allowPrivateEgress?: boolean;
  allowLoopbackCallbacks?: boolean;
  sinkSensitivity?: "read_only" | "external_sensitive_sink";
  writeCapability?: boolean;
}

interface RawRegistryBundle {
  bundleId?: string;
  registryVersion?: number | string;
  generatedAt?: string;
  expiresAt?: string;
  signer?: string;
  publicKeyId?: string;
  adapters?: RawRegistryAdapter[];
}

export interface LoadVerifiedRegistryBundleOptions {
  registryFile: string;
  signatureFile: string;
  publicKeyPath: string;
}

function toVerifiedEntry(
  adapter: RawRegistryAdapter,
  bundle: RawRegistryBundle,
  version: string
): VerifiedRegistryEntry {
  const registryEntryId = String(adapter.registryEntryId ?? adapter.adapterId ?? "unknown-adapter");
  return {
    registryEntryId,
    adapterId: String(adapter.adapterId ?? registryEntryId),
    bundleId: String(bundle.bundleId ?? "adapter-registry"),
    bundleVersion: version,
    signer: String(adapter.signer ?? bundle.signer ?? "unknown"),
    authType: adapter.authType ?? "none",
    package: adapter.package,
    mode: adapter.mode,
    capabilities: adapter.capabilities ?? [],
    allowedTransports: adapter.allowedTransports ?? [],
    allowedRedirectUris: adapter.allowedRedirectUris ?? [],
    allowedCallbackOrigins: adapter.allowedCallbackOrigins ?? [],
    allowedScopes: adapter.allowedScopes ?? [],
    manifestHash: adapter.manifestHash,
    schemaHash: adapter.schemaHash,
    expiresAt: adapter.expiresAt ?? bundle.expiresAt,
    allowPrivateEgress: adapter.allowPrivateEgress ?? false,
    allowLoopbackCallbacks: adapter.allowLoopbackCallbacks ?? false,
    sinkSensitivity: adapter.sinkSensitivity,
    writeCapability: adapter.writeCapability ?? false
  };
}

export async function loadVerifiedRegistryBundle(
  options: LoadVerifiedRegistryBundleOptions
): Promise<VerifiedRegistryBundle> {
  const [registryBytes, signatureText, publicKeyPem] = await Promise.all([
    readFile(options.registryFile),
    readFile(options.signatureFile, "utf8"),
    readFile(options.publicKeyPath, "utf8")
  ]);

  const publicKey = createPublicKey(publicKeyPem);
  const signatureVerified = verifyBuffer(
    null,
    registryBytes,
    publicKey,
    Buffer.from(signatureText.trim(), "base64")
  );
  const bundle = JSON.parse(registryBytes.toString("utf8")) as RawRegistryBundle;
  const version = String(bundle.registryVersion ?? "1");

  return {
    bundleId: String(bundle.bundleId ?? "adapter-registry"),
    version,
    signer: String(bundle.signer ?? "unknown"),
    generatedAt: String(bundle.generatedAt ?? new Date(0).toISOString()),
    expiresAt: bundle.expiresAt,
    publicKeyId: bundle.publicKeyId,
    signatureVerified,
    entries: (bundle.adapters ?? []).map((adapter) => toVerifiedEntry(adapter, bundle, version))
  };
}

export function buildRegistryDefaults(rootDir = process.cwd()): LoadVerifiedRegistryBundleOptions {
  return {
    registryFile: resolve(rootDir, "config", "adapter-registry.json"),
    signatureFile: resolve(rootDir, "config", "adapter-registry.json.sig"),
    publicKeyPath: resolve(
      rootDir,
      "knowledge_base",
      "signing",
      "safebrowse_vf_ed25519_public.pem"
    )
  };
}

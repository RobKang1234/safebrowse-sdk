import { createPublicKey, verify as verifyBuffer } from "node:crypto";
import { readFile, stat } from "node:fs/promises";
import { resolve } from "node:path";

import type {
  ExtractorProfileEntry,
  JsonValue,
  KnowledgeBaseContext,
  PolicyLayer,
  PolicyPack,
  VerifiedApiProviderEntry,
  VerifiedRegistryBundle,
  VerifiedRegistryEntry
} from "@safebrowse/core";
import YAML from "yaml";

const KB_FILE_MAP = {
  promptInjectionPatterns: "safebrowse_vf_prompt_injection_patterns.json",
  actionIntegrityPatterns: "safebrowse_vf_action_integrity_patterns.json",
  artifactSurfacePatterns: "safebrowse_vf_artifact_surface_patterns.json",
  toolProtocolPatterns: "safebrowse_vf_tool_protocol_supply_chain_patterns.json",
  memoryContextPatterns: "safebrowse_vf_memory_context_poisoning_patterns.json",
  trustSignalsCatalog: "safebrowse_vf_trust_signals_provenance.json",
  policyControls: "safebrowse_vf_policy_controls_catalog.json",
  incidentPlaybooks: "safebrowse_vf_incident_response_playbooks.json",
  evaluationScenarios: "safebrowse_vf_evaluation_scenarios.json",
  sourceRegistry: "safebrowse_vf_source_registry.json"
} satisfies Record<keyof KnowledgeBaseContext, string>;

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
}

interface RawRegistryBundle {
  bundleId?: string;
  registryVersion?: number | string;
  generatedAt?: string;
  expiresAt?: string;
  signer?: string;
  publicKeyId?: string;
  adapters?: RawRegistryAdapter[];
  apiProviders?: Array<{
    providerId?: string;
    authType?: "none" | "oauth" | "api_key";
    allowedBaseUrls?: string[];
    allowedMethods?: string[];
    allowedOperationClasses?: Array<
      | "browser_navigation"
      | "connector_setup"
      | "memory_promotion"
      | "email_send"
      | "email_reply"
      | "email_forward"
      | "api_read"
      | "api_write"
      | "api_delete"
      | "api_export"
    >;
    requestSchemaHash?: string;
    responseSchemaHash?: string;
    allowedScopes?: string[];
    allowedCallbackOrigins?: string[];
    allowedRedirectUris?: string[];
    signer?: string;
    readOnly?: boolean;
    mutating?: boolean;
    expiresAt?: string;
  }>;
  extractorProfiles?: Array<{
    extractorId?: string;
    supportedMimeTypes?: string[];
    supportedSurfaceTypes?: Array<
      | "html"
      | "pdf"
      | "image"
      | "email_message"
      | "docx"
      | "xlsx"
      | "pptx"
      | "attachment_bundle"
      | "external_api_response"
      | "tool_manifest"
      | "memory_candidate"
    >;
    parserDigest?: string;
    maxRecursionDepth?: number;
    maxExpandedBytes?: number;
    networkPolicy?: "deny" | "allowlisted_only";
    activeContentPolicy?: "block" | "quarantine";
    supportedChannels?: string[];
    signer?: string;
    expiresAt?: string;
  }>;
}

interface LoadVerifiedRegistryBundleOptions {
  registryFile: string;
  signatureFile: string;
  publicKeyPath: string;
}

function getDataArray(payload: Record<string, unknown>): Array<Record<string, unknown>> {
  const arrays = ["patterns", "entries", "signals", "controls", "playbooks", "scenarios", "sources"];
  for (const key of arrays) {
    const value = payload[key];
    if (Array.isArray(value)) {
      return value as Array<Record<string, unknown>>;
    }
  }
  return [];
}

async function readJsonFile(path: string): Promise<Record<string, unknown>> {
  return JSON.parse(await readFile(path, "utf8")) as Record<string, unknown>;
}

async function fileExists(path?: string): Promise<boolean> {
  if (!path) {
    return false;
  }
  try {
    await stat(path);
    return true;
  } catch {
    return false;
  }
}

function toPolicyLayer(name: string, input: Record<string, unknown>): PolicyLayer {
  const metadata = (input.metadata ?? {}) as Record<string, unknown>;
  const origins = (input.origins ?? {}) as Record<string, unknown>;
  const actions = (input.actions ?? {}) as Record<string, unknown>;
  const artifacts = (input.artifacts ?? {}) as Record<string, unknown>;
  const email = (input.email ?? {}) as Record<string, unknown>;
  const extraction = (input.extraction ?? {}) as Record<string, unknown>;
  const api = (input.api ?? {}) as Record<string, unknown>;
  const memory = (input.memory ?? {}) as Record<string, unknown>;
  const toolProtocol = (input.tool_protocol ?? {}) as Record<string, unknown>;
  const telemetry = (input.telemetry ?? {}) as Record<string, unknown>;

  return {
    name,
    version: String(metadata.version ?? input.version ?? "0.1.0"),
    profile: String(input.profile ?? "research"),
    origins: {
      readOnlyAllow: (origins.read_only_allow as string[] | undefined) ?? [],
      writableAllow: (origins.writable_allow as string[] | undefined) ?? []
    },
    actions: {
      allow: (actions.allow as string[] | undefined) ?? [],
      requireApproval: (actions.require_approval as string[] | undefined) ?? [],
      deny: (actions.deny as string[] | undefined) ?? []
    },
    artifacts: {
      enableDocumentHandoff: Boolean(artifacts.enable_document_handoff ?? true),
      quarantineOnHiddenTextMismatch: Boolean(
        artifacts.quarantine_on_hidden_text_mismatch ?? true
      ),
      allowMimeTypes: (artifacts.allow_mime_types as string[] | undefined) ?? [],
      allowAttachmentMimeFamilies:
        (artifacts.allow_attachment_mime_families as string[] | undefined) ?? [],
      maxExtractionDepth: Number(artifacts.max_extraction_depth ?? 3),
      encryptedAttachmentDecision:
        (artifacts.encrypted_attachment_decision as
          | "block"
          | "quarantine"
          | "manual_review"
          | undefined) ?? "quarantine"
    },
    email: {
      allowedProviders: (email.allowed_providers as string[] | undefined) ?? [],
      allowedRecipientDomains:
        (email.allowed_recipient_domains as string[] | undefined) ?? [],
      forbiddenRecipientDomains:
        (email.forbidden_recipient_domains as string[] | undefined) ?? []
    },
    extraction: {
      allowedExtractorIds: (extraction.allowed_extractor_ids as string[] | undefined) ?? [],
      maxRecursionDepth: Number(extraction.max_recursion_depth ?? 3),
      maxExpandedBytes: Number(extraction.max_expanded_bytes ?? 5_000_000),
      blockEncryptedChildren: Boolean(extraction.block_encrypted_children ?? true)
    },
    api: {
      allowedProviders: (api.allowed_providers as string[] | undefined) ?? [],
      allowedOperationClasses:
        (
          api.allowed_operation_classes as
            | NonNullable<PolicyLayer["api"]>["allowedOperationClasses"]
            | undefined
        ) ?? [],
      mutationRequiresApproval: Boolean(api.mutation_requires_approval ?? true),
      exportRequiresApproval: Boolean(api.export_requires_approval ?? true),
      maxResponseBytes: Number(api.max_response_bytes ?? 1_000_000)
    },
    memory: {
      durableWrites:
        (memory.durable_writes as "allow" | "deny" | "approval" | undefined) ?? "deny",
      protectedKeys: (memory.protected_keys as string[] | undefined) ?? []
    },
    toolProtocol: {
      forbidTokenPassthrough: Boolean(toolProtocol.forbid_token_passthrough ?? true),
      enforceExactRedirectUri: Boolean(toolProtocol.enforce_exact_redirect_uri ?? true),
      allowedRegistrySigners:
        (toolProtocol.allowed_registry_signers as string[] | undefined) ?? [],
      requireVerifiedRegistry: Boolean(toolProtocol.require_verified_registry ?? true),
      requireApprovalBinding: Boolean(toolProtocol.require_approval_binding ?? true),
      requireOauthStateBinding: Boolean(toolProtocol.require_oauth_state_binding ?? true),
      taintedConnectorFlowDecision:
        (toolProtocol.tainted_connector_flow_decision as "block" | "user_confirm" | undefined) ??
        "block",
      allowLoopbackCallbacksInDev: Boolean(
        toolProtocol.allow_loopback_callbacks_in_dev ?? false
      )
    },
    telemetry: {
      replayBundle: Boolean(telemetry.replay_bundle ?? true),
      redactSensitiveValues: Boolean(telemetry.redact_sensitive_values ?? true),
      sampling:
        (telemetry.sampling as "full" | "adaptive" | "off" | undefined) ?? "adaptive"
    },
    raw: input as Record<string, JsonValue>
  };
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
    allowLoopbackCallbacks: adapter.allowLoopbackCallbacks ?? false
  };
}

function toVerifiedApiProviderEntry(
  provider: NonNullable<RawRegistryBundle["apiProviders"]>[number],
  bundle: RawRegistryBundle,
  version: string
): VerifiedApiProviderEntry {
  return {
    providerId: String(provider.providerId ?? "unknown-provider"),
    bundleId: String(bundle.bundleId ?? "adapter-registry"),
    bundleVersion: version,
    signer: String(provider.signer ?? bundle.signer ?? "unknown"),
    authType: provider.authType ?? "none",
    allowedBaseUrls: provider.allowedBaseUrls ?? [],
    allowedMethods: provider.allowedMethods ?? [],
    allowedOperationClasses: provider.allowedOperationClasses ?? [],
    requestSchemaHash: provider.requestSchemaHash,
    responseSchemaHash: provider.responseSchemaHash,
    allowedScopes: provider.allowedScopes ?? [],
    allowedCallbackOrigins: provider.allowedCallbackOrigins ?? [],
    allowedRedirectUris: provider.allowedRedirectUris ?? [],
    readOnly: provider.readOnly ?? false,
    mutating: provider.mutating ?? false,
    expiresAt: provider.expiresAt ?? bundle.expiresAt
  };
}

function toExtractorProfileEntry(
  extractor: NonNullable<RawRegistryBundle["extractorProfiles"]>[number],
  bundle: RawRegistryBundle,
  version: string
): ExtractorProfileEntry {
  return {
    extractorId: String(extractor.extractorId ?? "unknown-extractor"),
    bundleId: String(bundle.bundleId ?? "adapter-registry"),
    bundleVersion: version,
    signer: String(extractor.signer ?? bundle.signer ?? "unknown"),
    supportedMimeTypes: extractor.supportedMimeTypes ?? [],
    supportedSurfaceTypes: extractor.supportedSurfaceTypes ?? [],
    parserDigest: String(extractor.parserDigest ?? ""),
    maxRecursionDepth: extractor.maxRecursionDepth ?? 3,
    maxExpandedBytes: extractor.maxExpandedBytes ?? 5_000_000,
    networkPolicy: extractor.networkPolicy ?? "deny",
    activeContentPolicy: extractor.activeContentPolicy ?? "block",
    supportedChannels: (extractor.supportedChannels ?? []) as ExtractorProfileEntry["supportedChannels"],
    expiresAt: extractor.expiresAt ?? bundle.expiresAt
  };
}

export async function loadKnowledgeBaseContext(kbDir: string): Promise<KnowledgeBaseContext> {
  const entries = await Promise.all(
    Object.entries(KB_FILE_MAP).map(async ([key, fileName]) => {
      const payload = await readJsonFile(resolve(kbDir, fileName));
      return [key, getDataArray(payload)] as const;
    })
  );

  return Object.fromEntries(entries) as unknown as KnowledgeBaseContext;
}

export function resolvePolicyLayerFiles(rootDir = process.cwd()): {
  base: string;
  tenant: string;
  project: string;
  emergency: string;
} {
  return {
    base: resolve(rootDir, "policies/base/research.yaml"),
    tenant: resolve(rootDir, "policies/tenant/default.yaml"),
    project: resolve(rootDir, "policies/project/default.yaml"),
    emergency: resolve(rootDir, "policies/emergency/default.yaml")
  };
}

export async function loadPolicyPackFromPaths(paths: {
  base: string;
  tenant?: string;
  project?: string;
  emergency?: string;
}): Promise<PolicyPack> {
  const orderedEntries = (
    await Promise.all(
      [
        ["base", paths.base],
        ["tenant", paths.tenant],
        ["project", paths.project],
        ["emergency", paths.emergency]
      ].map(async ([name, path]) => {
        if (!(await fileExists(path))) {
          return undefined;
        }
        const text = await readFile(path as string, "utf8");
        const parsed = YAML.parse(text) as Record<string, unknown>;
        return toPolicyLayer(name as string, parsed);
      })
    )
  ).filter(Boolean) as PolicyLayer[];

  if (!orderedEntries.length) {
    throw new Error("No policy layers were found.");
  }

  return {
    packId: `${orderedEntries[0].profile}-policy-pack`,
    profile: orderedEntries[0].profile,
    version: orderedEntries.map((layer) => layer.version).join("+"),
    layers: orderedEntries
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
    entries: (bundle.adapters ?? []).map((adapter) => toVerifiedEntry(adapter, bundle, version)),
    apiProviders: (bundle.apiProviders ?? []).map((provider) =>
      toVerifiedApiProviderEntry(provider, bundle, version)
    ),
    extractorProfiles: (bundle.extractorProfiles ?? []).map((extractor) =>
      toExtractorProfileEntry(extractor, bundle, version)
    )
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

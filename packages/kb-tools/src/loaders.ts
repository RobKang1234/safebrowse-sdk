import { readFile, stat } from "node:fs/promises";
import { resolve } from "node:path";

import type { KnowledgeBaseContext, PolicyLayer, PolicyPack } from "@safebrowse/core";
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

function toPolicyLayer(name: string, input: Record<string, unknown>): PolicyLayer {
  const metadata = (input.metadata ?? {}) as Record<string, unknown>;
  const origins = (input.origins ?? {}) as Record<string, unknown>;
  const actions = (input.actions ?? {}) as Record<string, unknown>;
  const artifacts = (input.artifacts ?? {}) as Record<string, unknown>;
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
      allowMimeTypes: (artifacts.allow_mime_types as string[] | undefined) ?? []
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
        (toolProtocol.allowed_registry_signers as string[] | undefined) ?? []
    },
    telemetry: {
      replayBundle: Boolean(telemetry.replay_bundle ?? true),
      redactSensitiveValues: Boolean(telemetry.redact_sensitive_values ?? true),
      sampling:
        (telemetry.sampling as "full" | "adaptive" | "off" | undefined) ?? "adaptive"
    }
  };
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

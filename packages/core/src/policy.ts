import type { CompiledPolicy, OperationClass, PolicyLayer, PolicyPack } from "./types.js";
import { normalizeOrigin } from "./utils.js";

function mergeArrays(...groups: Array<string[] | undefined>): ReadonlySet<string> {
  const merged = new Set<string>();
  for (const group of groups) {
    for (const item of group ?? []) {
      merged.add(item.toLowerCase());
    }
  }
  return merged;
}

function mergeBooleans(
  layers: PolicyLayer[],
  selector: (layer: PolicyLayer) => boolean | undefined,
  fallback: boolean
): boolean {
  let current = fallback;
  for (const layer of layers) {
    const value = selector(layer);
    if (typeof value === "boolean") {
      current = value;
    }
  }
  return current;
}

export function compilePolicy(policyPack: PolicyPack): CompiledPolicy {
  const layers = [...policyPack.layers];

  const readOnlyOrigins = new Set(
    [...mergeArrays(...layers.map((layer) => layer.origins?.readOnlyAllow))].map((origin) =>
      normalizeOrigin(origin)
    )
  );
  const writableOrigins = new Set(
    [...mergeArrays(...layers.map((layer) => layer.origins?.writableAllow))].map((origin) =>
      normalizeOrigin(origin)
    )
  );

  let memoryDurableWrites: "allow" | "deny" | "approval" = "deny";
  for (const layer of layers) {
    if (layer.memory?.durableWrites) {
      memoryDurableWrites = layer.memory.durableWrites;
    }
  }

  let telemetrySampling: "full" | "adaptive" | "off" = "adaptive";
  for (const layer of layers) {
    if (layer.telemetry?.sampling) {
      telemetrySampling = layer.telemetry.sampling;
    }
  }

  return {
    packId: policyPack.packId,
    profile: policyPack.profile,
    version: policyPack.version,
    layerOrder: layers.map((layer) => layer.name),
    layerProvenance: layers.map((layer) => ({
      name: layer.name,
      version: layer.version,
      profile: layer.profile
    })),
    readOnlyOrigins,
    writableOrigins,
    allowedActions: mergeArrays(...layers.map((layer) => layer.actions?.allow)),
    approvalActions: mergeArrays(...layers.map((layer) => layer.actions?.requireApproval)),
    deniedActions: mergeArrays(...layers.map((layer) => layer.actions?.deny)),
    allowedMimeTypes: mergeArrays(...layers.map((layer) => layer.artifacts?.allowMimeTypes)),
    allowedAttachmentMimeFamilies: mergeArrays(
      ...layers.map((layer) => layer.artifacts?.allowAttachmentMimeFamilies)
    ),
    protectedMemoryKeys: mergeArrays(...layers.map((layer) => layer.memory?.protectedKeys)),
    allowedEmailProviders: mergeArrays(...layers.map((layer) => layer.email?.allowedProviders)),
    allowedRecipientDomains: mergeArrays(
      ...layers.map((layer) => layer.email?.allowedRecipientDomains)
    ),
    forbiddenRecipientDomains: mergeArrays(
      ...layers.map((layer) => layer.email?.forbiddenRecipientDomains)
    ),
    allowedExtractorIds: mergeArrays(
      ...layers.map((layer) => layer.extraction?.allowedExtractorIds)
    ),
    maxExtractionDepth:
      [...layers]
        .reverse()
        .find((layer) => typeof layer.extraction?.maxRecursionDepth === "number")
        ?.extraction?.maxRecursionDepth ?? 3,
    maxExpandedBytes:
      [...layers]
        .reverse()
        .find((layer) => typeof layer.extraction?.maxExpandedBytes === "number")
        ?.extraction?.maxExpandedBytes ?? 5_000_000,
    blockEncryptedChildren: mergeBooleans(
      layers,
      (layer) => layer.extraction?.blockEncryptedChildren,
      true
    ),
    allowedApiProviders: mergeArrays(...layers.map((layer) => layer.api?.allowedProviders)),
    allowedApiOperationClasses: new Set(
      [...mergeArrays(...layers.map((layer) => layer.api?.allowedOperationClasses as string[] | undefined))]
    ) as ReadonlySet<OperationClass>,
    apiMutationRequiresApproval: mergeBooleans(
      layers,
      (layer) => layer.api?.mutationRequiresApproval,
      true
    ),
    apiExportRequiresApproval: mergeBooleans(
      layers,
      (layer) => layer.api?.exportRequiresApproval,
      true
    ),
    apiMaxResponseBytes:
      [...layers]
        .reverse()
        .find((layer) => typeof layer.api?.maxResponseBytes === "number")
        ?.api?.maxResponseBytes ?? 1_000_000,
    memoryDurableWrites,
    forbidTokenPassthrough: mergeBooleans(
      layers,
      (layer) => layer.toolProtocol?.forbidTokenPassthrough,
      true
    ),
    enforceExactRedirectUri: mergeBooleans(
      layers,
      (layer) => layer.toolProtocol?.enforceExactRedirectUri,
      true
    ),
    allowedRegistrySigners: mergeArrays(
      ...layers.map((layer) => layer.toolProtocol?.allowedRegistrySigners)
    ),
    requireVerifiedRegistry: mergeBooleans(
      layers,
      (layer) => layer.toolProtocol?.requireVerifiedRegistry,
      true
    ),
    requireApprovalBinding: mergeBooleans(
      layers,
      (layer) => layer.toolProtocol?.requireApprovalBinding,
      true
    ),
    requireOauthStateBinding: mergeBooleans(
      layers,
      (layer) => layer.toolProtocol?.requireOauthStateBinding,
      true
    ),
    taintedConnectorFlowDecision:
      [...layers]
        .reverse()
        .find((layer) => layer.toolProtocol?.taintedConnectorFlowDecision)
        ?.toolProtocol?.taintedConnectorFlowDecision ?? "block",
    allowLoopbackCallbacksInDev: mergeBooleans(
      layers,
      (layer) => layer.toolProtocol?.allowLoopbackCallbacksInDev,
      false
    ),
    enableDocumentHandoff: mergeBooleans(
      layers,
      (layer) => layer.artifacts?.enableDocumentHandoff,
      true
    ),
    quarantineOnHiddenTextMismatch: mergeBooleans(
      layers,
      (layer) => layer.artifacts?.quarantineOnHiddenTextMismatch,
      true
    ),
    encryptedAttachmentDecision:
      [...layers]
        .reverse()
        .find((layer) => layer.artifacts?.encryptedAttachmentDecision)
        ?.artifacts?.encryptedAttachmentDecision ?? "quarantine",
    replayBundle: mergeBooleans(layers, (layer) => layer.telemetry?.replayBundle, true),
    redactSensitiveValues: mergeBooleans(
      layers,
      (layer) => layer.telemetry?.redactSensitiveValues,
      true
    ),
    telemetrySampling,
    compiledAt: new Date().toISOString()
  };
}


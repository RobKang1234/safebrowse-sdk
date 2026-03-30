import { randomUUID } from "node:crypto";

import type {
  CapabilityDescriptorV5,
  CapabilityUseRequestV5,
  CompiledObservationV5,
  PlannerViewV5,
  SafeVerdict,
  TaskSession,
  VerifiedRegistryEntry
} from "./types.js";
import { clamp, normalizeOrigin, sha256Hex, stableStringify, uniq } from "./utils.js";

function parameterTypeMatches(expected: unknown, actual: unknown): boolean {
  if (expected === "string") {
    return typeof actual === "string";
  }
  if (expected === "boolean") {
    return typeof actual === "boolean";
  }
  if (expected === "number") {
    return typeof actual === "number";
  }
  if (expected === "none") {
    return actual === undefined;
  }
  return true;
}

function createCapabilityDigests(
  capability: Omit<CapabilityDescriptorV5, "capabilityDigest" | "semanticDigest">
): Pick<CapabilityDescriptorV5, "capabilityDigest" | "semanticDigest"> {
  const semanticDigest = sha256Hex(
    stableStringify({
      kind: capability.kind,
      targetClass: capability.targetClass,
      originBoundTo: capability.originBoundTo,
      targetOrigin: capability.targetOrigin,
      targetUrl: capability.targetUrl ?? null,
      selector: capability.selector ?? null,
      sourceObservationId: capability.sourceObservationId,
      sourceDigest: capability.sourceDigest,
      sourceSpanIds: capability.sourceSpanIds,
      sourceNodePathHash: capability.sourceNodePathHash ?? null,
      mintedFromChannels: capability.mintedFromChannels,
      visibleOnlyFlag: capability.visibleOnlyFlag,
      derivedSinkClass: capability.derivedSinkClass,
      derivedSensitiveSink: capability.derivedSensitiveSink,
      registryEntryId: capability.registryEntryId ?? null,
      connectorId: capability.connectorId ?? null,
      requestedScopes: capability.requestedScopes ?? [],
      callbackUri: capability.callbackUri ?? null,
      callbackOrigin: capability.callbackOrigin ?? null,
      memoryRecordId: capability.memoryRecordId ?? null,
      parameterSchema: capability.parameterSchema
    })
  );

  const capabilityDigest = sha256Hex(
    stableStringify({
      sessionId: capability.sessionId,
      workflowHash: capability.workflowHash,
      workflowStep: capability.workflowStep,
      semanticDigest,
      expiresAt: capability.expiresAt
    })
  );

  return {
    capabilityDigest,
    semanticDigest
  };
}

function allSourceSpansVisible(
  observation: CompiledObservationV5,
  sourceSpanIds: string[]
): boolean {
  const spans = observation.spans.filter((span) => sourceSpanIds.includes(span.spanId));
  return (
    spans.length > 0 &&
    spans.every(
      (span) =>
        span.visibilityClass === "visible" &&
        span.visibleOnlyFlag === true &&
        !span.blockedForAuthority &&
        !["hidden_text", "comment", "metadata", "annotation", "schema", "memory_candidate"].includes(
          span.channel
        )
    )
  );
}

export function mintCapabilitiesForObservationV5(
  session: TaskSession,
  observation: CompiledObservationV5,
  plannerView: PlannerViewV5,
  options: {
    ttlSeconds?: number;
    verifiedRegistryEntry?: VerifiedRegistryEntry;
    connectorId?: string;
    requestedScopes?: string[];
    callbackUri?: string;
    callbackOrigin?: string;
  } = {}
): CapabilityDescriptorV5[] {
  if (
    observation.parseStatus !== "compiled" ||
    !observation.authorityEligible ||
    plannerView.blockedChannels.length > 0 ||
    observation.secretFindings.length > 0
  ) {
    return [];
  }

  const createdAt = Date.now();
  const expiresAt = new Date(createdAt + (options.ttlSeconds ?? 120) * 1000).toISOString();

  return observation.extractedTargets.flatMap<CapabilityDescriptorV5>((target) => {
    if (
      target.kind === "navigate" &&
      target.href &&
      session.allowedOrigins.includes(target.targetOrigin) &&
      session.allowedVerbs.includes("navigate") &&
      target.visibleOnlyFlag === true &&
      allSourceSpansVisible(observation, target.sourceSpanIds)
    ) {
      const base: Omit<CapabilityDescriptorV5, "capabilityDigest" | "semanticDigest"> = {
        capabilityId: randomUUID(),
        sessionId: session.sessionId,
        workflowHash: session.workflowHash,
        workflowStep: session.currentStep,
        kind: "navigate",
        targetClass: "browser_navigation",
        originBoundTo: normalizeOrigin(target.sourceOrigin),
        targetOrigin: normalizeOrigin(target.targetOrigin),
        targetUrl: target.href,
        selector: target.selector,
        sourceObservationId: observation.observationId,
        sourceDigest: observation.sourceDigest,
        frameOrigins: uniq([normalizeOrigin(target.frameOrigin)]),
        sourceSpanIds: target.sourceSpanIds,
        sourceNodePathHash: target.sourceNodePathHash,
        mintedFromChannels: target.sourceChannelSet ?? ["link"],
        visibleOnlyFlag: true,
        parameterSchema: {
          openInNewTab: "boolean"
        },
        derivedSinkClass: "browser_navigation",
        derivedSensitiveSink: false,
        expiresAt,
        nonReplayable: true,
        title: target.displayText || target.href
      };
      return [
        {
          ...base,
          ...createCapabilityDigests(base)
        }
      ];
    }

    if (
      target.kind === "connector_prepare" &&
      session.allowedVerbs.includes("connector_prepare") &&
      target.visibleOnlyFlag === true &&
      allSourceSpansVisible(observation, target.sourceSpanIds) &&
      options.verifiedRegistryEntry
    ) {
      const entry = options.verifiedRegistryEntry;
      const connectorId = options.connectorId ?? entry.adapterId;
      const callbackUri = options.callbackUri ?? entry.allowedRedirectUris[0];
      const callbackOrigin = options.callbackOrigin ?? entry.allowedCallbackOrigins[0];
      const base: Omit<CapabilityDescriptorV5, "capabilityDigest" | "semanticDigest"> = {
        capabilityId: randomUUID(),
        sessionId: session.sessionId,
        workflowHash: session.workflowHash,
        workflowStep: session.currentStep,
        kind: "connector_prepare",
        targetClass: "connector",
        originBoundTo: normalizeOrigin(target.sourceOrigin),
        targetOrigin: normalizeOrigin(callbackOrigin ?? target.targetOrigin),
        selector: target.selector,
        sourceObservationId: observation.observationId,
        sourceDigest: observation.sourceDigest,
        frameOrigins: uniq([normalizeOrigin(target.frameOrigin)]),
        sourceSpanIds: target.sourceSpanIds,
        sourceNodePathHash: target.sourceNodePathHash,
        mintedFromChannels: target.sourceChannelSet ?? ["link"],
        visibleOnlyFlag: true,
        parameterSchema: {},
        derivedSinkClass:
          entry.sinkSensitivity === "external_sensitive_sink"
            ? "connector_oauth"
            : "connector_oauth",
        derivedSensitiveSink: Boolean(
          entry.writeCapability || entry.sinkSensitivity === "external_sensitive_sink"
        ),
        registryEntryId: entry.registryEntryId,
        connectorId,
        requestedScopes: options.requestedScopes ?? entry.allowedScopes,
        callbackUri,
        callbackOrigin,
        expiresAt,
        nonReplayable: true,
        title: `Prepare connector: ${connectorId}`
      };
      return [
        {
          ...base,
          ...createCapabilityDigests(base)
        }
      ];
    }

    return [];
  });
}

export function mintMemoryPromotionCapabilityV5(
  session: TaskSession,
  record: {
    recordId: string;
    sourceDigest?: string;
    sourceObservationId?: string;
    key: string;
    valueDigest: string;
  },
  ttlSeconds = 120
): CapabilityDescriptorV5 {
  const expiresAt = new Date(Date.now() + ttlSeconds * 1000).toISOString();
  const base: Omit<CapabilityDescriptorV5, "capabilityDigest" | "semanticDigest"> = {
    capabilityId: randomUUID(),
    sessionId: session.sessionId,
    workflowHash: session.workflowHash,
    workflowStep: session.currentStep,
    kind: "memory_promote",
    targetClass: "memory_promotion",
    originBoundTo: "memory://candidate",
    targetOrigin: "memory://trusted",
    sourceObservationId: record.sourceObservationId ?? "memory-candidate",
    sourceDigest: record.sourceDigest ?? record.valueDigest,
    frameOrigins: ["memory://candidate"],
    sourceSpanIds: [],
    mintedFromChannels: ["memory_candidate"],
    visibleOnlyFlag: false,
    parameterSchema: {},
    derivedSinkClass: "memory_promotion",
    derivedSensitiveSink: true,
    memoryRecordId: record.recordId,
    expiresAt,
    nonReplayable: true,
    title: `Promote memory: ${record.key}`
  };

  return {
    ...base,
    ...createCapabilityDigests(base)
  };
}

export function evaluateCapabilityUseV5(
  request: CapabilityUseRequestV5,
  session: TaskSession | undefined,
  capability: CapabilityDescriptorV5 | undefined,
  usageState: {
    alreadyUsed: boolean;
  }
): SafeVerdict {
  const reasonCodes: string[] = [];
  let decision: SafeVerdict["decision"] = "ALLOW";
  let riskScore = 0.15;

  if (!session) {
    decision = "BLOCK";
    reasonCodes.push("UNKNOWN_SESSION");
    riskScore = 0.99;
  }

  if (!capability) {
    decision = "BLOCK";
    reasonCodes.push(usageState.alreadyUsed ? "CAPABILITY_REPLAYED" : "UNKNOWN_CAPABILITY");
    riskScore = 0.99;
  }

  if (session && capability) {
    if (capability.sessionId !== session.sessionId) {
      decision = "BLOCK";
      reasonCodes.push("CAPABILITY_OUTSIDE_SESSION");
      riskScore = 0.99;
    }
    if (capability.workflowHash !== session.workflowHash) {
      decision = "BLOCK";
      reasonCodes.push("CAPABILITY_WORKFLOW_HASH_MISMATCH");
      riskScore = 0.99;
    }
    if (capability.workflowStep !== session.currentStep) {
      decision = "BLOCK";
      reasonCodes.push("CAPABILITY_OUTSIDE_WORKFLOW_STEP");
      riskScore = 0.99;
    }
  }

  if (capability) {
    if (request.capabilityDigest !== capability.capabilityDigest) {
      decision = "BLOCK";
      reasonCodes.push("CAPABILITY_DIGEST_MISMATCH");
      riskScore = 0.99;
    }
    if (new Date(capability.expiresAt).getTime() <= Date.now()) {
      decision = "BLOCK";
      reasonCodes.push("CAPABILITY_EXPIRED");
      riskScore = 0.99;
    }
    if (usageState.alreadyUsed) {
      decision = "BLOCK";
      reasonCodes.push("CAPABILITY_REPLAYED");
      riskScore = 0.99;
    }

    const parameters = request.parameters ?? {};
    for (const key of Object.keys(parameters)) {
      if (!(key in capability.parameterSchema)) {
        decision = "BLOCK";
        reasonCodes.push("CAPABILITY_PARAMETER_NOT_ALLOWED");
        riskScore = 0.98;
      }
    }
    for (const [key, schema] of Object.entries(capability.parameterSchema)) {
      if (!(key in parameters)) {
        continue;
      }
      if (!parameterTypeMatches(schema, parameters[key])) {
        decision = "BLOCK";
        reasonCodes.push("CAPABILITY_PARAMETER_SCHEMA_MISMATCH");
        riskScore = 0.98;
        break;
      }
    }
  }

  return {
    decision,
    reasonCodes: uniq(reasonCodes),
    riskScore: clamp(riskScore),
    safeConstraints: capability
      ? {
          capability_id: capability.capabilityId,
          capability_digest: capability.capabilityDigest,
          semantic_digest: capability.semanticDigest,
          target_class: capability.targetClass,
          target_origin: capability.targetOrigin,
          derived_sink_class: capability.derivedSinkClass,
          derived_sensitive_sink: capability.derivedSensitiveSink,
          claim_profile: "secure_v5"
        }
      : {
          claim_profile: "secure_v5"
        },
    telemetryTags: uniq(["capability_v5", request.capabilityId, decision.toLowerCase()])
  };
}

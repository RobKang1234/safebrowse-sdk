import { randomUUID } from "node:crypto";

import type {
  ApprovalEnvelopeV6,
  CapabilityDescriptorV6,
  CapabilityUseRequestV6,
  CompiledObservationV6,
  PlannerViewV6,
  SafeVerdict,
  TaskSession,
  TargetPathClass,
  VerifiedRegistryEntry
} from "./types.js";
import {
  classifyTargetPathClass,
  pathClassAllowedForSession,
  pathClassDenied,
  pathClassRequiresApprovalForSession
} from "./pathPolicyV6.js";
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

function createAuthorityDigests(
  authority: Omit<CapabilityDescriptorV6, "capabilityDigest" | "semanticDigest">
): Pick<CapabilityDescriptorV6, "capabilityDigest" | "semanticDigest"> {
  const semanticDigest = sha256Hex(
    stableStringify({
      kind: authority.kind,
      targetClass: authority.targetClass,
      targetPathClass: authority.targetPathClass,
      requiresApproval: authority.requiresApproval,
      originBoundTo: authority.originBoundTo,
      targetOrigin: authority.targetOrigin,
      targetUrl: authority.targetUrl ?? null,
      selector: authority.selector ?? null,
      sourceObservationId: authority.sourceObservationId,
      sourceDigest: authority.sourceDigest,
      sourceSpanIds: authority.sourceSpanIds,
      sourceNodePathHash: authority.sourceNodePathHash ?? null,
      mintedFromChannels: authority.mintedFromChannels,
      visibleOnlyFlag: authority.visibleOnlyFlag,
      derivedSinkClass: authority.derivedSinkClass,
      derivedSensitiveSink: authority.derivedSensitiveSink,
      evidenceSpanIds: authority.evidenceSpanIds,
      registryEntryId: authority.registryEntryId ?? null,
      registryBundleId: authority.registryBundleId ?? null,
      registryBundleVersion: authority.registryBundleVersion ?? null,
      registrySigner: authority.registrySigner ?? null,
      connectorId: authority.connectorId ?? null,
      requestedScopes: authority.requestedScopes ?? [],
      callbackUri: authority.callbackUri ?? null,
      callbackOrigin: authority.callbackOrigin ?? null,
      manifestHash: authority.manifestHash ?? null,
      schemaHash: authority.schemaHash ?? null,
      memoryRecordId: authority.memoryRecordId ?? null,
      parameterSchema: authority.parameterSchema
    })
  );

  const capabilityDigest = sha256Hex(
    stableStringify({
      sessionId: authority.sessionId,
      workflowHash: authority.workflowHash,
      workflowStep: authority.workflowStep,
      semanticDigest,
      expiresAt: authority.expiresAt
    })
  );

  return {
    capabilityDigest,
    semanticDigest
  };
}

function allSourceSpansVisible(
  observation: CompiledObservationV6,
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

function isSubsetSafe(requested: string[] | undefined, allowed: string[]): boolean {
  const requestedSet = new Set((requested ?? []).map((scope) => scope.trim()).filter(Boolean));
  const allowedSet = new Set(allowed.map((scope) => scope.trim()).filter(Boolean));
  for (const scope of requestedSet) {
    if (!allowedSet.has(scope)) {
      return false;
    }
  }
  return true;
}

function isExactAllowedUri(uri: string | undefined, allowedUris: string[]): boolean {
  if (!uri) {
    return false;
  }
  return allowedUris.includes(uri);
}

function registryEntryActive(entry: VerifiedRegistryEntry): boolean {
  if (!entry.expiresAt) {
    return true;
  }
  return new Date(entry.expiresAt).getTime() > Date.now();
}

function buildNavigateAuthority(input: {
  session: TaskSession;
  observation: CompiledObservationV6;
  target: CompiledObservationV6["extractedTargets"][number];
  ttlSeconds: number;
}): CapabilityDescriptorV6 | undefined {
  const { session, observation, target, ttlSeconds } = input;
  if (
    target.kind !== "navigate" ||
    !target.href ||
    !session.allowedOrigins.includes(target.targetOrigin) ||
    !session.allowedVerbs.includes("navigate") ||
    target.visibleOnlyFlag !== true ||
    !allSourceSpansVisible(observation, target.sourceSpanIds)
  ) {
    return undefined;
  }

  const targetPathClass = classifyTargetPathClass({
    targetUrl: target.href,
    displayText: target.displayText,
    selector: target.selector
  });
  if (pathClassDenied(targetPathClass)) {
    return undefined;
  }

  const allowedForSession = pathClassAllowedForSession(session, targetPathClass);
  const requiresApproval = pathClassRequiresApprovalForSession(session, targetPathClass);
  if (!allowedForSession) {
    return undefined;
  }

  const expiresAt = new Date(Date.now() + ttlSeconds * 1000).toISOString();
  const base: Omit<CapabilityDescriptorV6, "capabilityDigest" | "semanticDigest"> = {
    capabilityId: randomUUID(),
    sessionId: session.sessionId,
    workflowHash: session.workflowHash,
    workflowStep: session.currentStep,
    kind: "navigate",
    targetClass: "browser_navigation",
    targetPathClass,
    requiresApproval,
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
    derivedSensitiveSink: requiresApproval,
    evidenceSpanIds: target.sourceSpanIds,
    expiresAt,
    nonReplayable: true,
    title: target.displayText || target.href
  };

  return {
    ...base,
    ...createAuthorityDigests(base)
  };
}

function buildConnectorAuthority(input: {
  session: TaskSession;
  observation: CompiledObservationV6;
  target: CompiledObservationV6["extractedTargets"][number];
  ttlSeconds: number;
  verifiedRegistryEntry: VerifiedRegistryEntry;
  registryEntryId?: string;
  connectorId?: string;
  requestedScopes?: string[];
  callbackUri?: string;
  callbackOrigin?: string;
  manifestAuthType?: "none" | "oauth" | "api_key";
  manifestHash?: string;
  schemaHash?: string;
}): CapabilityDescriptorV6 | undefined {
  const {
    session,
    observation,
    target,
    ttlSeconds,
    verifiedRegistryEntry: entry,
    registryEntryId,
    connectorId,
    requestedScopes,
    callbackUri,
    callbackOrigin,
    manifestAuthType,
    manifestHash,
    schemaHash
  } = input;

  if (
    target.kind !== "connector_prepare" ||
    !session.allowedVerbs.includes("connector_prepare") ||
    target.visibleOnlyFlag !== true ||
    !allSourceSpansVisible(observation, target.sourceSpanIds) ||
    !pathClassAllowedForSession(session, "connector_setup")
  ) {
    return undefined;
  }

  const normalizedCallbackOrigin =
    callbackOrigin ?? (callbackUri ? normalizeOrigin(callbackUri) : undefined);
  const requested = uniq(requestedScopes ?? []);
  const connectorBindingValid =
    registryEntryActive(entry) &&
    (!registryEntryId || registryEntryId === entry.registryEntryId) &&
    ((connectorId ?? entry.adapterId) === entry.adapterId || (connectorId ?? entry.adapterId) === entry.registryEntryId) &&
    manifestAuthType === entry.authType &&
    isSubsetSafe(requested, entry.allowedScopes) &&
    isExactAllowedUri(callbackUri, entry.allowedRedirectUris) &&
    Boolean(normalizedCallbackOrigin) &&
    entry.allowedCallbackOrigins.includes(normalizeOrigin(normalizedCallbackOrigin ?? "")) &&
    normalizeOrigin(callbackUri ?? "") === normalizeOrigin(normalizedCallbackOrigin ?? "") &&
    (manifestHash === undefined || manifestHash === entry.manifestHash) &&
    (schemaHash === undefined || schemaHash === entry.schemaHash);
  if (!connectorBindingValid) {
    return undefined;
  }

  const expiresAt = new Date(Date.now() + ttlSeconds * 1000).toISOString();
  const base: Omit<CapabilityDescriptorV6, "capabilityDigest" | "semanticDigest"> = {
    capabilityId: randomUUID(),
    sessionId: session.sessionId,
    workflowHash: session.workflowHash,
    workflowStep: session.currentStep,
    kind: "connector_prepare",
    targetClass: "connector",
    targetPathClass: "connector_setup",
    requiresApproval: true,
    originBoundTo: normalizeOrigin(target.sourceOrigin),
    targetOrigin: normalizeOrigin(normalizedCallbackOrigin ?? target.targetOrigin),
    selector: target.selector,
    sourceObservationId: observation.observationId,
    sourceDigest: observation.sourceDigest,
    frameOrigins: uniq([normalizeOrigin(target.frameOrigin)]),
    sourceSpanIds: target.sourceSpanIds,
    sourceNodePathHash: target.sourceNodePathHash,
    mintedFromChannels: target.sourceChannelSet ?? ["visible_text"],
    visibleOnlyFlag: true,
    parameterSchema: {},
    derivedSinkClass: "connector_oauth",
    derivedSensitiveSink: true,
    evidenceSpanIds: target.sourceSpanIds,
    registryEntryId: entry.registryEntryId,
    registryBundleId: entry.bundleId,
    registryBundleVersion: entry.bundleVersion,
    registrySigner: entry.signer,
    connectorId: entry.adapterId,
    requestedScopes: requested,
    callbackUri,
    callbackOrigin: normalizeOrigin(normalizedCallbackOrigin ?? ""),
    manifestHash,
    schemaHash,
    expiresAt,
    nonReplayable: true,
    title: `Prepare connector: ${entry.adapterId}`
  };

  return {
    ...base,
    ...createAuthorityDigests(base)
  };
}

export function mintCapabilitiesForObservationV6(
  session: TaskSession,
  observation: CompiledObservationV6,
  plannerView: PlannerViewV6,
  options: {
    ttlSeconds?: number;
    verifiedRegistryEntry?: VerifiedRegistryEntry;
    registryEntryId?: string;
    connectorId?: string;
    requestedScopes?: string[];
    callbackUri?: string;
    callbackOrigin?: string;
    manifestAuthType?: "none" | "oauth" | "api_key";
    manifestHash?: string;
    schemaHash?: string;
  } = {}
): CapabilityDescriptorV6[] {
  if (
    observation.parseStatus !== "compiled" ||
    !observation.authorityEligible ||
    plannerView.blockedChannels.length > 0 ||
    observation.secretFindings.length > 0
  ) {
    return [];
  }

  const ttlSeconds = options.ttlSeconds ?? 120;
  return observation.extractedTargets.flatMap<CapabilityDescriptorV6>((target) => {
    const navigateAuthority = buildNavigateAuthority({
      session,
      observation,
      target,
      ttlSeconds
    });
    if (navigateAuthority) {
      return [navigateAuthority];
    }

    if (target.kind === "connector_prepare" && options.verifiedRegistryEntry) {
      const connectorAuthority = buildConnectorAuthority({
        session,
        observation,
        target,
        ttlSeconds,
        verifiedRegistryEntry: options.verifiedRegistryEntry,
        registryEntryId: options.registryEntryId,
        connectorId: options.connectorId,
        requestedScopes: options.requestedScopes,
        callbackUri: options.callbackUri,
        callbackOrigin: options.callbackOrigin,
        manifestAuthType: options.manifestAuthType,
        manifestHash: options.manifestHash,
        schemaHash: options.schemaHash
      });
      return connectorAuthority ? [connectorAuthority] : [];
    }

    return [];
  });
}

export function mintMemoryPromotionCapabilityV6(
  session: TaskSession,
  record: {
    recordId: string;
    sourceDigest?: string;
    sourceObservationId?: string;
    key: string;
    valueDigest: string;
  },
  ttlSeconds = 120
): CapabilityDescriptorV6 {
  const expiresAt = new Date(Date.now() + ttlSeconds * 1000).toISOString();
  const base: Omit<CapabilityDescriptorV6, "capabilityDigest" | "semanticDigest"> = {
    capabilityId: randomUUID(),
    sessionId: session.sessionId,
    workflowHash: session.workflowHash,
    workflowStep: session.currentStep,
    kind: "memory_promote",
    targetClass: "memory_promotion",
    targetPathClass: "workflow_continue",
    requiresApproval: true,
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
    evidenceSpanIds: [],
    memoryRecordId: record.recordId,
    expiresAt,
    nonReplayable: true,
    title: `Promote memory: ${record.key}`
  };

  return {
    ...base,
    ...createAuthorityDigests(base)
  };
}

function approvalMatchesAuthority(
  authority: CapabilityDescriptorV6,
  approvalEnvelope: ApprovalEnvelopeV6 | undefined
): boolean {
  if (!approvalEnvelope) {
    return false;
  }
  if (approvalEnvelope.capabilityId !== authority.capabilityId) {
    return false;
  }
  if (approvalEnvelope.capabilityDigest !== authority.capabilityDigest) {
    return false;
  }
  if (approvalEnvelope.workflowStep !== authority.workflowStep) {
    return false;
  }
  if (approvalEnvelope.consumedAt) {
    return false;
  }
  if (new Date(approvalEnvelope.expiresAt).getTime() <= Date.now()) {
    return false;
  }
  if (authority.kind === "navigate") {
    return (
      approvalEnvelope.sinkClass === "browser_navigation" &&
      approvalEnvelope.targetPathClass === authority.targetPathClass
    );
  }
  if (authority.kind === "connector_prepare") {
    return approvalEnvelope.sinkClass === "connector_oauth";
  }
  return approvalEnvelope.sinkClass === "memory_promotion";
}

export function evaluateCapabilityUseV6(
  request: CapabilityUseRequestV6,
  session: TaskSession | undefined,
  authority: CapabilityDescriptorV6 | undefined,
  usageState: {
    alreadyUsed: boolean;
    approvalEnvelope?: ApprovalEnvelopeV6;
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
  if (!authority) {
    decision = "BLOCK";
    reasonCodes.push(usageState.alreadyUsed ? "AUTHORITY_REPLAYED" : "UNKNOWN_AUTHORITY");
    riskScore = 0.99;
  }

  if (session && authority) {
    if (authority.sessionId !== session.sessionId) {
      decision = "BLOCK";
      reasonCodes.push("AUTHORITY_OUTSIDE_SESSION");
      riskScore = 0.99;
    }
    if (authority.workflowHash !== session.workflowHash) {
      decision = "BLOCK";
      reasonCodes.push("AUTHORITY_WORKFLOW_HASH_MISMATCH");
      riskScore = 0.99;
    }
    if (authority.workflowStep !== session.currentStep) {
      decision = "BLOCK";
      reasonCodes.push("AUTHORITY_OUTSIDE_WORKFLOW_STEP");
      riskScore = 0.99;
    }
  }

  if (authority) {
    if (authority.consumedAt || usageState.alreadyUsed) {
      decision = "BLOCK";
      reasonCodes.push("AUTHORITY_REPLAYED");
      riskScore = 0.99;
    }
    if (request.authorityDigest !== authority.capabilityDigest) {
      decision = "BLOCK";
      reasonCodes.push("AUTHORITY_DIGEST_MISMATCH");
      riskScore = 0.99;
    }
    if (new Date(authority.expiresAt).getTime() <= Date.now()) {
      decision = "BLOCK";
      reasonCodes.push("AUTHORITY_EXPIRED");
      riskScore = 0.99;
    }

    const parameters = request.parameters ?? {};
    for (const key of Object.keys(parameters)) {
      if (!(key in authority.parameterSchema)) {
        decision = "BLOCK";
        reasonCodes.push("AUTHORITY_PARAMETER_NOT_ALLOWED");
        riskScore = 0.98;
      }
    }
    for (const [key, schema] of Object.entries(authority.parameterSchema)) {
      if (!(key in parameters)) {
        continue;
      }
      if (!parameterTypeMatches(schema, parameters[key])) {
        decision = "BLOCK";
        reasonCodes.push("AUTHORITY_PARAMETER_SCHEMA_MISMATCH");
        riskScore = 0.98;
        break;
      }
    }

    if (decision === "ALLOW" && authority.requiresApproval) {
      if (!usageState.approvalEnvelope) {
        decision = "APPROVAL_REQUIRED";
        reasonCodes.push("APPROVAL_ENVELOPE_REQUIRED");
        riskScore = 0.7;
      } else if (!approvalMatchesAuthority(authority, usageState.approvalEnvelope)) {
        decision = "BLOCK";
        reasonCodes.push("APPROVAL_ENVELOPE_MISMATCH");
        riskScore = 0.99;
      }
    }
  }

  return {
    decision,
    reasonCodes: uniq(reasonCodes),
    riskScore: clamp(riskScore),
    safeConstraints: authority
      ? {
          capability_id: authority.capabilityId,
          capability_digest: authority.capabilityDigest,
          semantic_digest: authority.semanticDigest,
          target_class: authority.targetClass,
          target_path_class: authority.targetPathClass,
          target_origin: authority.targetOrigin,
          requires_approval: authority.requiresApproval,
          derived_sink_class: authority.derivedSinkClass,
          derived_sensitive_sink: authority.derivedSensitiveSink,
          claim_profile: "secure_v6"
        }
      : {
          claim_profile: "secure_v6"
        },
    telemetryTags: uniq(["authority_v6", request.authorityId, decision.toLowerCase()])
  };
}

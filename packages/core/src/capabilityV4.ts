import { randomUUID } from "node:crypto";

import type {
  CapabilityDescriptor,
  CapabilityUseRequest,
  CompiledObservation,
  SafeVerdict,
  StructuredPlannerInput,
  TaskSession
} from "./types.js";
import { clamp, normalizeOrigin, uniq } from "./utils.js";

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

export function mintCapabilitiesForObservation(
  session: TaskSession,
  observation: CompiledObservation,
  options: {
    ttlSeconds?: number;
    sourceObservationId?: string;
  } = {}
): CapabilityDescriptor[] {
  const createdAt = new Date();
  const expiresAt = new Date(createdAt.getTime() + (options.ttlSeconds ?? 120) * 1_000).toISOString();

  return observation.extractedTargets.flatMap<CapabilityDescriptor>((target) => {
      if (
        target.kind === "navigate" &&
        target.href &&
        session.allowedOrigins.includes(target.targetOrigin) &&
        session.allowedVerbs.includes("navigate")
      ) {
        return [
          {
            capabilityId: randomUUID(),
            sessionId: session.sessionId,
            workflowStep: session.currentStep,
            kind: "navigate",
            targetClass: "browser_navigation",
            originBoundTo: normalizeOrigin(target.sourceOrigin),
            targetOrigin: normalizeOrigin(target.targetOrigin),
            targetUrl: target.href,
            selector: target.selector,
            sourceObservationId: options.sourceObservationId ?? observation.observationId,
            sourceDigest: observation.sourceDigest,
            frameOrigins: uniq([normalizeOrigin(target.frameOrigin)]),
            sourceSpanIds: target.sourceSpanIds,
            parameterSchema: {
              openInNewTab: "boolean"
            },
            expiresAt,
            nonReplayable: true,
            workflowHash: session.workflowHash,
            title: target.displayText || target.href || target.targetOrigin
          }
        ];
      }

      if (
        target.kind === "connector_prepare" &&
        session.allowedOrigins.includes(target.targetOrigin) &&
        session.allowedVerbs.includes("connector_prepare")
      ) {
        return [
          {
            capabilityId: randomUUID(),
            sessionId: session.sessionId,
            workflowStep: session.currentStep,
            kind: "connector_prepare",
            targetClass: "connector",
            originBoundTo: normalizeOrigin(target.sourceOrigin),
            targetOrigin: normalizeOrigin(target.targetOrigin),
            selector: target.selector,
            sourceObservationId: options.sourceObservationId ?? observation.observationId,
            sourceDigest: observation.sourceDigest,
            frameOrigins: uniq([normalizeOrigin(target.frameOrigin)]),
            sourceSpanIds: target.sourceSpanIds,
            parameterSchema: {},
            expiresAt,
            nonReplayable: true,
            workflowHash: session.workflowHash,
            title: `Prepare connector: ${target.displayText || target.targetOrigin}`
          }
        ];
      }

      return [];
    });
}

export function attachCapabilitiesToPlannerInput(
  plannerInput: StructuredPlannerInput,
  capabilities: CapabilityDescriptor[]
): StructuredPlannerInput {
  return {
    ...plannerInput,
    candidateCapabilities: capabilities.map((capability) => ({
      capabilityId: capability.capabilityId,
      title: capability.title,
      kind: capability.kind,
      parameterSchema: capability.parameterSchema,
      expiresAt: capability.expiresAt
    }))
  };
}

export function evaluateCapabilityUse(
  request: CapabilityUseRequest,
  session: TaskSession | undefined,
  capability: CapabilityDescriptor | undefined,
  usageState: {
    alreadyUsed: boolean;
  }
): SafeVerdict {
  const reasonCodes: string[] = [];
  let decision: SafeVerdict["decision"] = "ALLOW";
  let riskScore = 0.2;

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

    if (capability.workflowStep !== session.currentStep) {
      decision = "BLOCK";
      reasonCodes.push("CAPABILITY_OUTSIDE_WORKFLOW_STEP");
      riskScore = Math.max(riskScore, 0.99);
    }

    if (capability.workflowHash !== session.workflowHash) {
      decision = "BLOCK";
      reasonCodes.push("CAPABILITY_WORKFLOW_HASH_MISMATCH");
      riskScore = Math.max(riskScore, 0.99);
    }
  }

  if (capability) {
    if (new Date(capability.expiresAt).getTime() <= Date.now()) {
      decision = "BLOCK";
      reasonCodes.push("CAPABILITY_EXPIRED");
      riskScore = Math.max(riskScore, 0.99);
    }

    if (usageState.alreadyUsed) {
      decision = "BLOCK";
      reasonCodes.push("CAPABILITY_REPLAYED");
      riskScore = Math.max(riskScore, 0.99);
    }

    if (request.sourceObservationId !== capability.sourceObservationId) {
      decision = "BLOCK";
      reasonCodes.push("CAPABILITY_OBSERVATION_MISMATCH");
      riskScore = Math.max(riskScore, 0.98);
    }

    if (request.sourceDigest !== capability.sourceDigest) {
      decision = "BLOCK";
      reasonCodes.push("CAPABILITY_SOURCE_DIGEST_MISMATCH");
      riskScore = Math.max(riskScore, 0.98);
    }

    const parameters = request.parameters ?? {};
    for (const key of Object.keys(parameters)) {
      if (!(key in capability.parameterSchema)) {
        decision = "BLOCK";
        reasonCodes.push("CAPABILITY_PARAMETER_NOT_ALLOWED");
        riskScore = Math.max(riskScore, 0.98);
      }
    }

    for (const [key, schema] of Object.entries(capability.parameterSchema)) {
      if (!(key in parameters)) {
        continue;
      }
      if (!parameterTypeMatches(schema, parameters[key])) {
        decision = "BLOCK";
        reasonCodes.push("CAPABILITY_PARAMETER_SCHEMA_MISMATCH");
        riskScore = Math.max(riskScore, 0.95);
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
          target_class: capability.targetClass,
          target_origin: capability.targetOrigin,
          non_replayable: true
        }
      : undefined,
    telemetryTags: uniq([
      "capability",
      request.capabilityId,
      decision.toLowerCase()
    ])
  };
}

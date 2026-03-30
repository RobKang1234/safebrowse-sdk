import { randomUUID } from "node:crypto";

import { redactJsonValue } from "./secretIsolation.js";
import type { JsonValue, ReplayBundle, ReplayEvent, RuntimeContext, SafeVerdict } from "./types.js";
import { sha256Hex, stableStringify } from "./utils.js";

function isVerdictPayload(payload: unknown): payload is SafeVerdict {
  return Boolean(payload && typeof payload === "object" && "decision" in payload);
}

export function buildReplayBundle(
  events: ReplayEvent[],
  context: Pick<RuntimeContext, "policy">
): ReplayBundle {
  let blockingDecisions = 0;
  let reviewDecisions = 0;

  for (const event of events) {
    if (isVerdictPayload(event.payload)) {
      if (event.payload.decision === "BLOCK") {
        blockingDecisions += 1;
      }
      if (
        event.payload.decision === "USER_CONFIRM" ||
        event.payload.decision === "REPLAN_READ_ONLY" ||
        event.payload.decision === "QUARANTINE_ARTIFACT"
      ) {
        reviewDecisions += 1;
      }
    }
  }

  const sanitizedEvents = events.map((event) =>
    context.policy.redactSensitiveValues
      ? (redactJsonValue(event as unknown as JsonValue).value as unknown as ReplayEvent)
      : event
  );

  return {
    bundleId: randomUUID(),
    createdAt: new Date().toISOString(),
    policyVersion: context.policy.version,
    profile: context.policy.profile,
    policyLayers: context.policy.layerProvenance,
    eventDigests: sanitizedEvents.map((event) => sha256Hex(stableStringify(event))),
    events: sanitizedEvents.map((event) => ({
      ...event,
      timestamp: event.timestamp ?? new Date().toISOString()
    })),
    metrics: {
      totalEvents: events.length,
      blockingDecisions,
      reviewDecisions
    }
  };
}


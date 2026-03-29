import { randomUUID } from "node:crypto";

import type { ReplayBundle, ReplayEvent, RuntimeContext, SafeVerdict } from "./types.js";
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

  return {
    bundleId: randomUUID(),
    createdAt: new Date().toISOString(),
    policyVersion: context.policy.version,
    profile: context.policy.profile,
    eventDigests: events.map((event) => sha256Hex(stableStringify(event))),
    events: events.map((event) => ({
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


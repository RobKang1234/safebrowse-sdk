import { randomUUID } from "node:crypto";

import { runPromptInjectionGuard } from "./promptInjection.js";
import { normalizeTrustSignals } from "./trust.js";
import type {
  ObservationEnvelope,
  ObservationFragment,
  RawObservationInput,
  RuntimeContext
} from "./types.js";
import { normalizeText, sha256Hex, uniq } from "./utils.js";

export function sanitizeObservation(
  input: RawObservationInput,
  context: Partial<RuntimeContext> = {}
): ObservationEnvelope {
  const trustSignals = normalizeTrustSignals(input.trustSignals);
  const fragments: ObservationFragment[] =
    input.fragments?.map((fragment) => ({
      fragmentId: fragment.fragmentId ?? randomUUID(),
      text: normalizeText(fragment.text),
      visibilityClass: fragment.visibilityClass ?? trustSignals.visibilityClass,
      medium: fragment.medium ?? "text",
      sourceOrigin: fragment.sourceOrigin ?? trustSignals.sourceOrigin,
      frameOrigin: fragment.frameOrigin ?? trustSignals.frameOrigin,
      selector: fragment.selector,
      tainted: fragment.tainted ?? trustSignals.taintClass !== "trusted"
    })) ?? [];

  const text = normalizeText(
    input.text ?? fragments.map((fragment) => fragment.text).join(" ")
  );

  const baseFlags = [
    ...fragments
      .filter((fragment) => fragment.visibilityClass === "hidden")
      .map(() => "hidden_fragment_present"),
    ...fragments
      .filter((fragment) => fragment.visibilityClass === "metadata")
      .map(() => "metadata_fragment_present")
  ];

  const envelope: ObservationEnvelope = {
    observationId: input.observationId ?? randomUUID(),
    taskId: input.taskId,
    sourceType: input.sourceType ?? "page",
    text,
    normalizedText: text.toLowerCase(),
    fragments,
    trustSignals,
    suspicionFlags: uniq(baseFlags),
    matchedPatternIds: [],
    riskScore: 0,
    rawHash: input.rawHash ?? sha256Hex(text),
    createdAt: (context.now?.() ?? new Date()).toISOString()
  };

  const promptGuard = runPromptInjectionGuard(envelope, {
    knowledgeBase: context.knowledgeBase
  });

  return {
    ...envelope,
    suspicionFlags: uniq([...envelope.suspicionFlags, ...promptGuard.suspicionFlags]),
    matchedPatternIds: promptGuard.matchedPatternIds,
    riskScore: promptGuard.riskScore
  };
}


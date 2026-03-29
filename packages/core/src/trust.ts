import { randomUUID } from "node:crypto";

import type { ArtifactKind, ExtractionMethod, TrustSignalSet, VisibilityClass } from "./types.js";
import { normalizeOrigin, sameOriginRelation } from "./utils.js";

export function normalizeTrustSignals(input: Partial<TrustSignalSet> = {}): TrustSignalSet {
  const sourceOrigin = normalizeOrigin(input.sourceOrigin);
  const frameOrigin = normalizeOrigin(input.frameOrigin ?? input.sourceOrigin);
  const relation =
    input.sameOriginRelation ?? sameOriginRelation(sourceOrigin, frameOrigin);

  return {
    sourceOrigin,
    frameOrigin,
    sameOriginRelation: relation,
    visibilityClass: (input.visibilityClass ?? "visible") as VisibilityClass,
    extractionMethod: (input.extractionMethod ?? "dom") as ExtractionMethod,
    artifactKind: (input.artifactKind ?? "page") as ArtifactKind,
    taintClass:
      input.taintClass ??
      (input.userSharedFlag
        ? "user-provided"
        : input.sessionDiscoveredFlag
          ? "session-discovered"
          : "untrusted"),
    approvalBindingId: input.approvalBindingId,
    lineageChain: input.lineageChain?.length ? input.lineageChain : [randomUUID()],
    userSharedFlag: input.userSharedFlag ?? false,
    sessionDiscoveredFlag: input.sessionDiscoveredFlag ?? true
  };
}

export function appendLineage(trustSignals: TrustSignalSet, lineageId: string): TrustSignalSet {
  return {
    ...trustSignals,
    lineageChain: [...trustSignals.lineageChain, lineageId]
  };
}


import { existsSync, readFileSync } from "node:fs";
import { randomUUID } from "node:crypto";

import { normalizeTrustSignals } from "./trust.js";
import type { ArtifactBrokerResult, ArtifactInput, ArtifactKind, RuntimeContext } from "./types.js";
import { clamp, overlapScore, sha256Hex, uniq } from "./utils.js";

function inferArtifactKind(mimeType: string, surfaceKind?: ArtifactKind): ArtifactKind {
  if (surfaceKind) {
    return surfaceKind;
  }
  if (mimeType === "application/pdf") {
    return "pdf";
  }
  if (mimeType.startsWith("image/")) {
    return "image";
  }
  if (mimeType.includes("zip") || mimeType.includes("tar")) {
    return "archive";
  }
  if (mimeType.includes("html")) {
    return "page";
  }
  return "document";
}

function matchArtifactPatterns(
  artifactKind: ArtifactKind,
  mismatchSignals: string[],
  patterns: Array<Record<string, unknown>>
): string[] {
  return patterns
    .filter((pattern) => {
      const surface = String(pattern.surface_kind ?? "").toLowerCase();
      const name = String(pattern.pattern_name ?? "").toLowerCase();
      return (
        surface === artifactKind ||
        (mismatchSignals.length > 0 && name.includes("hidden")) ||
        (artifactKind === "pdf" && surface === "pdf")
      );
    })
    .slice(0, 8)
    .map((pattern) => String(pattern.pattern_id ?? "unknown-artifact-pattern"));
}

export function brokerArtifact(
  input: ArtifactInput,
  context: RuntimeContext
): ArtifactBrokerResult {
  const artifactId = input.artifactId ?? randomUUID();
  const bytes =
    input.bytes ??
    (input.path && existsSync(input.path) ? new Uint8Array(readFileSync(input.path)) : undefined);
  const rendered = input.renderedText ?? "";
  const extracted = input.extractedText ?? "";
  const ocr = input.ocrText ?? "";

  const trustSignals = normalizeTrustSignals({
    artifactKind: inferArtifactKind(input.mimeType, input.surfaceKind),
    extractionMethod: input.extractionMethod ?? "download",
    sourceOrigin: input.sourceOrigin,
    frameOrigin: input.viewerOrigin ?? input.sourceOrigin,
    ...(input.trustSignals ?? {})
  });

  const mismatchSignals: string[] = [];
  if (rendered && extracted && overlapScore(rendered, extracted) < 0.45) {
    mismatchSignals.push("render_vs_text_mismatch");
  }
  if (rendered && ocr && overlapScore(rendered, ocr) < 0.45) {
    mismatchSignals.push("render_vs_ocr_mismatch");
  }

  const metadataSignals = [
    ...(input.annotations?.length ? ["annotation_channel_present"] : []),
    ...(input.metadataText?.some((value) => /ignore previous|system prompt|act as/i.test(value))
      ? ["metadata_instruction_candidate"]
      : [])
  ];

  let decision: ArtifactBrokerResult["verdict"]["decision"] = "ALLOW";
  const reasonCodes: string[] = [];
  let riskScore = 0.2;
  const derivedTaintClass =
    mismatchSignals.length > 0 || metadataSignals.length > 0
      ? "tainted"
      : trustSignals.taintClass;

  if (
    context.policy.allowedMimeTypes.size &&
    !context.policy.allowedMimeTypes.has(input.mimeType.toLowerCase())
  ) {
    decision = "USER_CONFIRM";
    reasonCodes.push("MIME_TYPE_REQUIRES_APPROVAL");
    riskScore = 0.55;
  }

  if (context.policy.quarantineOnHiddenTextMismatch && mismatchSignals.length > 0) {
    decision = "QUARANTINE_ARTIFACT";
    reasonCodes.push("HIDDEN_TEXT_MISMATCH");
    riskScore = 0.9;
  }

  if (metadataSignals.length > 0) {
    decision = decision === "ALLOW" ? "USER_CONFIRM" : decision;
    reasonCodes.push("METADATA_OR_ANNOTATION_RISK");
    riskScore = Math.max(riskScore, 0.6);
  }

  const matchedPatternIds = matchArtifactPatterns(
    trustSignals.artifactKind,
    mismatchSignals,
    context.knowledgeBase?.artifactSurfacePatterns ?? []
  );

  return {
    artifact: {
      artifactId,
      mimeType: input.mimeType.toLowerCase(),
      surfaceKind: trustSignals.artifactKind,
      sourceOrigin: trustSignals.sourceOrigin,
      viewerOrigin: input.viewerOrigin,
      downloadOrigin: input.downloadOrigin,
      extractionMethod: trustSignals.extractionMethod,
      sha256: sha256Hex(bytes ?? new TextEncoder().encode(`${artifactId}:${input.mimeType}`)),
      sizeBytes: bytes?.byteLength ?? 0,
      mismatchSignals: uniq(mismatchSignals),
      metadataSignals: uniq(metadataSignals),
      trustSignals,
      lineageChain: trustSignals.lineageChain,
      derivedTaintClass,
      toolActivationPolicy:
        derivedTaintClass === "tainted"
          ? "block"
          : trustSignals.taintClass === "trusted"
            ? "allow"
            : "user_confirm",
      approvalRequiredForFollowOn: derivedTaintClass !== "trusted",
      createdAt: (context.now?.() ?? new Date()).toISOString()
    },
    verdict: {
      decision,
      reasonCodes: uniq(reasonCodes),
      riskScore: clamp(riskScore),
      safeConstraints: {
        handoff_mode: decision === "ALLOW" ? "artifact_reference" : "quarantine",
        document_handoff_enabled: context.policy.enableDocumentHandoff
      },
      matchedPatternIds,
      incidentPlaybookId: decision === "QUARANTINE_ARTIFACT" ? "IR-03" : undefined,
      telemetryTags: uniq([trustSignals.artifactKind, decision.toLowerCase()])
    }
  };
}


import { randomUUID } from "node:crypto";

import { redactSecretsInText } from "./secretIsolation.js";
import { sanitizeObservation } from "./sanitize.js";
import { normalizeTrustSignals } from "./trust.js";
import type {
  CompiledObservation,
  ExtractedTarget,
  SafeVerdict,
  HtmlSurfaceCapture,
  ParserIsolationReport,
  ProvenanceChannel,
  ProvenanceSpan,
  RuntimeContext,
  StructuredPlannerInput,
  SurfaceCapture,
  SurfaceLinkCapture,
  ToolManifestSurfaceCapture
} from "./types.js";
import { clamp, normalizeOrigin, normalizeText, overlapScore, sha256Hex, uniq } from "./utils.js";

const HTML_COMMENT = /<!--([\s\S]*?)-->/g;
const TITLE_TAG = /<title[^>]*>([\s\S]*?)<\/title>/i;
const META_CONTENT =
  /<meta[^>]+(?:name|property)=["']?([^"'>\s]+)["']?[^>]+content=["']?([^"'>]+)["']?[^>]*>/gi;
const ANCHOR_TAG =
  /<a[^>]+href=["']?([^"'>\s]+)["']?[^>]*>([\s\S]*?)<\/a>/gi;
const HIDDEN_TAG =
  /<([a-z0-9:-]+)[^>]*(?:hidden|aria-hidden=["']?true["']?|style=["'][^"']*(?:display\s*:\s*none|visibility\s*:\s*hidden)[^"']*["'])[^>]*>([\s\S]*?)<\/\1>/gi;
const HIDDEN_BLOCK =
  /<[^>]*(?:hidden|aria-hidden=["']?true["']?|style=["'][^"']*(?:display\s*:\s*none|visibility\s*:\s*hidden)[^"']*["'])[^>]*>[\s\S]*?<\/[^>]+>/gi;
const ALT_ATTR = /\b(?:alt|title|aria-label)=["']([^"']+)["']/gi;
const TAGS = /<[^>]+>/g;
const SCRIPT_STYLE = /<(script|style)[^>]*>[\s\S]*?<\/\1>/gi;

function stripHtmlVisible(input: string): string {
  return normalizeText(
    input
      .replace(SCRIPT_STYLE, " ")
      .replace(HIDDEN_BLOCK, " ")
      .replace(HIDDEN_TAG, " ")
      .replace(HTML_COMMENT, " ")
      .replace(TAGS, " ")
  );
}

function stripHtml(input: string): string {
  return normalizeText(input.replace(SCRIPT_STYLE, " ").replace(HTML_COMMENT, " ").replace(TAGS, " "));
}

function hashSurface(capture: SurfaceCapture): string {
  if ("domDigest" in capture && capture.domDigest) {
    return capture.domDigest;
  }
  if ("sourceDigest" in capture && capture.sourceDigest) {
    return capture.sourceDigest;
  }
  return sha256Hex(
    JSON.stringify({
      surfaceType: capture.surfaceType,
      url: capture.url,
      frameUrl: capture.frameUrl,
      visibleText: "visibleText" in capture ? capture.visibleText : undefined,
      html: "html" in capture ? capture.html : undefined,
      renderedText: "renderedText" in capture ? capture.renderedText : undefined,
      extractedText: "extractedText" in capture ? capture.extractedText : undefined,
      ocrText: "ocrText" in capture ? capture.ocrText : undefined,
      description: "description" in capture ? capture.description : undefined,
      key: "key" in capture ? capture.key : undefined
    })
  );
}

function buildSpan(input: {
  channel: ProvenanceChannel;
  text: string;
  sourceOrigin: string;
  frameOrigin: string;
  visibilityClass: ProvenanceSpan["visibilityClass"];
  extractionMethod: ProvenanceSpan["extractionMethod"];
  taintClass: ProvenanceSpan["taintClass"];
  lineageChain: string[];
  selector?: string;
  supportingDigest?: string;
}): ProvenanceSpan {
  return {
    spanId: randomUUID(),
    channel: input.channel,
    text: normalizeText(input.text),
    sourceOrigin: input.sourceOrigin,
    frameOrigin: input.frameOrigin,
    visibilityClass: input.visibilityClass,
    extractionMethod: input.extractionMethod,
    taintClass: input.taintClass,
    lineageChain: input.lineageChain,
    selector: input.selector,
    supportingDigest: input.supportingDigest
  };
}

function parseHtmlLinks(html: string, fallbackLinks: SurfaceLinkCapture[]): SurfaceLinkCapture[] {
  const links: SurfaceLinkCapture[] = [...fallbackLinks];
  for (const match of html.matchAll(ANCHOR_TAG)) {
    links.push({
      href: match[1],
      text: stripHtml(match[2]),
      selector: `a[href="${match[1]}"]`
    });
  }
  return links;
}

function parseHtmlCapture(
  capture: HtmlSurfaceCapture,
  trustSignals: ReturnType<typeof normalizeTrustSignals>,
  sourceDigest: string
): {
  spans: ProvenanceSpan[];
  extractedFacts: string[];
  extractedTargets: ExtractedTarget[];
  riskFindings: string[];
  blockedChannels: ProvenanceChannel[];
  parseStatus: CompiledObservation["parseStatus"];
} {
  const html = capture.html ?? "";
  const visibleText = normalizeText(capture.visibleText ?? stripHtmlVisible(html));
  const sourceOrigin = normalizeOrigin(capture.url);
  const frameOrigin = normalizeOrigin(capture.frameUrl ?? capture.url);
  const spans: ProvenanceSpan[] = [];
  const extractedFacts: string[] = [];
  const extractedTargets: ExtractedTarget[] = [];
  const riskFindings: string[] = [];
  const blockedChannels: ProvenanceChannel[] = [];
  const nestedUnsupportedComponents = capture.nestedUnsupportedComponents ?? [];

  if (visibleText) {
    spans.push(
      buildSpan({
        channel: "visible_text",
        text: visibleText,
        sourceOrigin,
        frameOrigin,
        visibilityClass: "visible",
        extractionMethod: "dom",
        taintClass: trustSignals.taintClass,
        lineageChain: trustSignals.lineageChain,
        supportingDigest: sourceDigest
      })
    );
  }

  const titleMatch = capture.title || html.match(TITLE_TAG)?.[1];
  if (titleMatch) {
    spans.push(
      buildSpan({
        channel: "metadata",
        text: titleMatch,
        sourceOrigin,
        frameOrigin,
        visibilityClass: "metadata",
        extractionMethod: "dom",
        taintClass: trustSignals.taintClass,
        lineageChain: trustSignals.lineageChain,
        supportingDigest: sourceDigest
      })
    );
    extractedFacts.push(`title: ${normalizeText(titleMatch)}`);
    blockedChannels.push("metadata");
  }

  for (const match of html.matchAll(HTML_COMMENT)) {
    if (!normalizeText(match[1])) {
      continue;
    }
    spans.push(
      buildSpan({
        channel: "comment",
        text: match[1],
        sourceOrigin,
        frameOrigin,
        visibilityClass: "hidden",
        extractionMethod: "dom",
        taintClass: trustSignals.taintClass,
        lineageChain: trustSignals.lineageChain,
        supportingDigest: sourceDigest
      })
    );
    blockedChannels.push("comment");
    riskFindings.push("html_comment_channel_present");
  }

  for (const match of html.matchAll(HIDDEN_TAG)) {
    const hiddenText = stripHtml(match[2]);
    if (!hiddenText) {
      continue;
    }
    spans.push(
      buildSpan({
        channel: "hidden_text",
        text: hiddenText,
        sourceOrigin,
        frameOrigin,
        visibilityClass: "hidden",
        extractionMethod: "dom",
        taintClass: trustSignals.taintClass,
        lineageChain: trustSignals.lineageChain,
        supportingDigest: sourceDigest
      })
    );
    blockedChannels.push("hidden_text");
    riskFindings.push("html_hidden_channel_present");
  }

  for (const value of capture.hiddenText ?? []) {
    if (!normalizeText(value)) {
      continue;
    }
    spans.push(
      buildSpan({
        channel: "hidden_text",
        text: value,
        sourceOrigin,
        frameOrigin,
        visibilityClass: "hidden",
        extractionMethod: "dom",
        taintClass: trustSignals.taintClass,
        lineageChain: trustSignals.lineageChain,
        supportingDigest: sourceDigest
      })
    );
    blockedChannels.push("hidden_text");
  }

  for (const match of html.matchAll(META_CONTENT)) {
    spans.push(
      buildSpan({
        channel: "metadata",
        text: `${match[1]}: ${match[2]}`,
        sourceOrigin,
        frameOrigin,
        visibilityClass: "metadata",
        extractionMethod: "dom",
        taintClass: trustSignals.taintClass,
        lineageChain: trustSignals.lineageChain,
        supportingDigest: sourceDigest
      })
    );
    blockedChannels.push("metadata");
  }

  for (const match of html.matchAll(ALT_ATTR)) {
    spans.push(
      buildSpan({
        channel: "metadata",
        text: match[1],
        sourceOrigin,
        frameOrigin,
        visibilityClass: "metadata",
        extractionMethod: "dom",
        taintClass: trustSignals.taintClass,
        lineageChain: trustSignals.lineageChain,
        supportingDigest: sourceDigest
      })
    );
    blockedChannels.push("metadata");
  }

  for (const value of capture.metadataText ?? []) {
    if (!normalizeText(value)) {
      continue;
    }
    spans.push(
      buildSpan({
        channel: "metadata",
        text: value,
        sourceOrigin,
        frameOrigin,
        visibilityClass: "metadata",
        extractionMethod: "dom",
        taintClass: trustSignals.taintClass,
        lineageChain: trustSignals.lineageChain,
        supportingDigest: sourceDigest
      })
    );
    blockedChannels.push("metadata");
  }

  for (const value of capture.annotations ?? []) {
    if (!normalizeText(value)) {
      continue;
    }
    spans.push(
      buildSpan({
        channel: "annotation",
        text: value,
        sourceOrigin,
        frameOrigin,
        visibilityClass: "annotation",
        extractionMethod: "dom",
        taintClass: trustSignals.taintClass,
        lineageChain: trustSignals.lineageChain,
        supportingDigest: sourceDigest
      })
    );
    blockedChannels.push("annotation");
  }

  const linkEntries = parseHtmlLinks(html, capture.links ?? []);
  for (const link of linkEntries) {
    const targetOrigin = normalizeOrigin(link.href);
    const linkText = normalizeText(link.text ?? link.href);
    spans.push(
      buildSpan({
        channel: "link",
        text: linkText,
        sourceOrigin,
        frameOrigin: normalizeOrigin(link.frameOrigin ?? frameOrigin),
        visibilityClass: "visible",
        extractionMethod: "dom",
        taintClass: trustSignals.taintClass,
        lineageChain: trustSignals.lineageChain,
        selector: link.selector,
        supportingDigest: sourceDigest
      })
    );
    extractedTargets.push({
      targetId: randomUUID(),
      kind: "navigate",
      href: link.href,
      selector: link.selector,
      sourceSpanIds: [spans[spans.length - 1].spanId],
      sourceOrigin,
      frameOrigin,
      targetOrigin,
      displayText: linkText || link.href
    });
  }

  if (nestedUnsupportedComponents.length) {
    extractedFacts.push(
      ...nestedUnsupportedComponents.map((entry) => `nested unsupported component: ${normalizeText(entry)}`)
    );
    riskFindings.push("nested_unparsed_component");
    if (
      spans.some(
        (span) =>
          span.channel === "hidden_text" ||
          span.channel === "metadata" ||
          span.channel === "comment"
      )
    ) {
      riskFindings.push("surrounding_context_claims_safe_to_continue");
    }
  }

  const parseStatus: CompiledObservation["parseStatus"] = nestedUnsupportedComponents.length
    ? "partial"
    : html || capture.visibleText
      ? "compiled"
      : "unsupported";

  return {
    spans,
    extractedFacts: uniq(extractedFacts),
    extractedTargets,
    riskFindings: uniq(riskFindings),
    blockedChannels: uniq(blockedChannels),
    parseStatus
  };
}

function parsePdfCapture(
  capture: SurfaceCapture,
  trustSignals: ReturnType<typeof normalizeTrustSignals>,
  sourceDigest: string
): {
  spans: ProvenanceSpan[];
  extractedFacts: string[];
  extractedTargets: ExtractedTarget[];
  riskFindings: string[];
  blockedChannels: ProvenanceChannel[];
  parseStatus: CompiledObservation["parseStatus"];
} {
  const sourceOrigin = normalizeOrigin(capture.url);
  const frameOrigin = normalizeOrigin(capture.frameUrl ?? capture.url);
  const spans: ProvenanceSpan[] = [];
  const blockedChannels: ProvenanceChannel[] = [];
  const riskFindings: string[] = [];

  if ("renderedText" in capture && capture.renderedText) {
    spans.push(
      buildSpan({
        channel: "visible_text",
        text: capture.renderedText,
        sourceOrigin,
        frameOrigin,
        visibilityClass: "visible",
        extractionMethod: "download",
        taintClass: trustSignals.taintClass,
        lineageChain: trustSignals.lineageChain,
        supportingDigest: sourceDigest
      })
    );
  }

  if ("extractedText" in capture && capture.extractedText) {
    spans.push(
      buildSpan({
        channel: "hidden_text",
        text: capture.extractedText,
        sourceOrigin,
        frameOrigin,
        visibilityClass: "hidden",
        extractionMethod: "download",
        taintClass: trustSignals.taintClass,
        lineageChain: trustSignals.lineageChain,
        supportingDigest: sourceDigest
      })
    );
    blockedChannels.push("hidden_text");
  }

  if ("ocrText" in capture && capture.ocrText) {
    spans.push(
      buildSpan({
        channel: "ocr",
        text: capture.ocrText,
        sourceOrigin,
        frameOrigin,
        visibilityClass: "visible",
        extractionMethod: "ocr",
        taintClass: trustSignals.taintClass,
        lineageChain: trustSignals.lineageChain,
        supportingDigest: sourceDigest
      })
    );
  }

  for (const value of "metadataText" in capture ? capture.metadataText ?? [] : []) {
    spans.push(
      buildSpan({
        channel: "metadata",
        text: value,
        sourceOrigin,
        frameOrigin,
        visibilityClass: "metadata",
        extractionMethod: "download",
        taintClass: trustSignals.taintClass,
        lineageChain: trustSignals.lineageChain,
        supportingDigest: sourceDigest
      })
    );
    blockedChannels.push("metadata");
  }

  for (const value of "annotations" in capture ? capture.annotations ?? [] : []) {
    spans.push(
      buildSpan({
        channel: "annotation",
        text: value,
        sourceOrigin,
        frameOrigin,
        visibilityClass: "annotation",
        extractionMethod: "download",
        taintClass: trustSignals.taintClass,
        lineageChain: trustSignals.lineageChain,
        supportingDigest: sourceDigest
      })
    );
    blockedChannels.push("annotation");
  }

  if (
    "renderedText" in capture &&
    "extractedText" in capture &&
    capture.renderedText &&
    capture.extractedText &&
    overlapScore(capture.renderedText, capture.extractedText) < 0.45
  ) {
    riskFindings.push("render_vs_extracted_mismatch");
  }

  if (
    "renderedText" in capture &&
    "ocrText" in capture &&
    capture.renderedText &&
    capture.ocrText &&
    overlapScore(capture.renderedText, capture.ocrText) < 0.45
  ) {
    riskFindings.push("render_vs_ocr_mismatch");
  }

  return {
    spans,
    extractedFacts: uniq(
      ("attachments" in capture ? capture.attachments ?? [] : []).map(
        (entry) => `attachment: ${normalizeText(entry)}`
      )
    ),
    extractedTargets: [],
    riskFindings: uniq(riskFindings),
    blockedChannels: uniq(blockedChannels),
    parseStatus: spans.length ? "compiled" : "unsupported"
  };
}

function parseImageCapture(
  capture: SurfaceCapture,
  trustSignals: ReturnType<typeof normalizeTrustSignals>,
  sourceDigest: string
): {
  spans: ProvenanceSpan[];
  extractedFacts: string[];
  extractedTargets: ExtractedTarget[];
  riskFindings: string[];
  blockedChannels: ProvenanceChannel[];
  parseStatus: CompiledObservation["parseStatus"];
} {
  const sourceOrigin = normalizeOrigin(capture.url);
  const frameOrigin = normalizeOrigin(capture.frameUrl ?? capture.url);
  const spans: ProvenanceSpan[] = [];
  const blockedChannels: ProvenanceChannel[] = [];
  const extractedFacts: string[] = [];

  if ("ocrText" in capture && capture.ocrText) {
    spans.push(
      buildSpan({
        channel: "ocr",
        text: capture.ocrText,
        sourceOrigin,
        frameOrigin,
        visibilityClass: "visible",
        extractionMethod: "ocr",
        taintClass: trustSignals.taintClass,
        lineageChain: trustSignals.lineageChain,
        supportingDigest: sourceDigest
      })
    );
  }

  if ("captionText" in capture && capture.captionText) {
    extractedFacts.push(`caption: ${normalizeText(capture.captionText)}`);
  }

  for (const value of "metadataText" in capture ? capture.metadataText ?? [] : []) {
    spans.push(
      buildSpan({
        channel: "metadata",
        text: value,
        sourceOrigin,
        frameOrigin,
        visibilityClass: "metadata",
        extractionMethod: "manual",
        taintClass: trustSignals.taintClass,
        lineageChain: trustSignals.lineageChain,
        supportingDigest: sourceDigest
      })
    );
    blockedChannels.push("metadata");
  }

  return {
    spans,
    extractedFacts: uniq(extractedFacts),
    extractedTargets: [],
    riskFindings: [],
    blockedChannels: uniq(blockedChannels),
    parseStatus: spans.length || extractedFacts.length ? "compiled" : "unsupported"
  };
}

function parseToolManifestCapture(
  capture: ToolManifestSurfaceCapture,
  trustSignals: ReturnType<typeof normalizeTrustSignals>,
  sourceDigest: string
): {
  spans: ProvenanceSpan[];
  extractedFacts: string[];
  extractedTargets: ExtractedTarget[];
  riskFindings: string[];
  blockedChannels: ProvenanceChannel[];
  parseStatus: CompiledObservation["parseStatus"];
} {
  const sourceOrigin = normalizeOrigin(capture.url);
  const frameOrigin = normalizeOrigin(capture.frameUrl ?? capture.url);
  const spans: ProvenanceSpan[] = [
    buildSpan({
      channel: "visible_text",
      text: capture.description,
      sourceOrigin,
      frameOrigin,
      visibilityClass: "visible",
      extractionMethod: "api",
      taintClass: trustSignals.taintClass,
      lineageChain: trustSignals.lineageChain,
      supportingDigest: sourceDigest
    })
  ];
  const blockedChannels: ProvenanceChannel[] = [];
  const callbackTargetOrigin = normalizeOrigin(
    capture.callbackOrigin ?? capture.callbackUri ?? capture.url
  );
  for (const entry of capture.schemaDescriptions ?? []) {
    spans.push(
      buildSpan({
        channel: "schema",
        text: entry,
        sourceOrigin,
        frameOrigin,
        visibilityClass: "metadata",
        extractionMethod: "api",
        taintClass: trustSignals.taintClass,
        lineageChain: trustSignals.lineageChain,
        supportingDigest: sourceDigest
      })
    );
    blockedChannels.push("schema");
  }

  const riskFindings = capture.schemaDescriptions?.length ? ["tool_schema_present"] : [];
  const lowerDescription = capture.description.toLowerCase();
  const lowerSchema = (capture.schemaDescriptions ?? []).join(" ").toLowerCase();
  if (
    /(finalized by the adapter|auto-submit|without approval|fastpath|fast path|route them somewhere)/.test(
      lowerDescription
    )
  ) {
    riskFindings.push("tool_manifest_security_sensitive_prose");
  }
  if (
    /(approvalcontext|destinationmailbox|fastpathreason|fast path reason|route|submit|finalize)/.test(
      lowerSchema
    )
  ) {
    riskFindings.push("schema_example_operational_suggestion");
  }

  return {
    spans,
    extractedFacts: uniq(
      [
        `tool: ${capture.toolId}`,
        capture.authType ? `auth: ${capture.authType}` : "",
        ...(capture.requestedScopes ?? []).map((scope) => `scope: ${scope}`)
      ].filter(Boolean)
    ),
    extractedTargets:
      capture.authType === "oauth" || Boolean(capture.callbackUri) || Boolean(capture.callbackOrigin)
        ? [
            {
              targetId: randomUUID(),
              kind: "connector_prepare",
              sourceSpanIds: [spans[0].spanId],
              sourceOrigin,
              frameOrigin,
              targetOrigin: callbackTargetOrigin,
              displayText: capture.toolId
            }
          ]
        : [],
    riskFindings: uniq(riskFindings),
    blockedChannels: uniq(blockedChannels),
    parseStatus: "compiled"
  };
}

function parseMemoryCandidateCapture(
  capture: SurfaceCapture,
  trustSignals: ReturnType<typeof normalizeTrustSignals>,
  sourceDigest: string
): {
  spans: ProvenanceSpan[];
  extractedFacts: string[];
  extractedTargets: ExtractedTarget[];
  riskFindings: string[];
  blockedChannels: ProvenanceChannel[];
  parseStatus: CompiledObservation["parseStatus"];
} {
  const sourceOrigin = normalizeOrigin(capture.url);
  const frameOrigin = normalizeOrigin(capture.frameUrl ?? capture.url);
  if (!("key" in capture)) {
    return {
      spans: [],
      extractedFacts: [],
      extractedTargets: [],
      riskFindings: [],
      blockedChannels: [],
      parseStatus: "unsupported"
    };
  }
  return {
    spans: [
      buildSpan({
        channel: "memory_candidate",
        text: `${capture.key}: ${JSON.stringify(capture.value)}`,
        sourceOrigin,
        frameOrigin,
        visibilityClass: "metadata",
        extractionMethod: "api",
        taintClass: trustSignals.taintClass,
        lineageChain: trustSignals.lineageChain,
        supportingDigest: sourceDigest
      })
    ],
    extractedFacts: [`candidate memory key: ${capture.key}`],
    extractedTargets: [],
    riskFindings: ["memory_candidate_present"],
    blockedChannels: ["memory_candidate"],
    parseStatus: "compiled"
  };
}

export function compileObservation(
  capture: SurfaceCapture,
  context: Partial<RuntimeContext> = {},
  options: {
    parserIsolation?: ParserIsolationReport;
    workflowHash?: string;
  } = {}
): {
  compiledObservation: CompiledObservation;
  plannerInput: StructuredPlannerInput;
} {
  const trustSignals = normalizeTrustSignals({
    sourceOrigin: capture.url,
    frameOrigin: capture.frameUrl ?? capture.url,
    userSharedFlag: capture.userShared ?? false,
    sessionDiscoveredFlag: !(capture.userShared ?? false),
    artifactKind:
      capture.surfaceType === "tool_manifest"
        ? "tool_manifest"
        : capture.surfaceType === "memory_candidate"
          ? "memory"
          : capture.surfaceType === "html"
            ? "page"
            : capture.surfaceType,
    extractionMethod:
      capture.surfaceType === "html"
        ? "dom"
        : capture.surfaceType === "tool_manifest" || capture.surfaceType === "memory_candidate"
          ? "api"
          : capture.surfaceType === "image"
            ? "ocr"
            : "download",
    ...(capture.trustSignals ?? {})
  });
  const sourceDigest = hashSurface(capture);
  const parsed =
    capture.surfaceType === "html"
      ? parseHtmlCapture(capture, trustSignals, sourceDigest)
      : capture.surfaceType === "pdf"
        ? parsePdfCapture(capture, trustSignals, sourceDigest)
        : capture.surfaceType === "image"
          ? parseImageCapture(capture, trustSignals, sourceDigest)
          : capture.surfaceType === "tool_manifest"
            ? parseToolManifestCapture(capture, trustSignals, sourceDigest)
            : parseMemoryCandidateCapture(capture, trustSignals, sourceDigest);

  const aggregateText = parsed.spans.map((span) => span.text).join(" ");
  const legacyObservation = sanitizeObservation(
    {
      observationId: capture.captureId,
      taskId: capture.taskId,
      sourceType:
        capture.surfaceType === "tool_manifest"
          ? "tool_text"
          : capture.surfaceType === "memory_candidate"
            ? "memory"
            : capture.surfaceType === "pdf" || capture.surfaceType === "image"
              ? "document"
              : "page",
      text: aggregateText,
      fragments: parsed.spans.map((span) => ({
        text: span.text,
        visibilityClass: span.visibilityClass,
        medium:
          span.channel === "ocr"
            ? "ocr"
            : span.channel === "annotation"
              ? "annotation"
              : span.channel === "metadata" || span.channel === "schema"
                ? "metadata"
                : "text",
        sourceOrigin: span.sourceOrigin,
        frameOrigin: span.frameOrigin,
        selector: span.selector,
        tainted: span.taintClass !== "trusted"
      })),
      trustSignals
    },
    context
  );

  const visibleExcerptSource = parsed.spans
    .filter((span) => span.channel === "visible_text" || span.channel === "ocr")
    .map((span) => span.text)
    .join(" ");
  const visibleExcerpt = redactSecretsInText(visibleExcerptSource).text.slice(0, 3000);

  const quotedUntrustedBlocks = parsed.spans
    .filter((span) =>
      ["hidden_text", "metadata", "annotation", "comment", "schema", "memory_candidate"].includes(
        span.channel
      )
    )
    .slice(0, 6)
    .map((span) => {
      const redacted = redactSecretsInText(span.text);
      return {
        channel: span.channel,
        text: redacted.text.slice(0, 500),
        spanId: span.spanId
      };
    });

  const extractedFacts = parsed.extractedFacts.map((fact) => redactSecretsInText(fact).text);
  const secretFindings = uniq([
    ...parsed.spans.flatMap((span) => redactSecretsInText(span.text).secretFindings),
    ...quotedUntrustedBlocks.flatMap((block) => redactSecretsInText(block.text).secretFindings),
    ...extractedFacts.flatMap((fact) => redactSecretsInText(fact).secretFindings)
  ]);

  const compiledObservation: CompiledObservation = {
    observationId: legacyObservation.observationId,
    sessionId: capture.sessionId,
    taskId: capture.taskId,
    surfaceType: capture.surfaceType,
    sourceOrigin: trustSignals.sourceOrigin,
    frameOrigin: trustSignals.frameOrigin,
    sourceDigest,
    workflowHash: options.workflowHash,
    parseStatus: parsed.parseStatus,
    parserIsolation:
      options.parserIsolation ?? {
        processIsolated: false,
        envScrubbed: false,
        egressDenied: false,
        envKeys: [],
        allowlistedEgress: []
      },
    spans: parsed.spans,
    extractedFacts,
    extractedTargets: parsed.extractedTargets,
    riskFindings: uniq(parsed.riskFindings),
    suspicionFlags: legacyObservation.suspicionFlags,
    matchedPatternIds: legacyObservation.matchedPatternIds,
    riskScore: clamp(Math.max(legacyObservation.riskScore, parsed.riskFindings.length * 0.1)),
    secretFindings,
    createdAt: legacyObservation.createdAt
  };

  return {
    compiledObservation,
    plannerInput: {
      observationId: compiledObservation.observationId,
      sessionId: compiledObservation.sessionId,
      surfaceType: compiledObservation.surfaceType,
      visibleExcerpt,
      facts: compiledObservation.extractedFacts,
      quotedUntrustedBlocks,
      riskMarkers: uniq([
        ...compiledObservation.suspicionFlags,
        ...compiledObservation.riskFindings,
        ...(compiledObservation.secretFindings.length ? ["secret_redaction_applied"] : [])
      ]),
      blockedChannels: uniq(parsed.blockedChannels),
      secretRedactionsApplied: compiledObservation.secretFindings.length > 0,
      candidateCapabilities: []
    }
  };
}

export function applyV4FailClosedMediation(
  compiledObservation: CompiledObservation,
  plannerInput: StructuredPlannerInput,
  mode: "observe" | "artifact"
): {
  plannerInput: StructuredPlannerInput;
  verdict: SafeVerdict;
  failClosed: boolean;
} {
  if (compiledObservation.parseStatus === "compiled") {
    return {
      plannerInput,
      verdict: {
        decision: "ALLOW",
        reasonCodes: [],
        riskScore: clamp(Math.max(0.05, compiledObservation.riskScore)),
        telemetryTags: uniq(["v4_parse_status", "compiled", mode, "allow"])
      },
      failClosed: false
    };
  }

  const parseReasonCode =
    compiledObservation.parseStatus === "partial"
      ? "PARSE_STATUS_PARTIAL"
      : "PARSE_STATUS_UNSUPPORTED";

  return {
    plannerInput: {
      ...plannerInput,
      visibleExcerpt: "",
      facts: [],
      quotedUntrustedBlocks: [],
      candidateCapabilities: [],
      riskMarkers: uniq([
        ...plannerInput.riskMarkers,
        `parse_status_${compiledObservation.parseStatus}`
      ])
    },
    verdict: {
      decision: mode === "artifact" ? "QUARANTINE_ARTIFACT" : "BLOCK",
      reasonCodes: [parseReasonCode],
      riskScore: 0.95,
      safeConstraints: {
        parse_status: compiledObservation.parseStatus,
        planner_safe_content_removed: true
      },
      telemetryTags: uniq([
        "v4_parse_status",
        compiledObservation.parseStatus,
        mode,
        "fail_closed"
      ])
    },
    failClosed: true
  };
}

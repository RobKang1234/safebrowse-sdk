import { randomUUID } from "node:crypto";
import { parse as parseHtmlDocument } from "parse5";

import { materializeBinarySurfaceCapture } from "./binarySurfaceIngest.js";
import { extractTextFromHtml } from "./htmlText.js";
import { redactSecretsInText } from "./secretIsolation.js";
import { sanitizeObservation } from "./sanitize.js";
import { normalizeTrustSignals } from "./trust.js";
import type {
  AttachmentBundleSurfaceCapture,
  AttachmentNodeCapture,
  CompiledObservation,
  DocxSurfaceCapture,
  EmailActionCandidateCapture,
  EmailSurfaceCapture,
  ExternalApiSurfaceCapture,
  ExtractedTarget,
  ExtractionAttestation,
  SafeVerdict,
  HtmlSurfaceCapture,
  PptxSurfaceCapture,
  ParserIsolationReport,
  ProvenanceChannel,
  ProvenanceSpan,
  RuntimeContext,
  StructuredPlannerInput,
  SurfaceCapture,
  SurfaceLinkCapture,
  ToolManifestSurfaceCapture,
  XlsxSurfaceCapture
} from "./types.js";
import { clamp, normalizeOrigin, normalizeText, overlapScore, sha256Hex, uniq } from "./utils.js";

type HtmlAttr = {
  name: string;
  value: string;
};

type HtmlNode = {
  nodeName?: string;
  tagName?: string;
  value?: string;
  data?: string;
  attrs?: HtmlAttr[];
  childNodes?: HtmlNode[];
};

const SKIP_TEXT_TAGS = new Set(["script", "style", "template", "noscript"]);
const METADATA_ATTRS = new Set(["alt", "title", "aria-label"]);

function getAttr(node: HtmlNode, name: string): string | undefined {
  return node.attrs?.find((attr) => attr.name.toLowerCase() === name)?.value;
}

function stripAsciiWhitespace(input: string): string {
  let result = "";
  for (const char of input) {
    if (
      char !== " " &&
      char !== "\t" &&
      char !== "\n" &&
      char !== "\r" &&
      char !== "\f" &&
      char !== "\v"
    ) {
      result += char;
    }
  }
  return result;
}

function styleContainsHiddenSignal(style: string | undefined): boolean {
  if (!style) {
    return false;
  }

  for (const declaration of style.toLowerCase().split(";")) {
    const separator = declaration.indexOf(":");
    if (separator === -1) {
      continue;
    }

    const property = declaration.slice(0, separator).trim();
    const value = stripAsciiWhitespace(declaration.slice(separator + 1));

    if ((property === "display" && value === "none") || (property === "visibility" && value === "hidden")) {
      return true;
    }
  }

  return false;
}

function elementHasHiddenSignal(node: HtmlNode): boolean {
  if (!node.tagName) {
    return false;
  }

  const hidden = getAttr(node, "hidden");
  const inert = getAttr(node, "inert");
  const ariaHidden = getAttr(node, "aria-hidden")?.toLowerCase();

  return (
    hidden !== undefined ||
    inert !== undefined ||
    ariaHidden === "true" ||
    styleContainsHiddenSignal(getAttr(node, "style"))
  );
}

function nodeText(node: HtmlNode): string {
  return normalizeText(node.value ?? node.data ?? "");
}

function textContent(node: HtmlNode, skipHiddenDescendants = false): string {
  const nodeName = node.nodeName?.toLowerCase() ?? "";
  if (nodeName === "#text") {
    return nodeText(node);
  }
  if (nodeName === "#comment") {
    return "";
  }

  const tagName = node.tagName?.toLowerCase();
  if (tagName && SKIP_TEXT_TAGS.has(tagName)) {
    return "";
  }

  if (skipHiddenDescendants && elementHasHiddenSignal(node)) {
    return "";
  }

  return normalizeText((node.childNodes ?? []).map((child) => textContent(child, skipHiddenDescendants)).join(" "));
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
      providerId: "providerId" in capture ? capture.providerId : undefined,
      parserId: "parserId" in capture ? capture.parserId : undefined,
      extractorId: "extractorId" in capture ? capture.extractorId : undefined,
      visibleText: "visibleText" in capture ? capture.visibleText : undefined,
      html: "html" in capture ? capture.html : undefined,
      renderedText: "renderedText" in capture ? capture.renderedText : undefined,
      extractedText: "extractedText" in capture ? capture.extractedText : undefined,
      ocrText: "ocrText" in capture ? capture.ocrText : undefined,
      description: "description" in capture ? capture.description : undefined,
      key: "key" in capture ? capture.key : undefined,
      subject: "subject" in capture ? capture.subject : undefined,
      bodyText: "bodyText" in capture ? capture.bodyText : undefined,
      responseText: "responseText" in capture ? capture.responseText : undefined,
      operationId: "operationId" in capture ? capture.operationId : undefined,
      attachments:
        "attachments" in capture
          ? capture.attachments
          : undefined
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
  visibleOnlyFlag?: boolean;
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
    supportingDigest: input.supportingDigest,
    visibleOnlyFlag: input.visibleOnlyFlag
  };
}

function hashNormalizedValues(values: string[]): string | undefined {
  const normalized = values.map((value) => normalizeText(value)).filter(Boolean).sort();
  if (!normalized.length) {
    return undefined;
  }
  return sha256Hex(JSON.stringify(normalized));
}

function hashNormalizedValue(value: string | undefined): string | undefined {
  const normalized = normalizeText(value ?? "");
  return normalized ? sha256Hex(normalized) : undefined;
}

function hasExtractionAttestation(
  capture: SurfaceCapture
): capture is
  | EmailSurfaceCapture
  | DocxSurfaceCapture
  | XlsxSurfaceCapture
  | PptxSurfaceCapture
  | AttachmentBundleSurfaceCapture
  | ExternalApiSurfaceCapture {
  return "extractionAttestation" in capture;
}

function extractionAttestationFacts(attestation: ExtractionAttestation | undefined): string[] {
  if (!attestation) {
    return [];
  }
  return [
    `extractor: ${attestation.extractorId}`,
    `extractor version: ${attestation.extractorVersion}`,
    `network policy: ${attestation.networkPolicy}`
  ];
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
  const sourceOrigin = normalizeOrigin(capture.url);
  const frameOrigin = normalizeOrigin(capture.frameUrl ?? capture.url);
  const spans: ProvenanceSpan[] = [];
  const extractedFacts: string[] = [];
  const extractedTargets: ExtractedTarget[] = [];
  const riskFindings: string[] = [];
  const blockedChannels: ProvenanceChannel[] = [];
  const nestedUnsupportedComponents = capture.nestedUnsupportedComponents ?? [];
  const document = html ? (parseHtmlDocument(html) as unknown as HtmlNode) : undefined;
  const visibleParts: string[] = [];
  const htmlLinks: SurfaceLinkCapture[] = [];

  function pushLink(link: SurfaceLinkCapture): void {
    if (!normalizeText(link.href)) {
      return;
    }

    const targetOrigin = normalizeOrigin(link.href);
    const linkText = normalizeText(link.text ?? link.href);
    const normalizedFrameOrigin = normalizeOrigin(link.frameOrigin ?? frameOrigin);
    const span = buildSpan({
      channel: "link",
      text: linkText,
      sourceOrigin,
      frameOrigin: normalizedFrameOrigin,
      visibilityClass: "visible",
      extractionMethod: "dom",
      taintClass: trustSignals.taintClass,
      lineageChain: trustSignals.lineageChain,
      selector: link.selector,
      supportingDigest: sourceDigest
    });
    spans.push(span);
    extractedTargets.push({
      targetId: randomUUID(),
      kind: "navigate",
      operationClass: "browser_navigation",
      href: link.href,
      selector: link.selector,
      sourceSpanIds: [span.spanId],
      sourceOrigin,
      frameOrigin: normalizedFrameOrigin,
      targetOrigin,
      displayText: linkText || link.href
    });
  }

  function walk(node: HtmlNode, state: { hidden: boolean; inHead: boolean }): void {
    const nodeName = node.nodeName?.toLowerCase() ?? "";
    const tagName = node.tagName?.toLowerCase();

    if (nodeName === "#comment") {
      const commentText = nodeText(node);
      if (commentText) {
        spans.push(
          buildSpan({
            channel: "comment",
            text: commentText,
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
      return;
    }

    if (nodeName === "#text") {
      const text = nodeText(node);
      if (!text) {
        return;
      }

      if (state.hidden) {
        spans.push(
          buildSpan({
            channel: "hidden_text",
            text,
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
      } else if (!state.inHead) {
        visibleParts.push(text);
      }

      return;
    }

    if (!tagName) {
      for (const child of node.childNodes ?? []) {
        walk(child, state);
      }
      return;
    }

    const hidden = state.hidden || elementHasHiddenSignal(node);
    const inHead = state.inHead || tagName === "head";

    if (tagName === "title") {
      const title = normalizeText(capture.title ?? textContent(node));
      if (title) {
        spans.push(
          buildSpan({
            channel: "metadata",
            text: title,
            sourceOrigin,
            frameOrigin,
            visibilityClass: "metadata",
            extractionMethod: "dom",
            taintClass: trustSignals.taintClass,
            lineageChain: trustSignals.lineageChain,
            supportingDigest: sourceDigest
          })
        );
        extractedFacts.push(`title: ${title}`);
        blockedChannels.push("metadata");
      }
    } else if (tagName === "meta") {
      const metaName = normalizeText(getAttr(node, "name") ?? getAttr(node, "property") ?? "");
      const metaContent = normalizeText(getAttr(node, "content") ?? "");
      if (metaName && metaContent) {
        spans.push(
          buildSpan({
            channel: "metadata",
            text: `${metaName}: ${metaContent}`,
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
    } else if (tagName === "a" && !hidden) {
      const href = getAttr(node, "href");
      if (href && normalizeText(href)) {
        htmlLinks.push({
          href,
          text: textContent(node, true),
          selector: `a[href="${href}"]`,
          frameOrigin
        });
      }
    }

    for (const attrName of METADATA_ATTRS) {
      const attrValue = normalizeText(getAttr(node, attrName) ?? "");
      if (!attrValue) {
        continue;
      }
      spans.push(
        buildSpan({
          channel: "metadata",
          text: attrValue,
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

    for (const child of node.childNodes ?? []) {
      walk(child, {
        hidden,
        inHead
      });
    }
  }

  if (document) {
    walk(document, { hidden: false, inHead: false });
  }

  const visibleText = normalizeText(capture.visibleText ?? visibleParts.join(" "));

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

  for (const link of capture.links ?? []) {
    pushLink(link);
  }

  for (const link of htmlLinks) {
    pushLink(link);
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
        (entry) =>
          `attachment: ${normalizeText(typeof entry === "string" ? entry : entry.filename)}`
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
              operationClass: "connector_setup",
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

function buildOfficeLinkTarget(
  link: SurfaceLinkCapture,
  sourceOrigin: string,
  frameOrigin: string,
  trustSignals: ReturnType<typeof normalizeTrustSignals>,
  sourceDigest: string
): { span: ProvenanceSpan; target: ExtractedTarget } | undefined {
  if (!normalizeText(link.href)) {
    return undefined;
  }
  const text = normalizeText(link.text ?? link.href);
  const span = buildSpan({
    channel: "link",
    text,
    sourceOrigin,
    frameOrigin,
    visibilityClass: "visible",
    extractionMethod: "ooxml",
    taintClass: trustSignals.taintClass,
    lineageChain: trustSignals.lineageChain,
    selector: link.selector,
    supportingDigest: sourceDigest,
    visibleOnlyFlag: true
  });
  return {
    span,
    target: {
      targetId: randomUUID(),
      kind: "navigate",
      operationClass: "browser_navigation",
      href: link.href,
      selector: link.selector,
      sourceSpanIds: [span.spanId],
      sourceOrigin,
      frameOrigin,
      targetOrigin: normalizeOrigin(link.href),
      displayText: text || link.href,
      sourceChannelSet: ["link"],
      visibleOnlyFlag: true
    }
  };
}

function parseOfficeCapture(
  capture: DocxSurfaceCapture | XlsxSurfaceCapture | PptxSurfaceCapture,
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
  const extractedFacts: string[] = [...extractionAttestationFacts(capture.extractionAttestation)];
  const extractedTargets: ExtractedTarget[] = [];
  const riskFindings: string[] = [];
  const blockedChannels: ProvenanceChannel[] = [];

  const visibleText = normalizeText(capture.visibleText ?? "");
  if (visibleText) {
    spans.push(
      buildSpan({
        channel: "visible_text",
        text: visibleText,
        sourceOrigin,
        frameOrigin,
        visibilityClass: "visible",
        extractionMethod: "ooxml",
        taintClass: trustSignals.taintClass,
        lineageChain: trustSignals.lineageChain,
        supportingDigest: sourceDigest
      })
    );
  }

  for (const value of capture.hiddenText ?? []) {
    const text = normalizeText(value);
    if (!text) {
      continue;
    }
    spans.push(
      buildSpan({
        channel: capture.surfaceType === "xlsx" ? "hidden_sheet" : "hidden_slide",
        text,
        sourceOrigin,
        frameOrigin,
        visibilityClass: "hidden",
        extractionMethod: "ooxml",
        taintClass: trustSignals.taintClass,
        lineageChain: trustSignals.lineageChain,
        supportingDigest: sourceDigest
      })
    );
    blockedChannels.push(capture.surfaceType === "xlsx" ? "hidden_sheet" : "hidden_slide");
  }

  for (const value of capture.metadataText ?? []) {
    const text = normalizeText(value);
    if (!text) {
      continue;
    }
    spans.push(
      buildSpan({
        channel: "metadata",
        text,
        sourceOrigin,
        frameOrigin,
        visibilityClass: "metadata",
        extractionMethod: "ooxml",
        taintClass: trustSignals.taintClass,
        lineageChain: trustSignals.lineageChain,
        supportingDigest: sourceDigest
      })
    );
    blockedChannels.push("metadata");
  }

  for (const value of capture.comments ?? []) {
    const text = normalizeText(value);
    if (!text) {
      continue;
    }
    spans.push(
      buildSpan({
        channel: "office_comment",
        text,
        sourceOrigin,
        frameOrigin,
        visibilityClass: "annotation",
        extractionMethod: "ooxml",
        taintClass: trustSignals.taintClass,
        lineageChain: trustSignals.lineageChain,
        supportingDigest: sourceDigest
      })
    );
    blockedChannels.push("office_comment");
  }

  for (const value of capture.notes ?? []) {
    const text = normalizeText(value);
    if (!text) {
      continue;
    }
    spans.push(
      buildSpan({
        channel: "office_note",
        text,
        sourceOrigin,
        frameOrigin,
        visibilityClass: "annotation",
        extractionMethod: "ooxml",
        taintClass: trustSignals.taintClass,
        lineageChain: trustSignals.lineageChain,
        supportingDigest: sourceDigest
      })
    );
    blockedChannels.push("office_note");
  }

  for (const value of capture.trackedChanges ?? []) {
    const text = normalizeText(value);
    if (!text) {
      continue;
    }
    spans.push(
      buildSpan({
        channel: "tracked_change",
        text,
        sourceOrigin,
        frameOrigin,
        visibilityClass: "annotation",
        extractionMethod: "ooxml",
        taintClass: trustSignals.taintClass,
        lineageChain: trustSignals.lineageChain,
        supportingDigest: sourceDigest
      })
    );
    blockedChannels.push("tracked_change");
  }

  for (const value of capture.formulas ?? []) {
    const text = normalizeText(value);
    if (!text) {
      continue;
    }
    spans.push(
      buildSpan({
        channel: "office_formula",
        text,
        sourceOrigin,
        frameOrigin,
        visibilityClass: "metadata",
        extractionMethod: "ooxml",
        taintClass: trustSignals.taintClass,
        lineageChain: trustSignals.lineageChain,
        supportingDigest: sourceDigest
      })
    );
    blockedChannels.push("office_formula");
  }

  for (const value of capture.externalRelationships ?? []) {
    const text = normalizeText(value);
    if (!text) {
      continue;
    }
    spans.push(
      buildSpan({
        channel: "external_relationship",
        text,
        sourceOrigin,
        frameOrigin,
        visibilityClass: "metadata",
        extractionMethod: "ooxml",
        taintClass: trustSignals.taintClass,
        lineageChain: trustSignals.lineageChain,
        supportingDigest: sourceDigest
      })
    );
    blockedChannels.push("external_relationship");
    riskFindings.push("office_external_relationship_present");
  }

  for (const value of capture.embeddedObjects ?? []) {
    const text = normalizeText(value);
    if (!text) {
      continue;
    }
    spans.push(
      buildSpan({
        channel: "embedded_object",
        text,
        sourceOrigin,
        frameOrigin,
        visibilityClass: "metadata",
        extractionMethod: "ooxml",
        taintClass: trustSignals.taintClass,
        lineageChain: trustSignals.lineageChain,
        supportingDigest: sourceDigest
      })
    );
    blockedChannels.push("embedded_object");
    riskFindings.push("office_embedded_object_present");
  }

  for (const attachment of capture.attachments ?? []) {
    extractedFacts.push(`attachment: ${attachment.filename}`);
  }

  for (const link of capture.links ?? []) {
    const parsedLink = buildOfficeLinkTarget(
      link,
      sourceOrigin,
      frameOrigin,
      trustSignals,
      sourceDigest
    );
    if (!parsedLink) {
      continue;
    }
    spans.push(parsedLink.span);
    extractedTargets.push(parsedLink.target);
  }

  if ((capture.hiddenText?.length ?? 0) > 0) {
    riskFindings.push("hidden_office_content_present");
  }
  if (!capture.extractionAttestation) {
    riskFindings.push("surface_attestation_missing");
  }
  if ((capture.unsupportedSubtrees?.length ?? 0) > 0) {
    riskFindings.push("unsupported_nested_renderer");
    extractedFacts.push(
      ...capture.unsupportedSubtrees!.map((entry) => `unsupported subtree: ${normalizeText(entry)}`)
    );
  }

  const parseStatus: CompiledObservation["parseStatus"] =
    (capture.unsupportedSubtrees?.length ?? 0) > 0
      ? "partial"
      : spans.length || extractedFacts.length
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

function actionSpanText(action: EmailActionCandidateCapture): string {
  return `${action.kind.replaceAll("_", " ")} ${action.recipients.join(", ")}`.trim();
}

function parseEmailCapture(
  capture: EmailSurfaceCapture,
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
  const extractedFacts: string[] = [
    ...extractionAttestationFacts(capture.extractionAttestation),
    capture.subject ? `subject: ${normalizeText(capture.subject)}` : ""
  ].filter(Boolean);
  const extractedTargets: ExtractedTarget[] = [];
  const riskFindings: string[] = [];
  const blockedChannels: ProvenanceChannel[] = [];
  const visibleParts = [
    normalizeText(capture.subject ?? ""),
    normalizeText(capture.bodyText ?? ""),
    capture.bodyHtml ? extractTextFromHtml(capture.bodyHtml) : ""
  ].filter(Boolean);

  if (visibleParts.length) {
    spans.push(
      buildSpan({
        channel: "visible_text",
        text: visibleParts.join(" "),
        sourceOrigin,
        frameOrigin,
        visibilityClass: "visible",
        extractionMethod: "mime",
        taintClass: trustSignals.taintClass,
        lineageChain: trustSignals.lineageChain,
        supportingDigest: sourceDigest
      })
    );
  }

  for (const value of capture.headers ?? []) {
    const text = normalizeText(value);
    if (!text) {
      continue;
    }
    spans.push(
      buildSpan({
        channel: "email_header",
        text,
        sourceOrigin,
        frameOrigin,
        visibilityClass: "metadata",
        extractionMethod: "mime",
        taintClass: trustSignals.taintClass,
        lineageChain: trustSignals.lineageChain,
        supportingDigest: sourceDigest
      })
    );
    blockedChannels.push("email_header");
  }

  for (const value of capture.authResults ?? []) {
    const text = normalizeText(value);
    if (!text) {
      continue;
    }
    spans.push(
      buildSpan({
        channel: "auth_result",
        text,
        sourceOrigin,
        frameOrigin,
        visibilityClass: "metadata",
        extractionMethod: "mime",
        taintClass: trustSignals.taintClass,
        lineageChain: trustSignals.lineageChain,
        supportingDigest: sourceDigest
      })
    );
    blockedChannels.push("auth_result");
  }

  for (const value of capture.quotedThreadText ?? []) {
    const text = normalizeText(value);
    if (!text) {
      continue;
    }
    spans.push(
      buildSpan({
        channel: "quoted_thread",
        text,
        sourceOrigin,
        frameOrigin,
        visibilityClass: "hidden",
        extractionMethod: "mime",
        taintClass: trustSignals.taintClass,
        lineageChain: trustSignals.lineageChain,
        supportingDigest: sourceDigest
      })
    );
    blockedChannels.push("quoted_thread");
  }

  for (const value of capture.remoteContent ?? []) {
    const text = normalizeText(value);
    if (!text) {
      continue;
    }
    spans.push(
      buildSpan({
        channel: "remote_content",
        text,
        sourceOrigin,
        frameOrigin,
        visibilityClass: "metadata",
        extractionMethod: "mime",
        taintClass: "tainted",
        lineageChain: trustSignals.lineageChain,
        supportingDigest: sourceDigest
      })
    );
    blockedChannels.push("remote_content");
  }

  for (const address of uniq([
    ...(capture.to ?? []),
    ...(capture.cc ?? []),
    ...(capture.bcc ?? [])
  ])) {
    const text = normalizeText(address);
    if (!text) {
      continue;
    }
    spans.push(
      buildSpan({
        channel: "recipient",
        text,
        sourceOrigin,
        frameOrigin,
        visibilityClass: "metadata",
        extractionMethod: "mime",
        taintClass: trustSignals.taintClass,
        lineageChain: trustSignals.lineageChain,
        supportingDigest: sourceDigest
      })
    );
    blockedChannels.push("recipient");
  }

  for (const attachment of capture.attachments ?? []) {
    extractedFacts.push(`attachment: ${attachment.filename}`);
  }

  for (const link of capture.links ?? []) {
    const parsedLink = buildOfficeLinkTarget(
      link,
      sourceOrigin,
      frameOrigin,
      { ...trustSignals, extractionMethod: "mime" },
      sourceDigest
    );
    if (!parsedLink) {
      continue;
    }
    spans.push(parsedLink.span);
    extractedTargets.push(parsedLink.target);
  }

  for (const action of capture.actionCandidates ?? []) {
    const span = buildSpan({
      channel: "visible_text",
      text: actionSpanText(action),
      sourceOrigin,
      frameOrigin,
      visibilityClass: "visible",
      extractionMethod: "mime",
      taintClass: trustSignals.taintClass,
      lineageChain: trustSignals.lineageChain,
      supportingDigest: sourceDigest,
      visibleOnlyFlag: true
    });
    spans.push(span);
    extractedTargets.push({
      targetId: randomUUID(),
      kind: action.kind,
      operationClass: action.kind,
      sourceSpanIds: [span.spanId],
      sourceOrigin,
      frameOrigin,
      targetOrigin: normalizeOrigin(capture.url),
      displayText: actionSpanText(action),
      providerId: capture.providerId,
      mailboxId: action.mailboxId ?? capture.mailboxId,
      accountId: action.accountId ?? capture.accountId,
      messageId: action.messageId ?? capture.messageId,
      threadId: action.threadId ?? capture.threadId,
      recipients: uniq(action.recipients),
      recipientSetHash: hashNormalizedValues(action.recipients),
      subjectHash: hashNormalizedValue(action.subject ?? capture.subject),
      bodyDigest: hashNormalizedValue(action.bodyText ?? capture.bodyText),
      attachmentDigestSet: uniq(action.attachmentDigests ?? []),
      sourceChannelSet: ["visible_text"],
      visibleOnlyFlag: true
    });
  }

  if ((capture.remoteContent?.length ?? 0) > 0) {
    riskFindings.push("email_remote_content_present");
  }
  if (!capture.extractionAttestation) {
    riskFindings.push("surface_attestation_missing");
  }
  if ((capture.quotedThreadText?.length ?? 0) > 0) {
    riskFindings.push("quoted_thread_prompting_present");
  }
  if ((capture.unsupportedSubtrees?.length ?? 0) > 0) {
    riskFindings.push("unsupported_nested_renderer");
  }

  const parseStatus: CompiledObservation["parseStatus"] =
    (capture.unsupportedSubtrees?.length ?? 0) > 0
      ? "partial"
      : spans.length || extractedFacts.length
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

function parseExternalApiCapture(
  capture: ExternalApiSurfaceCapture,
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
  const extractedFacts: string[] = [
    ...extractionAttestationFacts(capture.extractionAttestation),
    `provider: ${capture.providerId}`,
    `operation: ${capture.operationId}`,
    `method: ${capture.method}`
  ];
  const extractedTargets: ExtractedTarget[] = [];
  const blockedChannels: ProvenanceChannel[] = [];
  const riskFindings: string[] = [];

  const responseText = normalizeText(capture.responseText ?? "");
  if (responseText) {
    spans.push(
      buildSpan({
        channel: "visible_text",
        text: responseText,
        sourceOrigin,
        frameOrigin,
        visibilityClass: "visible",
        extractionMethod: "api",
        taintClass: trustSignals.taintClass,
        lineageChain: trustSignals.lineageChain,
        supportingDigest: sourceDigest
      })
    );
  }

  for (const value of capture.responseFields ?? []) {
    const text = normalizeText(value);
    if (!text) {
      continue;
    }
    spans.push(
      buildSpan({
        channel: "api_field",
        text,
        sourceOrigin,
        frameOrigin,
        visibilityClass: "metadata",
        extractionMethod: "api",
        taintClass: trustSignals.taintClass,
        lineageChain: trustSignals.lineageChain,
        supportingDigest: sourceDigest
      })
    );
    blockedChannels.push("api_field");
  }

  for (const url of capture.linkedUrls ?? []) {
    const parsedLink = buildOfficeLinkTarget(
      { href: url, text: url, frameOrigin },
      sourceOrigin,
      frameOrigin,
      trustSignals,
      sourceDigest
    );
    if (!parsedLink) {
      continue;
    }
    spans.push(parsedLink.span);
    extractedTargets.push(parsedLink.target);
  }

  for (const action of capture.actionCandidates ?? []) {
    const span = buildSpan({
      channel: "visible_text",
      text: `${action.kind.replaceAll("_", " ")} ${action.pathTemplate}`,
      sourceOrigin,
      frameOrigin,
      visibilityClass: "visible",
      extractionMethod: "api",
      taintClass: trustSignals.taintClass,
      lineageChain: trustSignals.lineageChain,
      supportingDigest: sourceDigest,
      visibleOnlyFlag: true
    });
    spans.push(span);
    extractedTargets.push({
      targetId: randomUUID(),
      kind: action.kind,
      operationClass: action.kind,
      sourceSpanIds: [span.spanId],
      sourceOrigin,
      frameOrigin,
      targetOrigin: normalizeOrigin(action.baseUrl),
      displayText: `${action.method} ${action.pathTemplate}`,
      providerId: action.providerId,
      operationId: action.operationId,
      method: action.method,
      pathTemplate: action.pathTemplate,
      requestSchemaHash: action.requestSchemaHash,
      responseSchemaHash: action.responseSchemaHash,
      resourceId: action.resourceId,
      sourceChannelSet: ["visible_text"],
      visibleOnlyFlag: true
    });
  }

  if ((capture.responseFields?.length ?? 0) > 0) {
    riskFindings.push("api_response_fields_present");
  }
  if (!capture.extractionAttestation) {
    riskFindings.push("surface_attestation_missing");
  }

  return {
    spans,
    extractedFacts: uniq(extractedFacts),
    extractedTargets,
    riskFindings: uniq(riskFindings),
    blockedChannels: uniq(blockedChannels),
    parseStatus: spans.length || extractedFacts.length ? "compiled" : "unsupported"
  };
}

function flattenAttachmentNodes(
  nodes: AttachmentNodeCapture[],
  facts: string[],
  blockedChildren: string[],
  unsupportedChildren: string[],
  riskFindings: string[]
): void {
  for (const node of nodes) {
    facts.push(`attachment: ${normalizeText(node.filename)}`);
    if (node.encrypted || node.passwordProtected) {
      blockedChildren.push(node.attachmentId);
      riskFindings.push("encrypted_attachment_present");
    }
    if (node.unsupported) {
      unsupportedChildren.push(node.attachmentId);
      riskFindings.push("unsupported_nested_renderer");
    }
    if (node.blockedActiveContent) {
      blockedChildren.push(node.attachmentId);
      riskFindings.push("blocked_active_content_child");
    }
    if ((node.externalReferences?.length ?? 0) > 0) {
      riskFindings.push("external_relationship_hydration_attempt");
    }
    flattenAttachmentNodes(
      node.children ?? [],
      facts,
      blockedChildren,
      unsupportedChildren,
      riskFindings
    );
  }
}

function parseAttachmentBundleCapture(
  capture: AttachmentBundleSurfaceCapture,
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
  const blockedChildren: string[] = [];
  const unsupportedChildren: string[] = [];
  const riskFindings: string[] = [];
  const extractedFacts: string[] = [...extractionAttestationFacts(capture.extractionAttestations?.[0])];
  flattenAttachmentNodes(
    capture.attachments,
    extractedFacts,
    blockedChildren,
    unsupportedChildren,
    riskFindings
  );

  const spans = uniq([...blockedChildren, ...unsupportedChildren]).map((nodeId) =>
    buildSpan({
      channel: "attachment_reference",
      text: nodeId,
      sourceOrigin,
      frameOrigin,
      visibilityClass: "metadata",
      extractionMethod: "extractor",
      taintClass: trustSignals.taintClass,
      lineageChain: trustSignals.lineageChain,
      supportingDigest: sourceDigest
    })
  );

  return {
    spans,
    extractedFacts: uniq(extractedFacts),
    extractedTargets: [],
    riskFindings: uniq([
      ...riskFindings,
      ...(capture.extractionAttestations?.length ? [] : ["surface_attestation_missing"])
    ]),
    blockedChannels: spans.length ? ["attachment_reference"] : [],
    parseStatus: capture.attachments.length ? "compiled" : "unsupported"
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
  capture = materializeBinarySurfaceCapture(capture);
  const trustSignals = normalizeTrustSignals({
    sourceOrigin: capture.url,
    frameOrigin: capture.frameUrl ?? capture.url,
    userSharedFlag: capture.userShared ?? false,
    sessionDiscoveredFlag: !(capture.userShared ?? false),
    artifactKind:
      capture.surfaceType === "email_message"
        ? "email_message"
        : capture.surfaceType === "docx"
          ? "docx"
          : capture.surfaceType === "xlsx"
            ? "xlsx"
            : capture.surfaceType === "pptx"
              ? "pptx"
              : capture.surfaceType === "attachment_bundle"
                ? "attachment_bundle"
                : capture.surfaceType === "external_api_response"
                  ? "external_api_response"
                  : capture.surfaceType === "tool_manifest"
                    ? "tool_manifest"
                    : capture.surfaceType === "memory_candidate"
                      ? "memory"
                      : capture.surfaceType === "html"
                        ? "page"
                        : capture.surfaceType,
    extractionMethod:
      capture.surfaceType === "html"
        ? "dom"
        : capture.surfaceType === "email_message"
          ? "mime"
          : capture.surfaceType === "docx" ||
              capture.surfaceType === "xlsx" ||
              capture.surfaceType === "pptx"
            ? "ooxml"
            : capture.surfaceType === "attachment_bundle"
              ? "extractor"
              : capture.surfaceType === "tool_manifest" || capture.surfaceType === "memory_candidate"
                ? "api"
                : capture.surfaceType === "external_api_response"
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
          : capture.surfaceType === "email_message"
            ? parseEmailCapture(capture, trustSignals, sourceDigest)
            : capture.surfaceType === "docx" ||
                capture.surfaceType === "xlsx" ||
                capture.surfaceType === "pptx"
              ? parseOfficeCapture(capture, trustSignals, sourceDigest)
              : capture.surfaceType === "attachment_bundle"
                ? parseAttachmentBundleCapture(capture, trustSignals, sourceDigest)
                : capture.surfaceType === "external_api_response"
                  ? parseExternalApiCapture(capture, trustSignals, sourceDigest)
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
            : capture.surfaceType === "email_message"
              ? "email"
              : capture.surfaceType === "docx" ||
                  capture.surfaceType === "xlsx" ||
                  capture.surfaceType === "pptx"
                ? "office_document"
                : capture.surfaceType === "attachment_bundle"
                  ? "attachment_bundle"
                  : capture.surfaceType === "external_api_response"
                    ? "api_response"
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
      [
        "hidden_text",
        "metadata",
        "annotation",
        "comment",
        "schema",
        "memory_candidate",
        "email_header",
        "quoted_thread",
        "remote_content",
        "auth_result",
        "office_comment",
        "office_note",
        "office_formula",
        "hidden_sheet",
        "hidden_slide",
        "tracked_change",
        "embedded_object",
        "external_relationship",
        "api_field",
        "recipient",
        "attachment_reference"
      ].includes(span.channel)
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
          mode: "scrubbed_process",
          processIsolated: false,
          envScrubbed: false,
          egressDenied: false,
          permissionModelEnabled: false,
          fsReadRestricted: false,
          childProcessDenied: false,
          workerThreadsDenied: false,
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

export function applyFailClosedObservationMediation(
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

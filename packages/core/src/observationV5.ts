import { randomUUID } from "node:crypto";

import { parse as parseHtmlDocument } from "parse5";

import { compileObservation } from "./observationV4.js";
import { redactSecretsInText } from "./secretIsolation.js";
import { sanitizeObservation } from "./sanitize.js";
import { normalizeTrustSignals } from "./trust.js";
import type {
  CompiledObservation,
  CompiledObservationV5,
  ExtractedTarget,
  HtmlSurfaceCapture,
  ParserIsolationReport,
  PlannerViewV5,
  ProvenanceChannel,
  ProvenanceSpan,
  RuntimeContext,
  SafeVerdict,
  SurfaceCapture
} from "./types.js";
import { clamp, normalizeOrigin, normalizeText, sha256Hex, stableStringify, uniq } from "./utils.js";

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

const UNSUPPORTED_NESTED_TAGS = new Set([
  "iframe",
  "object",
  "embed",
  "svg",
  "math",
  "canvas",
  "foreignobject"
]);

const SKIP_VISIBLE_TEXT_TAGS = new Set(["script", "style", "template", "noscript"]);
const HEAD_METADATA_TAGS = new Set(["meta", "title"]);

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

function getAttr(node: HtmlNode, name: string): string | undefined {
  return node.attrs?.find((attr) => attr.name.toLowerCase() === name)?.value;
}

function elementHasHiddenSignal(node: HtmlNode): boolean {
  if (!node.tagName) {
    return false;
  }
  const hidden = getAttr(node, "hidden");
  const ariaHidden = getAttr(node, "aria-hidden");
  const inert = getAttr(node, "inert");
  const style = getAttr(node, "style")?.toLowerCase() ?? "";

  return (
    hidden !== undefined ||
    inert !== undefined ||
    ariaHidden === "true" ||
    /display\s*:\s*none/.test(style) ||
    /visibility\s*:\s*hidden/.test(style)
  );
}

function textContent(node: HtmlNode, skipHiddenDescendants = false): string {
  if (node.nodeName === "#text") {
    return normalizeText(node.value ?? "");
  }
  if (node.nodeName === "#comment") {
    return "";
  }
  if (node.tagName && SKIP_VISIBLE_TEXT_TAGS.has(node.tagName.toLowerCase())) {
    return "";
  }

  const hidden = elementHasHiddenSignal(node);
  if (skipHiddenDescendants && hidden) {
    return "";
  }

  return normalizeText((node.childNodes ?? []).map((child) => textContent(child, skipHiddenDescendants)).join(" "));
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
  sourceNodePathHash?: string;
  blockedForAuthority?: boolean;
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
    sourceNodePathHash: input.sourceNodePathHash,
    blockedForAuthority: input.blockedForAuthority,
    visibleOnlyFlag: input.visibleOnlyFlag
  };
}

function nodePathHash(path: string[]): string {
  return sha256Hex(path.join(">"));
}

function deriveBlockedChannels(spans: ProvenanceSpan[], riskFindings: string[]): ProvenanceChannel[] {
  const channels = spans
    .filter((span) => span.blockedForAuthority)
    .map((span) => span.channel);
  if (riskFindings.includes("nested_unparsed_component")) {
    channels.push("annotation");
  }
  return uniq(channels);
}

function parseHtmlCaptureV5(
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
  if (!html && !capture.visibleText) {
    return {
      spans: [],
      extractedFacts: [],
      extractedTargets: [],
      riskFindings: [],
      blockedChannels: [],
      parseStatus: "unsupported"
    };
  }

  const sourceOrigin = normalizeOrigin(capture.url);
  const frameOrigin = normalizeOrigin(capture.frameUrl ?? capture.url);
  const spans: ProvenanceSpan[] = [];
  const extractedFacts: string[] = [];
  const extractedTargets: ExtractedTarget[] = [];
  const riskFindings: string[] = [];

  const document = html ? (parseHtmlDocument(html) as unknown as HtmlNode) : undefined;
  const pathStack: string[] = [];
  const visibleParts: string[] = [];
  let nestedUnsupportedFound = false;

  function walk(node: HtmlNode, state: { hidden: boolean; inHead: boolean }): void {
    const nodeName = node.nodeName?.toLowerCase() ?? "";
    const tagName = node.tagName?.toLowerCase();

    if (nodeName === "#comment") {
      const commentText = normalizeText(node.data ?? node.value ?? "");
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
            supportingDigest: sourceDigest,
            sourceNodePathHash: nodePathHash([...pathStack, "#comment"]),
            blockedForAuthority: true
          })
        );
        riskFindings.push("html_comment_channel_present");
      }
      return;
    }

    if (nodeName === "#text") {
      const text = normalizeText(node.value ?? "");
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
            supportingDigest: sourceDigest,
            sourceNodePathHash: nodePathHash([...pathStack, "#text"]),
            blockedForAuthority: true
          })
        );
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

    const currentPath = [...pathStack, tagName];
    pathStack.push(tagName);

    const hidden = state.hidden || elementHasHiddenSignal(node);
    const inHead = state.inHead || tagName === "head";

    if (UNSUPPORTED_NESTED_TAGS.has(tagName)) {
      nestedUnsupportedFound = true;
    }

    if (tagName === "title") {
      const title = textContent(node, false);
      if (title) {
        extractedFacts.push(`title: ${title}`);
      }
    } else if (tagName === "meta") {
      const metaName = getAttr(node, "name") ?? getAttr(node, "property");
      const metaContent = getAttr(node, "content");
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
            supportingDigest: sourceDigest,
            sourceNodePathHash: nodePathHash(currentPath)
          })
        );
      }
    } else if (tagName === "a" && !hidden) {
      const href = getAttr(node, "href");
      const linkText = textContent(node, true);
      if (href && normalizeText(href)) {
        const span = buildSpan({
          channel: "link",
          text: linkText || href,
          sourceOrigin,
          frameOrigin,
          visibilityClass: "visible",
          extractionMethod: "dom",
          taintClass: trustSignals.taintClass,
          lineageChain: trustSignals.lineageChain,
          selector: `a[href="${href}"]`,
          supportingDigest: sourceDigest,
          sourceNodePathHash: nodePathHash(currentPath),
          visibleOnlyFlag: true
        });
        spans.push(span);
        extractedTargets.push({
          targetId: randomUUID(),
          kind: "navigate",
          href,
          selector: span.selector,
          sourceSpanIds: [span.spanId],
          sourceOrigin,
          frameOrigin,
          targetOrigin: normalizeOrigin(href),
          displayText: span.text || href,
          sourceNodePathHash: span.sourceNodePathHash,
          sourceChannelSet: ["link"],
          visibleOnlyFlag: true
        });
      }
    }

    if (!SKIP_VISIBLE_TEXT_TAGS.has(tagName) && !HEAD_METADATA_TAGS.has(tagName)) {
      for (const child of node.childNodes ?? []) {
        walk(child, { hidden, inHead });
      }
    }

    pathStack.pop();
  }

  if (document) {
    walk(document, { hidden: false, inHead: false });
  }

  const visibleText = normalizeText(capture.visibleText ?? visibleParts.join(" "));
  if (visibleText) {
    spans.unshift(
      buildSpan({
        channel: "visible_text",
        text: visibleText,
        sourceOrigin,
        frameOrigin,
        visibilityClass: "visible",
        extractionMethod: "dom",
        taintClass: trustSignals.taintClass,
        lineageChain: trustSignals.lineageChain,
        supportingDigest: sourceDigest,
        sourceNodePathHash: nodePathHash(["visible_text"]),
        visibleOnlyFlag: true
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
        channel: "hidden_text",
        text,
        sourceOrigin,
        frameOrigin,
        visibilityClass: "hidden",
        extractionMethod: "dom",
        taintClass: trustSignals.taintClass,
        lineageChain: trustSignals.lineageChain,
        supportingDigest: sourceDigest,
        sourceNodePathHash: nodePathHash(["hidden_text", text]),
        blockedForAuthority: true
      })
    );
  }

  for (const value of capture.annotations ?? []) {
    const text = normalizeText(value);
    if (!text) {
      continue;
    }
    spans.push(
      buildSpan({
        channel: "annotation",
        text,
        sourceOrigin,
        frameOrigin,
        visibilityClass: "annotation",
        extractionMethod: "dom",
        taintClass: trustSignals.taintClass,
        lineageChain: trustSignals.lineageChain,
        supportingDigest: sourceDigest,
        sourceNodePathHash: nodePathHash(["annotation", text]),
        blockedForAuthority: true
      })
    );
  }

  if (capture.nestedUnsupportedComponents?.length || nestedUnsupportedFound) {
    riskFindings.push("nested_unparsed_component");
    extractedFacts.push(
      ...(capture.nestedUnsupportedComponents ?? []).map((entry) => `nested unsupported component: ${normalizeText(entry)}`)
    );
  }

  const blockedChannels = deriveBlockedChannels(spans, riskFindings);
  const parseStatus: CompiledObservation["parseStatus"] =
    nestedUnsupportedFound || (capture.nestedUnsupportedComponents?.length ?? 0) > 0
      ? "partial"
      : spans.length
        ? "compiled"
        : "unsupported";

  return {
    spans,
    extractedFacts: uniq(extractedFacts),
    extractedTargets,
    riskFindings: uniq(riskFindings),
    blockedChannels,
    parseStatus
  };
}

function buildPlannerViewV5(compiledObservation: CompiledObservation): PlannerViewV5 {
  const visibleExcerpt = redactSecretsInText(
    compiledObservation.spans
      .filter((span) => span.channel === "visible_text")
      .map((span) => span.text)
      .join(" ")
  ).text.slice(0, 3000);

  const quotedTaintedBlocks = compiledObservation.spans
    .filter(
      (span) =>
        span.blockedForAuthority ||
        ["metadata", "annotation", "schema", "memory_candidate"].includes(span.channel)
    )
    .slice(0, 6)
    .map((span) => ({
      channel: span.channel,
      text: redactSecretsInText(span.text).text.slice(0, 500),
      spanId: span.spanId
    }));

  const blockedChannels = uniq(
    compiledObservation.spans
      .filter((span) => span.blockedForAuthority)
      .map((span) => span.channel)
  );

  return {
    observationId: compiledObservation.observationId,
    sessionId: compiledObservation.sessionId,
    surfaceType: compiledObservation.surfaceType,
    visibleExcerpt,
    facts: compiledObservation.extractedFacts.map((fact) => redactSecretsInText(fact).text),
    quotedTaintedBlocks,
    blockedChannels,
    riskMarkers: uniq([
      ...compiledObservation.suspicionFlags,
      ...compiledObservation.riskFindings,
      ...(compiledObservation.secretFindings.length ? ["secret_redaction_applied"] : [])
    ]),
    secretRedactionsApplied: compiledObservation.secretFindings.length > 0
  };
}

export function compileObservationV5(
  capture: SurfaceCapture,
  context: Partial<RuntimeContext> = {},
  options: {
    parserIsolation?: ParserIsolationReport;
    workflowHash?: string;
  } = {}
): {
  compiledObservation: CompiledObservationV5;
  plannerView: PlannerViewV5;
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
            : "download"
  });
  const sourceDigest = hashSurface(capture);

  if (capture.surfaceType !== "html") {
    const base = compileObservation(
      {
        ...capture,
        trustSignals: undefined
      } as SurfaceCapture,
      context,
      options
    );
    const normalizedSpans =
      capture.surfaceType === "tool_manifest"
        ? base.compiledObservation.spans.map((span) =>
            span.channel === "visible_text"
              ? {
                  ...span,
                  visibleOnlyFlag: true
                }
              : span
          )
        : base.compiledObservation.spans;
    const normalizedTargets =
      capture.surfaceType === "tool_manifest"
        ? base.compiledObservation.extractedTargets.map((target) => ({
            ...target,
            visibleOnlyFlag: true,
            sourceChannelSet: ["visible_text" as ProvenanceChannel]
          }))
        : base.compiledObservation.extractedTargets;
    const authorityEligible =
      base.compiledObservation.parseStatus === "compiled" &&
      !base.plannerInput.blockedChannels.length &&
      !base.compiledObservation.secretFindings.length &&
      !base.compiledObservation.riskFindings.length;

    const compiledObservation: CompiledObservationV5 = {
      ...base.compiledObservation,
      spans: normalizedSpans,
      extractedTargets: normalizedTargets,
      authorityEligible,
      provenanceDigest: sha256Hex(
        stableStringify({
          observationId: base.compiledObservation.observationId,
          sourceDigest: base.compiledObservation.sourceDigest,
          spans: normalizedSpans.map((span) => ({
            spanId: span.spanId,
            channel: span.channel,
            sourceNodePathHash: span.sourceNodePathHash ?? null
          }))
        })
      )
    };

    return {
      compiledObservation,
      plannerView: buildPlannerViewV5(compiledObservation)
    };
  }

  const parsed = parseHtmlCaptureV5(capture, trustSignals, sourceDigest);
  const aggregateText = parsed.spans.map((span) => span.text).join(" ");
  const legacyObservation = sanitizeObservation(
    {
      observationId: capture.captureId,
      taskId: capture.taskId,
      sourceType: "page",
      text: aggregateText,
      fragments: parsed.spans.map((span) => ({
        text: span.text,
        visibilityClass: span.visibilityClass,
        medium:
          span.channel === "annotation"
            ? "annotation"
            : span.channel === "metadata"
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

  const secretFindings = uniq(
    parsed.spans.flatMap((span) => redactSecretsInText(span.text).secretFindings)
  );

  const compiledObservation: CompiledObservationV5 = {
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
    extractedFacts: parsed.extractedFacts.map((fact) => redactSecretsInText(fact).text),
    extractedTargets: parsed.extractedTargets,
    riskFindings: uniq(parsed.riskFindings),
    suspicionFlags: legacyObservation.suspicionFlags,
    matchedPatternIds: legacyObservation.matchedPatternIds,
    riskScore: clamp(Math.max(legacyObservation.riskScore, parsed.riskFindings.length * 0.1)),
    secretFindings,
    createdAt: legacyObservation.createdAt,
    authorityEligible:
      parsed.parseStatus === "compiled" &&
      !parsed.blockedChannels.length &&
      !parsed.riskFindings.length &&
      !secretFindings.length,
    provenanceDigest: sha256Hex(
      stableStringify({
        sourceDigest,
        spans: parsed.spans.map((span) => ({
          spanId: span.spanId,
          channel: span.channel,
          sourceNodePathHash: span.sourceNodePathHash ?? null,
          blockedForAuthority: Boolean(span.blockedForAuthority)
        })),
        targets: parsed.extractedTargets.map((target) => ({
          kind: target.kind,
          href: target.href ?? null,
          sourceNodePathHash: target.sourceNodePathHash ?? null
        }))
      })
    )
  };

  return {
    compiledObservation,
    plannerView: buildPlannerViewV5(compiledObservation)
  };
}

export function applyV5ObservationMediation(
  compiledObservation: CompiledObservationV5,
  plannerView: PlannerViewV5
): {
  plannerView: PlannerViewV5;
  verdict: SafeVerdict;
  failClosed: boolean;
} {
  if (compiledObservation.parseStatus === "compiled") {
    return {
      plannerView,
      verdict: {
        decision: "ALLOW",
        reasonCodes: compiledObservation.authorityEligible ? [] : ["AUTHORITY_REDUCED_TO_FACTS_ONLY"],
        riskScore: clamp(Math.max(0.05, compiledObservation.riskScore)),
        safeConstraints: {
          authority_eligible: compiledObservation.authorityEligible,
          claim_profile: "secure_v5"
        },
        telemetryTags: uniq([
          "v5_observation",
          compiledObservation.authorityEligible ? "authority_eligible" : "facts_only"
        ])
      },
      failClosed: false
    };
  }

  return {
    plannerView: {
      ...plannerView,
      visibleExcerpt: "",
      facts: [],
      quotedTaintedBlocks: [],
      riskMarkers: uniq([
        ...plannerView.riskMarkers,
        `parse_status_${compiledObservation.parseStatus}`
      ])
    },
    verdict: {
      decision: "BLOCK",
      reasonCodes: [
        compiledObservation.parseStatus === "partial"
          ? "PARSE_STATUS_PARTIAL"
          : "PARSE_STATUS_UNSUPPORTED"
      ],
      riskScore: 0.98,
      safeConstraints: {
        parse_status: compiledObservation.parseStatus,
        planner_safe_content_removed: true,
        claim_profile: "secure_v5"
      },
      telemetryTags: uniq(["v5_observation", compiledObservation.parseStatus, "fail_closed"])
    },
    failClosed: true
  };
}

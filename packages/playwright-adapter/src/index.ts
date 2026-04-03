import type {
  ActionProposal,
  HtmlSurfaceCapture,
  RawObservationInput,
  SafeVerdict
} from "@safebrowse/core";

export interface PageLike {
  url(): string;
  content?(): Promise<string>;
  title?(): Promise<string>;
  visibleText?(): Promise<string>;
}

export interface PlaywrightPageSnapshot {
  url: string;
  frameUrl?: string;
  visibleText: string;
  html?: string;
  hiddenText?: string | string[];
  metadataText?: string[];
  annotations?: string[];
  renderedText?: string;
  extractedText?: string;
  userShared?: boolean;
}

export interface V6AuthorityCandidateRef {
  authorityId: string;
  authorityDigest: string;
}

export function createObservationFromSnapshot(
  snapshot: PlaywrightPageSnapshot
): RawObservationInput {
  const hiddenText = Array.isArray(snapshot.hiddenText)
    ? snapshot.hiddenText
    : snapshot.hiddenText
      ? [snapshot.hiddenText]
      : [];

  return {
    sourceType: "page",
    text: snapshot.visibleText,
    fragments: [
      {
        text: snapshot.visibleText,
        visibilityClass: "visible",
        medium: "text",
        sourceOrigin: snapshot.url,
        frameOrigin: snapshot.frameUrl ?? snapshot.url
      },
      ...hiddenText.map((text) => ({
        text,
        visibilityClass: "hidden" as const,
        medium: "metadata" as const,
        sourceOrigin: snapshot.url,
        frameOrigin: snapshot.frameUrl ?? snapshot.url
      })),
      ...(snapshot.metadataText ?? []).map((text) => ({
        text,
        visibilityClass: "metadata" as const,
        medium: "metadata" as const,
        sourceOrigin: snapshot.url,
        frameOrigin: snapshot.frameUrl ?? snapshot.url
      }))
    ],
    trustSignals: {
      sourceOrigin: snapshot.url,
      frameOrigin: snapshot.frameUrl ?? snapshot.url,
      userSharedFlag: snapshot.userShared ?? false,
      sessionDiscoveredFlag: !(snapshot.userShared ?? false)
    }
  };
}

export function createSurfaceCaptureFromSnapshot(
  snapshot: PlaywrightPageSnapshot
): HtmlSurfaceCapture {
  const hiddenText = Array.isArray(snapshot.hiddenText)
    ? snapshot.hiddenText
    : snapshot.hiddenText
      ? [snapshot.hiddenText]
      : [];

  return {
    surfaceType: "html",
    url: snapshot.url,
    frameUrl: snapshot.frameUrl,
    html: snapshot.html,
    visibleText: snapshot.visibleText,
    hiddenText,
    metadataText: snapshot.metadataText,
    annotations: snapshot.annotations,
    userShared: snapshot.userShared
  };
}

export function buildObservePayloadV6(sessionId: string, snapshot: PlaywrightPageSnapshot) {
  return {
    sessionId,
    capture: createSurfaceCaptureFromSnapshot(snapshot)
  };
}

export function buildArtifactIngestPayloadV6(sessionId: string, snapshot: PlaywrightPageSnapshot) {
  return buildObservePayloadV6(sessionId, snapshot);
}

export function buildActionEvaluatePayloadV6(
  sessionId: string,
  authority: V6AuthorityCandidateRef,
  parameters?: Record<string, unknown>
) {
  return {
    sessionId,
    authorityId: authority.authorityId,
    authorityDigest: authority.authorityDigest,
    parameters
  };
}

export function proposeNavigationAction(input: {
  actionId: string;
  currentUrl: string;
  targetUrl: string;
  riskClass?: ActionProposal["riskClass"];
  requestedWrite?: boolean;
}): ActionProposal {
  return {
    actionId: input.actionId,
    verb: "navigate",
    currentOrigin: input.currentUrl,
    targetUrl: input.targetUrl,
    riskClass: input.riskClass ?? "low",
    requestedWrite: input.requestedWrite ?? false,
    trustSignals: {
      sourceOrigin: input.currentUrl,
      frameOrigin: input.currentUrl
    }
  };
}

export async function snapshotPage(page: PageLike): Promise<PlaywrightPageSnapshot> {
  const [html, title] = await Promise.all([
    page.content?.() ?? Promise.resolve(""),
    page.title?.() ?? Promise.resolve("")
  ]);
  const visibleText = page.visibleText
    ? await page.visibleText()
    : html
        .replace(/<script[\s\S]*?<\/script>/gi, " ")
        .replace(/<style[\s\S]*?<\/style>/gi, " ")
        .replace(/<!--[\s\S]*?-->/g, " ")
        .replace(/<[^>]+>/g, " ")
        .replace(/\s+/g, " ")
        .trim();

  return {
    url: page.url(),
    visibleText,
    html,
    metadataText: title ? [title] : []
  };
}

export async function enforceVerdict<T>(
  verdict: SafeVerdict,
  allowedAction: () => Promise<T>
): Promise<T> {
  if (verdict.decision !== "ALLOW") {
    throw new Error(
      `SafeBrowse blocked adapter execution with decision ${verdict.decision}: ${verdict.reasonCodes.join(", ")}`
    );
  }
  return allowedAction();
}


import type { ActionProposal, RawObservationInput, SafeVerdict } from "@safebrowse/core";

export interface PageLike {
  url(): string;
  content?(): Promise<string>;
  title?(): Promise<string>;
}

export interface PlaywrightPageSnapshot {
  url: string;
  frameUrl?: string;
  visibleText: string;
  hiddenText?: string;
  metadataText?: string[];
  annotations?: string[];
  renderedText?: string;
  extractedText?: string;
  userShared?: boolean;
}

export function createObservationFromSnapshot(
  snapshot: PlaywrightPageSnapshot
): RawObservationInput {
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
      ...(snapshot.hiddenText
        ? [
            {
              text: snapshot.hiddenText,
              visibilityClass: "hidden" as const,
              medium: "metadata" as const,
              sourceOrigin: snapshot.url,
              frameOrigin: snapshot.frameUrl ?? snapshot.url
            }
          ]
        : []),
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

  return {
    url: page.url(),
    visibleText: html,
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


import type {
  ActionProposal,
  CaptureAttestation,
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
  captureAttestation?: CaptureAttestation;
}

export interface V6AuthorityCandidateRef {
  authorityId: string;
  authorityDigest: string;
}

export interface EmailSnapshot {
  url: string;
  providerId: string;
  subject: string;
  bodyText: string;
  rawMimeBase64?: string;
  mailboxId?: string;
  accountId?: string;
  messageId?: string;
  threadId?: string;
  to?: string[];
  cc?: string[];
  headers?: string[];
  authResults?: string[];
  quotedThreadText?: string[];
  remoteContent?: string[];
  actionCandidates?: Array<Record<string, unknown>>;
  attachments?: Array<Record<string, unknown>>;
}

export interface OfficeDocumentSnapshot {
  surfaceType: "docx" | "xlsx" | "pptx";
  url: string;
  visibleText: string;
  contentBase64?: string;
  metadataText?: string[];
  comments?: string[];
  notes?: string[];
  trackedChanges?: string[];
  hiddenText?: string[];
  formulas?: string[];
  externalRelationships?: string[];
  embeddedObjects?: string[];
  links?: Array<{ href: string; text?: string; selector?: string }>;
  attachments?: Array<Record<string, unknown>>;
  unsupportedSubtrees?: string[];
}

export interface ExternalApiSnapshot {
  url: string;
  providerId: string;
  operationId: string;
  method: string;
  baseUrl: string;
  pathTemplate: string;
  responseText?: string;
  responseFields?: string[];
  linkedUrls?: string[];
  actionCandidates?: Array<Record<string, unknown>>;
  requestSchemaHash?: string;
  responseSchemaHash?: string;
}

export interface AttachmentBundleSnapshot {
  url: string;
  rootAttachmentId?: string;
  attachments: Array<Record<string, unknown>>;
  extractionAttestations?: Array<Record<string, unknown>>;
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
    userShared: snapshot.userShared,
    captureAttestation:
      snapshot.captureAttestation ?? {
        captureMethod: "rendered_dom",
        visibilityAttested: Boolean(snapshot.visibleText.trim()),
        frameCoverage: "full",
        shadowDomCoverage: "full",
        unsupportedSubtrees: []
      }
  };
}

export function buildObservePayloadV6(sessionId: string, snapshot: PlaywrightPageSnapshot) {
  return {
    sessionId,
    capture: createSurfaceCaptureFromSnapshot(snapshot)
  };
}

export function buildArtifactIngestPayloadV6(sessionId: string, snapshot: PlaywrightPageSnapshot) {
  return {
    sessionId,
    capture: createSurfaceCaptureFromSnapshot(snapshot)
  };
}

export function buildEmailObservePayloadV6(sessionId: string, snapshot: EmailSnapshot) {
  return {
    sessionId,
    capture: {
      surfaceType: "email_message",
      url: snapshot.url,
      providerId: snapshot.providerId,
      subject: snapshot.subject,
      bodyText: snapshot.bodyText,
      rawMimeBase64: snapshot.rawMimeBase64,
      mailboxId: snapshot.mailboxId,
      accountId: snapshot.accountId,
      messageId: snapshot.messageId,
      threadId: snapshot.threadId,
      to: snapshot.to ?? [],
      cc: snapshot.cc ?? [],
      headers: snapshot.headers ?? [],
      authResults: snapshot.authResults ?? [],
      quotedThreadText: snapshot.quotedThreadText ?? [],
      remoteContent: snapshot.remoteContent ?? [],
      actionCandidates: snapshot.actionCandidates ?? [],
      attachments: snapshot.attachments ?? [],
      extractionAttestation: {
        extractorId: "playwright-email-extractor",
        extractorVersion: "1.0.0",
        parserDigest: "playwright-email-extractor",
        networkPolicy: "deny",
        maxRecursionDepth: 3,
        maxExpandedBytes: 5000000,
        extractedAt: new Date().toISOString()
      }
    }
  };
}

export function buildOfficeArtifactIngestPayloadV6(
  sessionId: string,
  snapshot: OfficeDocumentSnapshot
) {
  return {
    sessionId,
    capture: {
      ...snapshot,
      extractionAttestation: {
        extractorId: `playwright-${snapshot.surfaceType}-extractor`,
        extractorVersion: "1.0.0",
        parserDigest: `playwright-${snapshot.surfaceType}-extractor`,
        networkPolicy: "deny",
        maxRecursionDepth: 3,
        maxExpandedBytes: 5000000,
        extractedAt: new Date().toISOString()
      }
    }
  };
}

export function buildExternalApiObservePayloadV6(
  sessionId: string,
  snapshot: ExternalApiSnapshot
) {
  return {
    sessionId,
    capture: {
      surfaceType: "external_api_response",
      ...snapshot,
      extractionAttestation: {
        extractorId: "playwright-api-extractor",
        extractorVersion: "1.0.0",
        parserDigest: "playwright-api-extractor",
        networkPolicy: "deny",
        maxRecursionDepth: 3,
        maxExpandedBytes: 5000000,
        extractedAt: new Date().toISOString()
      }
    }
  };
}

export function buildAttachmentExtractPayloadV6(
  sessionId: string,
  snapshot: AttachmentBundleSnapshot
) {
  return {
    sessionId,
    capture: {
      surfaceType: "attachment_bundle",
      ...snapshot,
      extractionAttestations:
        snapshot.extractionAttestations ??
        [
          {
            extractorId: "playwright-attachment-extractor",
            extractorVersion: "1.0.0",
            parserDigest: "playwright-attachment-extractor",
            networkPolicy: "deny",
            maxRecursionDepth: 3,
            maxExpandedBytes: 5000000,
            extractedAt: new Date().toISOString()
          }
        ]
    }
  };
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
  const visibleText = page.visibleText ? await page.visibleText() : "";

  return {
    url: page.url(),
    visibleText,
    html,
    metadataText: title ? [title] : [],
    captureAttestation: {
      captureMethod: "rendered_dom",
      visibilityAttested: Boolean(visibleText.trim()),
      frameCoverage: "full",
      shadowDomCoverage: "full",
      unsupportedSubtrees: []
    }
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

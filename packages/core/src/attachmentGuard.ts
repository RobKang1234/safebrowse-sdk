import { randomUUID } from "node:crypto";

import type {
  AttachmentBundleSurfaceCapture,
  AttachmentGraphNode,
  AttachmentNodeCapture,
  ArtifactExtractionResponseV6,
  ArtifactKind,
  ExtractionAttestation,
  RuntimeContext,
  SafeDecision,
  SafeVerdict,
  TaintClass,
  V6ArtifactRef
} from "./types.js";
import { clamp, normalizeOrigin, uniq } from "./utils.js";

function surfaceKindFromNode(node: AttachmentNodeCapture): ArtifactKind {
  switch (node.surface?.surfaceType) {
    case "email_message":
      return "email_message";
    case "docx":
      return "docx";
    case "xlsx":
      return "xlsx";
    case "pptx":
      return "pptx";
    case "attachment_bundle":
      return "attachment_bundle";
    case "external_api_response":
      return "external_api_response";
    case "pdf":
      return "pdf";
    case "image":
      return "image";
    case "tool_manifest":
      return "tool_manifest";
    case "memory_candidate":
      return "memory";
    case "html":
      return "page";
    default:
      if (node.mimeType.includes("zip") || node.mimeType.includes("tar")) {
        return "archive";
      }
      return "document";
  }
}

function childVerdict(node: AttachmentNodeCapture, depthExceeded: boolean): SafeDecision {
  if (depthExceeded || node.unsupported || node.blockedActiveContent) {
    return "QUARANTINE_ARTIFACT";
  }
  if (node.encrypted || node.passwordProtected) {
    return "QUARANTINE_ARTIFACT";
  }
  return "ALLOW";
}

function childTaint(node: AttachmentNodeCapture): TaintClass {
  return node.unsupported || node.blockedActiveContent || node.encrypted || node.passwordProtected
    ? "tainted"
    : "session-discovered";
}

function childArtifactRef(
  node: AttachmentNodeCapture,
  parentOrigin: string,
  verdict: SafeDecision
): V6ArtifactRef {
  const taint = childTaint(node);
  return {
    artifactId: node.attachmentId,
    surfaceKind: surfaceKindFromNode(node),
    sourceOrigin: normalizeOrigin(node.surface?.url ?? parentOrigin),
    viewerOrigin: normalizeOrigin(node.surface?.frameUrl ?? node.surface?.url ?? parentOrigin),
    mismatchSignals: verdict === "ALLOW" ? [] : ["extraction_policy_restricted"],
    metadataSignals: uniq([
      ...(node.externalReferences?.length ? ["external_reference_present"] : []),
      ...(node.unsupported ? ["unsupported_child"] : []),
      ...(node.blockedActiveContent ? ["active_content_blocked"] : []),
      ...(node.encrypted || node.passwordProtected ? ["encrypted_child"] : [])
    ]),
    provenance: {
      extractionMethod: node.surface?.surfaceType === "external_api_response" ? "api" : "extractor",
      lineageChain: [node.attachmentId],
      derivedTaintClass: taint
    },
    authorityEligible: verdict === "ALLOW"
  };
}

function collectAttestations(
  node: AttachmentNodeCapture,
  target: ExtractionAttestation[]
): void {
  const attestation =
    node.surface && "extractionAttestation" in node.surface
      ? node.surface.extractionAttestation
      : undefined;
  if (attestation) {
    target.push(attestation);
  }
  for (const child of node.children ?? []) {
    collectAttestations(child, target);
  }
}

export function extractAttachmentGraphV6(
  capture: AttachmentBundleSurfaceCapture,
  context: Pick<RuntimeContext, "policy" | "verifiedRegistry">
): Omit<ArtifactExtractionResponseV6, "replayEventId"> {
  const nodes: AttachmentGraphNode[] = [];
  const childRefs: V6ArtifactRef[] = [];
  const blockedChildren: string[] = [];
  const unsupportedChildren: string[] = [];
  const extractionAttestations: ExtractionAttestation[] = [
    ...(capture.extractionAttestations ?? [])
  ];
  const verifiedExtractorIds = new Set(
    context.verifiedRegistry?.extractorProfiles?.map((entry) => entry.extractorId) ?? []
  );
  const maxDepth = context.policy.maxExtractionDepth;
  const maxExpandedBytes = context.policy.maxExpandedBytes;
  let expandedBytes = 0;

  function walk(
    attachments: AttachmentNodeCapture[],
    parentNodeId: string | undefined,
    depth: number
  ): string[] {
    return attachments.map((attachment) => {
      expandedBytes += attachment.sizeBytes ?? 0;
      const depthExceeded = depth > maxDepth || expandedBytes > maxExpandedBytes;
      const verdict = childVerdict(attachment, depthExceeded);
      if (attachment.unsupported || depthExceeded) {
        unsupportedChildren.push(attachment.attachmentId);
      }
      if (attachment.encrypted || attachment.passwordProtected || attachment.blockedActiveContent) {
        blockedChildren.push(attachment.attachmentId);
      }
      const nodeId = randomUUID();
      const childNodeIds = walk(attachment.children ?? [], nodeId, depth + 1);
      nodes.push({
        nodeId,
        parentNodeId,
        attachmentId: attachment.attachmentId,
        filename: attachment.filename,
        mimeType: attachment.mimeType,
        sha256: attachment.sha256,
        surfaceType: attachment.surface?.surfaceType,
        encrypted: attachment.encrypted,
        passwordProtected: attachment.passwordProtected,
        unsupported: attachment.unsupported || depthExceeded,
        blockedActiveContent: attachment.blockedActiveContent,
        childNodeIds,
        derivedVerdict: verdict
      });
      childRefs.push(childArtifactRef(attachment, capture.url, verdict));
      collectAttestations(attachment, extractionAttestations);
      return nodeId;
    });
  }

  const rootNodeIds = walk(capture.attachments, undefined, 1);
  const unverifiedExtractorPresent = extractionAttestations.some(
    (entry) =>
      (verifiedExtractorIds.size > 0 && !verifiedExtractorIds.has(entry.extractorId)) ||
      (context.policy.allowedExtractorIds.size > 0 &&
        !context.policy.allowedExtractorIds.has(entry.extractorId.toLowerCase()))
  );
  const verdictDecision: SafeDecision =
    blockedChildren.length || unsupportedChildren.length || unverifiedExtractorPresent
      ? "QUARANTINE_ARTIFACT"
      : "ALLOW";
  const verdict: SafeVerdict = {
    decision: verdictDecision,
    reasonCodes: uniq([
      ...(blockedChildren.length ? ["ATTACHMENT_CHILD_BLOCKED"] : []),
      ...(unsupportedChildren.length ? ["ATTACHMENT_CHILD_UNSUPPORTED"] : []),
      ...(expandedBytes > maxExpandedBytes ? ["ATTACHMENT_EXPANSION_LIMIT_REACHED"] : []),
      ...(unverifiedExtractorPresent ? ["EXTRACTOR_PROFILE_UNVERIFIED"] : [])
    ]),
    riskScore: clamp(
      blockedChildren.length || unsupportedChildren.length || expandedBytes > maxExpandedBytes
        ? 0.92
        : 0.15
    ),
    safeConstraints: {
      extraction_depth_limit: maxDepth,
      extraction_bytes_limit: maxExpandedBytes
    },
    telemetryTags: ["attachment_extract_v6", verdictDecision.toLowerCase()]
  };

  return {
    artifactGraph: {
      rootNodeIds,
      nodes
    },
    childRefs,
    blockedChildren: uniq(blockedChildren),
    unsupportedChildren: uniq(unsupportedChildren),
    extractionAttestations: uniq(
      extractionAttestations.map((entry) => JSON.stringify(entry))
    ).map((entry) => JSON.parse(entry) as ExtractionAttestation),
    artifactVerdict: verdict
  };
}

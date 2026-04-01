import { createHash, createPublicKey, randomUUID, type KeyObject } from "node:crypto";
import { readFile, stat } from "node:fs/promises";
import { createServer, type IncomingMessage, type Server, type ServerResponse } from "node:http";
import { resolve } from "node:path";
import { fileURLToPath } from "node:url";

import {
  applyV4FailClosedMediation,
  applyV5ObservationMediation,
  attachCapabilitiesToPlannerInput,
  brokerArtifact,
  brokerArtifactV2,
  buildReplayBundle,
  compilePolicy,
  compileObservationV5,
  createApprovalGrantHash,
  createApprovalIntentPayloadV5,
  evaluateAction,
  evaluateCapabilityUse,
  evaluateCapabilityUseV5,
  evaluateMemoryWrite,
  evaluateMemoryWriteV4,
  evaluateMemoryWriteV5,
  evaluateToolRequest,
  mintCapabilitiesForObservation,
  mintCapabilitiesForObservationV5,
  mintMemoryPromotionCapabilityV5,
  prepareToolOnboarding,
  prepareToolOnboardingV4,
  prepareToolOnboardingV5,
  promoteMemoryRecordV4,
  promoteMemoryRecordV5,
  rollbackMemoryRecordV4,
  rollbackMemoryRecordV5,
  sanitizeObservation,
  issueApprovalEnvelopeV5,
  verifyApprovalIntentSignatureV5,
  verifyToolCallback,
  verifyToolCallbackV4,
  verifyToolCallbackV5,
  type ActionProposal,
  type ApprovalGrant,
  type ApprovalEnvelopeV5,
  type ArtifactInput,
  type ArtifactV2Input,
  type CapabilityDescriptor,
  type CapabilityUseRequest,
  type CapabilityDescriptorV5,
  type CapabilityUseRequestV5,
  type CompiledObservation,
  type CompiledObservationV5,
  type ConnectorHandle,
  type KnowledgeBaseContext,
  type MemoryPromotionRequest,
  type MemoryPromotionRequestV5,
  type MemoryRecord,
  type MemoryRollbackRequest,
  type MemoryWriteRequestV5,
  type MemoryWriteRequest,
  type PolicyPack,
  type PlannerViewV5,
  type ReplayEvent,
  type RuntimeContext,
  type StructuredPlannerInput,
  type SurfaceCapture,
  type TaskSession,
  type ToolCallbackVerificationRequest,
  type ToolOnboardingSession,
  type ToolOnboardingSessionV5,
  type ToolRequest
} from "@safebrowse/core";
import {
  buildRegistryDefaults,
  loadKnowledgeBaseContext,
  loadVerifiedRegistryBundle,
  loadPolicyPackFromPaths,
  resolvePolicyLayerFiles
} from "./loaders.js";
import { compileObservationInIsolation, probeParserIsolation } from "./parserIsolation.js";
import type { VerifiedRegistryBundle, VerifiedRegistryEntry } from "@safebrowse/core";

export interface SafeBrowseDaemonOptions {
  host?: string;
  port?: number;
  rootDir?: string;
  policyPack?: PolicyPack;
  knowledgeBase?: KnowledgeBaseContext;
  verifiedRegistry?: VerifiedRegistryBundle;
  parserAllowlistedEgress?: string[];
  deploymentProfile?: "development" | "secure_v5";
  approvalBrokerPublicKeyPath?: string;
  approvalBrokerPublicKeyPem?: string;
}

interface SessionState {
  session: TaskSession;
  latestObservation?: CompiledObservation;
  observations: Map<string, CompiledObservation>;
  capabilities: Map<string, CapabilityDescriptor>;
  usedCapabilities: Set<string>;
  authorityReduced: boolean;
  authorityReductionReasons: string[];
  approvalGrants: Map<string, ApprovalGrant>;
  memoryRecords: Map<string, MemoryRecord>;
  memorySnapshots: Map<string, MemoryRecord | MemorySnapshotState>;
  onboardingSessions: Map<string, ToolOnboardingSession>;
  latestObservationV5?: CompiledObservationV5;
  observationsV5: Map<string, CompiledObservationV5>;
  capabilitiesV5: Map<string, CapabilityDescriptorV5>;
  consumedCapabilitiesV5: Map<string, CapabilityDescriptorV5>;
  usedCapabilitiesV5: Set<string>;
  approvalEnvelopesV5: Map<string, ApprovalEnvelopeV5>;
  onboardingSessionsV5: Map<string, ToolOnboardingSessionV5>;
  connectorHandlesV5: Map<string, ConnectorHandle>;
}

interface SessionStartRequest {
  taskId: string;
  userGoal: string;
  phase?: string;
  allowedOrigins?: string[];
  allowedVerbs?: string[];
  forbiddenSinks?: string[];
  expiresInSeconds?: number;
}

interface ApprovalGrantRequest {
  sessionId: string;
  connectorId: string;
  scopes?: string[];
  sinkClass: ApprovalGrant["sinkClass"];
  capabilityIds?: string[];
  targetOrigin: string;
  expiresInSeconds?: number;
}

interface V4ToolPreparePayload {
  sessionId: string;
  approvalGrantId: string;
  request: ToolRequest;
}

interface V4ToolCallbackPayload {
  sessionId: string;
  approvalGrantId: string;
  request: ToolCallbackVerificationRequest;
}

interface V4ObservePayload {
  sessionId: string;
  capture: SurfaceCapture;
}

interface V4ArtifactPayload {
  sessionId: string;
  capture: SurfaceCapture;
}

interface V4MemoryWritePayload extends MemoryWriteRequest {
  sessionId: string;
  sourceObservationId?: string;
  sourceDigest?: string;
}

interface V5ObservePayload {
  sessionId: string;
  capture: SurfaceCapture;
}

interface V5ApprovalIssuePayload {
  sessionId: string;
  capabilityId: string;
  capabilityDigest: string;
  brokerSignature: string;
  expiresInSeconds?: number;
}

interface V5ToolPreparePayload {
  sessionId: string;
  approvalId: string;
}

interface V5ToolCallbackPayload {
  sessionId: string;
  approvalId: string;
  onboardingSessionId: string;
  request: ToolCallbackVerificationRequest;
}

interface MemorySnapshotState {
  snapshotId: string;
  sessionId: string;
  recordId: string;
  key: string;
  createdAt: string;
  baselineAbsent: boolean;
  snapshotRecord?: MemoryRecord;
}

function hashValue(input: unknown): string {
  return createHash("sha256").update(JSON.stringify(input)).digest("hex");
}

async function readJson<T>(request: IncomingMessage): Promise<T> {
  const chunks: Uint8Array[] = [];
  for await (const chunk of request) {
    chunks.push(typeof chunk === "string" ? Buffer.from(chunk) : chunk);
  }
  return JSON.parse(Buffer.concat(chunks).toString("utf8")) as T;
}

function writeJson(response: ServerResponse, statusCode: number, payload: unknown): void {
  response.statusCode = statusCode;
  response.setHeader("content-type", "application/json; charset=utf-8");
  response.end(JSON.stringify(payload, null, 2));
}

function legacyResponseMeta(route: string) {
  return {
    deprecated: true as const,
    telemetry: {
      deprecated: true as const,
      claimScope: "legacy_compatibility" as const,
      preventionClaim: false as const,
      routeVersion: route
    }
  };
}

async function fileExists(path: string): Promise<boolean> {
  try {
    await stat(path);
    return true;
  } catch {
    return false;
  }
}

async function resolveDefaultRootDir(): Promise<string> {
  const moduleDir = resolve(fileURLToPath(new URL(".", import.meta.url)));
  const packagedRuntimeRoot = resolve(moduleDir, "runtime");
  const packagedPolicy = resolve(packagedRuntimeRoot, "policies", "base", "research.yaml");

  if (await fileExists(packagedPolicy)) {
    return packagedRuntimeRoot;
  }

  return process.cwd();
}

async function buildRuntimeContext(
  options: SafeBrowseDaemonOptions
): Promise<
  RuntimeContext & {
    knowledgeBase: KnowledgeBaseContext;
    verifiedRegistry?: VerifiedRegistryBundle;
    parserAllowlistedEgress: string[];
    deploymentProfile: "development" | "secure_v5";
    approvalBrokerPublicKey?: KeyObject;
    approvalBrokerConfigured: boolean;
  }
> {
  const rootDir = options.rootDir ?? (await resolveDefaultRootDir());
  const policyPack =
    options.policyPack ??
    (await loadPolicyPackFromPaths(resolvePolicyLayerFiles(resolve(rootDir))));
  const knowledgeBase =
    options.knowledgeBase ?? (await loadKnowledgeBaseContext(resolve(rootDir, "knowledge_base")));
  const verifiedRegistry =
    options.verifiedRegistry ??
    (await loadVerifiedRegistryBundle(buildRegistryDefaults(resolve(rootDir))).catch(() => undefined));
  const approvalBrokerPublicKeyPem =
    options.approvalBrokerPublicKeyPem ??
    (options.approvalBrokerPublicKeyPath
      ? await readFile(options.approvalBrokerPublicKeyPath, "utf8").catch(() => undefined)
      : await readFile(
          resolve(
            rootDir,
            "knowledge_base",
            "signing",
            "safebrowse_vf_ed25519_public.pem"
          ),
          "utf8"
        ).catch(() => undefined));

  return {
    policy: compilePolicy(policyPack),
    knowledgeBase,
    verifiedRegistry,
    parserAllowlistedEgress: options.parserAllowlistedEgress ?? [],
    deploymentProfile: options.deploymentProfile ?? "development",
    approvalBrokerPublicKey: approvalBrokerPublicKeyPem
      ? createPublicKey(approvalBrokerPublicKeyPem)
      : undefined,
    approvalBrokerConfigured: Boolean(approvalBrokerPublicKeyPem)
  };
}

function plusMinutes(value: string, minutes: number): string {
  return new Date(new Date(value).getTime() + minutes * 60_000).toISOString();
}

function plusSeconds(value: string, seconds: number): string {
  return new Date(new Date(value).getTime() + seconds * 1_000).toISOString();
}

function createWorkflowHash(payload: Pick<
  SessionStartRequest,
  "taskId" | "userGoal" | "phase" | "allowedOrigins" | "allowedVerbs" | "forbiddenSinks"
>): string {
  return hashValue({
    taskId: payload.taskId,
    userGoal: payload.userGoal,
    phase: payload.phase ?? "",
    allowedOrigins: payload.allowedOrigins ?? [],
    allowedVerbs: payload.allowedVerbs ?? [],
    forbiddenSinks: payload.forbiddenSinks ?? []
  });
}

function createSessionState(
  request: SessionStartRequest,
  runtime: RuntimeContext & {
    deploymentProfile?: "development" | "secure_v5";
    approvalBrokerConfigured?: boolean;
  }
): SessionState {
  const createdAt = new Date().toISOString();
  const allowedOrigins =
    request.allowedOrigins ??
    [...runtime.policy.readOnlyOrigins, ...runtime.policy.writableOrigins];
  const allowedVerbs = request.allowedVerbs ?? [...runtime.policy.allowedActions];
  const forbiddenSinks = request.forbiddenSinks ?? [];
  const session: TaskSession = {
    sessionId: randomUUID(),
    taskId: request.taskId,
    userGoal: request.userGoal,
    phase: request.phase,
    allowedOrigins,
    allowedVerbs,
    forbiddenSinks,
    workflowHash: createWorkflowHash({
      taskId: request.taskId,
      userGoal: request.userGoal,
      phase: request.phase,
      allowedOrigins,
      allowedVerbs,
      forbiddenSinks
    }),
    currentStep: 0,
    createdAt,
    expiresAt: plusSeconds(createdAt, request.expiresInSeconds ?? 1800),
    claimProfile: runtime.deploymentProfile === "secure_v5" ? "secure_v5" : undefined,
    approvalBrokerRequired: runtime.deploymentProfile === "secure_v5",
    legacyRoutesDisabled: runtime.deploymentProfile === "secure_v5"
  };

  return {
    session,
    observations: new Map(),
    capabilities: new Map(),
    usedCapabilities: new Set(),
    authorityReduced: false,
    authorityReductionReasons: [],
    approvalGrants: new Map(),
    memoryRecords: new Map(),
    memorySnapshots: new Map(),
    onboardingSessions: new Map(),
    observationsV5: new Map(),
    capabilitiesV5: new Map(),
    consumedCapabilitiesV5: new Map(),
    usedCapabilitiesV5: new Set(),
    approvalEnvelopesV5: new Map(),
    onboardingSessionsV5: new Map(),
    connectorHandlesV5: new Map()
  };
}

function shouldReduceAuthority(
  sessionState: SessionState,
  observation: CompiledObservation
): boolean {
  if (sessionState.authorityReduced) {
    return true;
  }

  const hasPriorSurface = Boolean(sessionState.latestObservation);
  const hasMeaningfulRisk =
    observation.parseStatus !== "compiled" ||
    observation.riskFindings.length > 0 ||
    observation.secretFindings.length > 0;

  return hasPriorSurface && hasMeaningfulRisk;
}

function applyAuthorityReduction(
  sessionState: SessionState,
  observation: CompiledObservation,
  plannerInput: StructuredPlannerInput
): StructuredPlannerInput {
  const reasons = [
    ...sessionState.authorityReductionReasons,
    ...(observation.parseStatus !== "compiled"
      ? [`parse_status_${observation.parseStatus}`]
      : []),
    ...observation.riskFindings,
    ...(observation.secretFindings.length ? ["secret_redaction_boundary"] : [])
  ];

  sessionState.authorityReduced = true;
  sessionState.authorityReductionReasons = [...new Set(reasons)];
  sessionState.capabilities.clear();

  return {
    ...plannerInput,
    candidateCapabilities: [],
    riskMarkers: [
      ...new Set([
        ...plannerInput.riskMarkers,
        "multimodal_reducer_active",
        ...sessionState.authorityReductionReasons.map((reason) => `chain:${reason}`)
      ])
    ]
  };
}

function createOnboardingSession(
  request: ToolRequest,
  runtime: RuntimeContext & { verifiedRegistry?: VerifiedRegistryBundle },
  approvalGrant: ApprovalGrant,
  verifiedRegistryEntry?: VerifiedRegistryEntry
): ToolOnboardingSession | undefined {
  const callbackUri =
    verifiedRegistryEntry?.allowedRedirectUris[0] ??
    request.oauthContext?.callbackUri ??
    request.callbackUri ??
    request.oauthContext?.redirectUri ??
    request.requestedRedirectUri;

  if (!callbackUri) {
    return undefined;
  }

  const callbackOrigin =
    verifiedRegistryEntry?.allowedCallbackOrigins[0] ?? new URL(callbackUri).origin;

  const createdAt = (runtime.now?.() ?? new Date()).toISOString();
  return {
    sessionId: randomUUID(),
    approvalBindingId: approvalGrant.approvalGrantId,
    workflowBindingId: request.sourceObservationId,
    toolId: request.toolId,
    registryEntryId:
      verifiedRegistryEntry?.registryEntryId ?? request.registryEntryId ?? request.toolId,
    registryBundleId:
      verifiedRegistryEntry?.bundleId ??
      request.registryBundleId ??
      runtime.verifiedRegistry?.bundleId ??
      "unverified-registry",
    callbackUri,
    callbackOrigin,
    requestedScopes: approvalGrant.scopes,
    state: randomUUID(),
    pkceMethod: "S256",
    createdAt,
    expiresAt: plusMinutes(createdAt, 5),
    status: "prepared"
  };
}

function issueApprovalGrant(
  request: ApprovalGrantRequest,
  sessionState: SessionState
): ApprovalGrant {
  const issuedAt = new Date().toISOString();
  const grantWithoutHash = {
    approvalGrantId: randomUUID(),
    sessionId: sessionState.session.sessionId,
    workflowHash: sessionState.session.workflowHash,
    connectorId: request.connectorId,
    scopes: request.scopes ?? [],
    sinkClass: request.sinkClass,
    capabilityIds: request.capabilityIds ?? [],
    targetOrigin: request.targetOrigin,
    issuedAt,
    expiresAt: plusSeconds(issuedAt, request.expiresInSeconds ?? 600)
  };

  return {
    ...grantWithoutHash,
    grantHash: createApprovalGrantHash(grantWithoutHash)
  };
}

function findSessionState(
  sessions: Map<string, SessionState>,
  sessionId: string
): SessionState | undefined {
  const sessionState = sessions.get(sessionId);
  if (!sessionState) {
    return undefined;
  }

  if (new Date(sessionState.session.expiresAt).getTime() <= Date.now()) {
    sessions.delete(sessionId);
    return undefined;
  }

  return sessionState;
}

function legacyRoutesDisabled(runtime: { deploymentProfile: "development" | "secure_v5" }): boolean {
  return runtime.deploymentProfile === "secure_v5";
}

function isLegacyRoute(url: string): boolean {
  return url.startsWith("/v1/") || url.startsWith("/v2/") || url.startsWith("/v4/");
}

function lookupVerifiedRegistryEntry(
  runtime: { verifiedRegistry?: VerifiedRegistryBundle },
  toolId?: string,
  registryEntryId?: string
): VerifiedRegistryEntry | undefined {
  return runtime.verifiedRegistry?.entries.find(
    (entry) =>
      entry.registryEntryId === registryEntryId ||
      entry.registryEntryId === toolId ||
      entry.adapterId === toolId
  );
}

function resolveToolManifestRegistryEntry(
  runtime: { verifiedRegistry?: VerifiedRegistryBundle },
  capture: Extract<SurfaceCapture, { surfaceType: "tool_manifest" }>
): VerifiedRegistryEntry | undefined {
  return runtime.verifiedRegistry?.entries.find((entry) => {
    if (capture.toolId !== entry.adapterId && capture.toolId !== entry.registryEntryId) {
      return false;
    }
    if (capture.authType && capture.authType !== entry.authType) {
      return false;
    }
    if (capture.callbackUri && !entry.allowedRedirectUris.includes(capture.callbackUri)) {
      return false;
    }
    if (
      capture.callbackOrigin &&
      !entry.allowedCallbackOrigins.includes(capture.callbackOrigin)
    ) {
      return false;
    }
    if (
      capture.requestedScopes?.length &&
      capture.requestedScopes.some((scope) => !entry.allowedScopes.includes(scope))
    ) {
      return false;
    }
    return true;
  });
}

function getCapabilityV5(
  sessionState: SessionState | undefined,
  capabilityId: string | undefined
): CapabilityDescriptorV5 | undefined {
  if (!sessionState || !capabilityId) {
    return undefined;
  }
  return (
    sessionState.capabilitiesV5.get(capabilityId) ??
    sessionState.consumedCapabilitiesV5.get(capabilityId)
  );
}

function consumeCapabilityV5(
  sessionState: SessionState,
  capability: CapabilityDescriptorV5,
  consumedAt = new Date().toISOString()
): CapabilityDescriptorV5 {
  const consumedCapability = {
    ...capability,
    consumedAt
  };
  sessionState.capabilitiesV5.delete(capability.capabilityId);
  sessionState.consumedCapabilitiesV5.set(capability.capabilityId, consumedCapability);
  sessionState.usedCapabilitiesV5.add(capability.capabilityId);
  return consumedCapability;
}

function getActiveApprovalEnvelopeForCapability(
  sessionState: SessionState | undefined,
  capabilityId: string | undefined
): ApprovalEnvelopeV5 | undefined {
  if (!sessionState || !capabilityId) {
    return undefined;
  }
  return [...sessionState.approvalEnvelopesV5.values()].find(
    (envelope) =>
      envelope.capabilityId === capabilityId &&
      !envelope.consumedAt &&
      new Date(envelope.expiresAt).getTime() > Date.now()
  );
}

function buildMemorySnapshotState(
  sessionState: SessionState,
  record: MemoryRecord
): MemorySnapshotState {
  const priorTrustedBaseline = [...sessionState.memoryRecords.values()]
    .filter(
      (candidate) =>
        candidate.sessionId === record.sessionId &&
        candidate.key === record.key &&
        candidate.tier === "trusted_durable" &&
        candidate.recordId !== record.recordId
    )
    .sort((left, right) => right.createdAt.localeCompare(left.createdAt))[0];

  return {
    snapshotId: randomUUID(),
    sessionId: record.sessionId,
    recordId: record.recordId,
    key: record.key,
    createdAt: new Date().toISOString(),
    baselineAbsent: !priorTrustedBaseline,
    snapshotRecord: priorTrustedBaseline
      ? {
          ...priorTrustedBaseline
        }
      : undefined
  };
}

function retireObservationCapabilitiesV5(sessionState: SessionState): void {
  const retiredCapabilityIds: string[] = [];
  for (const [capabilityId, capability] of sessionState.capabilitiesV5.entries()) {
    if (capability.kind !== "memory_promote") {
      sessionState.capabilitiesV5.delete(capabilityId);
      retiredCapabilityIds.push(capabilityId);
    }
  }
  if (!retiredCapabilityIds.length) {
    return;
  }
  for (const [approvalId, envelope] of sessionState.approvalEnvelopesV5.entries()) {
    if (retiredCapabilityIds.includes(envelope.capabilityId) && !envelope.consumedAt) {
      sessionState.approvalEnvelopesV5.delete(approvalId);
    }
  }
}

function buildV5ExecutionPlan(capability: CapabilityDescriptorV5 | undefined) {
  if (!capability) {
    return undefined;
  }

  return {
    verb: capability.kind,
    targetUrl: capability.targetUrl,
    targetOrigin: capability.targetOrigin,
    selector: capability.selector,
    connectorId: capability.connectorId,
    callbackUri: capability.callbackUri,
    callbackOrigin: capability.callbackOrigin,
    memoryRecordId: capability.memoryRecordId,
    derivedSinkClass: capability.derivedSinkClass,
    derivedSensitiveSink: capability.derivedSensitiveSink,
    semanticDigest: capability.semanticDigest
  };
}

function buildLegacyObservationCapture(payload: SurfaceCapture): ArtifactInput | undefined {
  if (payload.surfaceType === "pdf") {
    return {
      mimeType: "application/pdf",
      sourceOrigin: payload.url,
      viewerOrigin: payload.frameUrl ?? payload.url,
      renderedText: payload.renderedText,
      extractedText: payload.extractedText,
      ocrText: payload.ocrText,
      annotations: payload.annotations,
      metadataText: payload.metadataText,
      extractionMethod: "download",
      trustSignals: payload.trustSignals
    };
  }

  if (payload.surfaceType === "image") {
    return {
      mimeType: "image/png",
      sourceOrigin: payload.url,
      viewerOrigin: payload.frameUrl ?? payload.url,
      ocrText: payload.ocrText,
      metadataText: payload.metadataText,
      extractionMethod: "ocr",
      trustSignals: payload.trustSignals
    };
  }

  if (payload.surfaceType === "tool_manifest") {
    return {
      mimeType: "application/json",
      surfaceKind: "tool_manifest",
      sourceOrigin: payload.url,
      viewerOrigin: payload.frameUrl ?? payload.url,
      extractedText: payload.description,
      metadataText: payload.schemaDescriptions,
      extractionMethod: "api",
      trustSignals: payload.trustSignals
    };
  }

  return undefined;
}

export async function createSafeBrowseServer(
  options: SafeBrowseDaemonOptions = {}
): Promise<Server> {
  const runtime = await buildRuntimeContext(options);
  if (runtime.deploymentProfile === "secure_v5") {
    if (!runtime.verifiedRegistry?.signatureVerified) {
      throw new Error("secure_v5 requires a signature-verified registry bundle");
    }
    if (!runtime.approvalBrokerConfigured || !runtime.approvalBrokerPublicKey) {
      throw new Error("secure_v5 requires an approval broker public key");
    }
    const parserProbe = await probeParserIsolation();
    if (!parserProbe.processIsolated || !parserProbe.egressDenied || parserProbe.envKeys.length) {
      throw new Error("secure_v5 requires isolated parsers with denied egress and scrubbed env");
    }
  }
  const onboardingSessions = new Map<string, ToolOnboardingSession>();
  const sessions = new Map<string, SessionState>();

  return createServer(async (request, response) => {
    if (!request.url) {
      writeJson(response, 400, { error: "missing_url" });
      return;
    }

    try {
      if (request.method === "GET" && request.url === "/health") {
        const parserProbe = await probeParserIsolation();
        writeJson(response, 200, {
          status: "ok",
          profile: runtime.policy.profile,
          deploymentProfile: runtime.deploymentProfile,
          version: runtime.policy.version,
          policyLayers: runtime.policy.layerProvenance,
          legacyRoutesEnabled: !legacyRoutesDisabled(runtime),
          verifiedRegistry: runtime.verifiedRegistry
            ? {
                bundleId: runtime.verifiedRegistry.bundleId,
                version: runtime.verifiedRegistry.version,
                signatureVerified: runtime.verifiedRegistry.signatureVerified,
                entryCount: runtime.verifiedRegistry.entries.length,
                required: runtime.deploymentProfile === "secure_v5"
              }
            : undefined,
          parserIsolation: {
            ...parserProbe,
            enforced: runtime.deploymentProfile === "secure_v5"
          },
          approvalBroker: {
            required: runtime.deploymentProfile === "secure_v5",
            configured: runtime.approvalBrokerConfigured
          }
        });
        return;
      }

      if (request.method !== "POST") {
        writeJson(response, 405, { error: "method_not_allowed" });
        return;
      }

      if (legacyRoutesDisabled(runtime) && isLegacyRoute(request.url)) {
        writeJson(response, 403, {
          error: "route_disabled_in_secure_v5",
          route: request.url,
          claimProfile: "secure_v5"
        });
        return;
      }

      if (request.url === "/v1/observe") {
        const payload = await readJson<Parameters<typeof sanitizeObservation>[0]>(request);
        writeJson(response, 200, {
          ...sanitizeObservation(payload, runtime),
          ...legacyResponseMeta("/v1/observe")
        });
        return;
      }

      if (request.url === "/v1/action") {
        const payload = await readJson<ActionProposal>(request);
        writeJson(response, 200, {
          ...evaluateAction(payload, runtime),
          ...legacyResponseMeta("/v1/action")
        });
        return;
      }

      if (request.url === "/v1/artifact") {
        const payload = await readJson<ArtifactInput>(request);
        writeJson(response, 200, {
          ...brokerArtifact(payload, runtime),
          ...legacyResponseMeta("/v1/artifact")
        });
        return;
      }

      if (request.url === "/v1/tool") {
        const payload = await readJson<ToolRequest>(request);
        writeJson(response, 200, {
          ...evaluateToolRequest(payload, runtime),
          ...legacyResponseMeta("/v1/tool")
        });
        return;
      }

      if (request.url === "/v1/memory") {
        const payload = await readJson<MemoryWriteRequest>(request);
        writeJson(response, 200, {
          ...evaluateMemoryWrite(payload, runtime),
          ...legacyResponseMeta("/v1/memory")
        });
        return;
      }

      if (request.url === "/v1/replay") {
        const payload = await readJson<{ events: ReplayEvent[] }>(request);
        writeJson(response, 200, {
          ...buildReplayBundle(payload.events, runtime),
          ...legacyResponseMeta("/v1/replay")
        });
        return;
      }

      if (request.url === "/v2/tool/prepare") {
        const payload = await readJson<ToolRequest>(request);
        const prepared = prepareToolOnboarding(payload, runtime);
        const onboardingSession =
          prepared.verdict.decision === "ALLOW" && payload.authType === "oauth"
            ? createOnboardingSession(
                payload,
                runtime,
                {
                  approvalGrantId: payload.approvalBindingId ?? randomUUID(),
                  sessionId: "legacy-session",
                  workflowHash: hashValue(payload.sourceObservationId ?? payload.requestId),
                  connectorId: payload.toolId,
                  scopes: payload.requestedScopes ?? [],
                  sinkClass: "connector_oauth",
                  capabilityIds: payload.capabilityId ? [payload.capabilityId] : [],
                  targetOrigin:
                    payload.callbackOrigin ??
                    payload.oauthContext?.callbackOrigin ??
                    payload.callbackUri ??
                    payload.requestedRedirectUri ??
                    "unknown",
                  issuedAt: new Date().toISOString(),
                  expiresAt: plusMinutes(new Date().toISOString(), 10),
                  grantHash: "legacy"
                }
              )
            : undefined;

        if (onboardingSession) {
          onboardingSessions.set(onboardingSession.sessionId, onboardingSession);
        }

        writeJson(response, 200, {
          verdict: prepared.verdict,
          verifiedRegistryEntry: prepared.verifiedRegistryEntry,
          workflowBinding: prepared.workflowBinding,
          onboardingSession,
          ...legacyResponseMeta("/v2/tool/prepare")
        });
        return;
      }

      if (request.url === "/v2/tool/callback/verify") {
        const payload = await readJson<ToolCallbackVerificationRequest>(request);
        const session = onboardingSessions.get(payload.sessionId);
        const result = verifyToolCallback(payload, session, runtime);
        if (session) {
          onboardingSessions.set(payload.sessionId, {
            ...session,
            status: result.verdict.decision === "ALLOW" ? "used" : session.status
          });
        }
        writeJson(response, 200, {
          ...result,
          ...legacyResponseMeta("/v2/tool/callback/verify")
        });
        return;
      }

      if (request.url === "/v2/artifact") {
        const payload = await readJson<ArtifactV2Input>(request);
        writeJson(response, 200, {
          ...brokerArtifactV2(payload, runtime),
          ...legacyResponseMeta("/v2/artifact")
        });
        return;
      }

      if (request.url === "/v5/session/start") {
        const payload = await readJson<SessionStartRequest>(request);
        const sessionState = createSessionState(payload, runtime);
        sessions.set(sessionState.session.sessionId, sessionState);
        writeJson(response, 200, {
          session: sessionState.session
        });
        return;
      }

      if (request.url === "/v5/observe") {
        const payload = await readJson<V5ObservePayload>(request);
        const sessionState = findSessionState(sessions, payload.sessionId);
        if (!sessionState) {
          writeJson(response, 404, { error: "unknown_session" });
          return;
        }

        const capture: SurfaceCapture = {
          ...payload.capture,
          sessionId: payload.sessionId,
          taskId: sessionState.session.taskId
        };

        const observationResult = await compileObservationInIsolation({
          capture,
          workflowHash: sessionState.session.workflowHash,
          allowlistedEgress: runtime.parserAllowlistedEgress,
          compilerVersion: "v5",
          runtime: {
            knowledgeBase: runtime.knowledgeBase
          }
        });

        const compiledObservation = observationResult.compiledObservation as CompiledObservationV5;
        const plannerView = observationResult.plannerView as PlannerViewV5;
        const mediated = applyV5ObservationMediation(compiledObservation, plannerView);
        const verifiedEntry =
          capture.surfaceType === "tool_manifest"
            ? resolveToolManifestRegistryEntry(runtime, capture)
            : undefined;

        retireObservationCapabilitiesV5(sessionState);
        const capabilities = mediated.failClosed
          ? []
          : mintCapabilitiesForObservationV5(sessionState.session, compiledObservation, mediated.plannerView, {
              verifiedRegistryEntry: verifiedEntry,
              registryEntryId:
                capture.surfaceType === "tool_manifest" ? verifiedEntry?.registryEntryId : undefined,
              connectorId:
                capture.surfaceType === "tool_manifest" ? verifiedEntry?.adapterId ?? capture.toolId : undefined,
              requestedScopes: capture.surfaceType === "tool_manifest" ? capture.requestedScopes : undefined,
              callbackUri: capture.surfaceType === "tool_manifest" ? capture.callbackUri : undefined,
              callbackOrigin: capture.surfaceType === "tool_manifest" ? capture.callbackOrigin : undefined,
              manifestAuthType: capture.surfaceType === "tool_manifest" ? capture.authType : undefined
            });

        sessionState.latestObservationV5 = compiledObservation;
        sessionState.observationsV5.set(compiledObservation.observationId, compiledObservation);
        for (const capability of capabilities) {
          sessionState.capabilitiesV5.set(capability.capabilityId, capability);
        }

        writeJson(response, 200, {
          compiledObservation,
          plannerView: mediated.plannerView,
          capabilities: capabilities.map((capability) => ({
            capabilityId: capability.capabilityId,
            capabilityDigest: capability.capabilityDigest,
            semanticDigest: capability.semanticDigest,
            title: capability.title,
            kind: capability.kind,
            parameterSchema: capability.parameterSchema,
            expiresAt: capability.expiresAt
          })),
          observationVerdict: mediated.verdict
        });
        return;
      }

      if (request.url === "/v5/capability/use") {
        const payload = await readJson<CapabilityUseRequestV5>(request);
        const sessionState = findSessionState(sessions, payload.sessionId);
        const capability = getCapabilityV5(sessionState, payload.capabilityId);
        const verdict = evaluateCapabilityUseV5(payload, sessionState?.session, capability, {
          alreadyUsed: sessionState?.usedCapabilitiesV5.has(payload.capabilityId) ?? false
        });

        if (verdict.decision === "ALLOW" && sessionState && capability) {
          consumeCapabilityV5(sessionState, capability);
          sessionState.session = {
            ...sessionState.session,
            currentStep: sessionState.session.currentStep + 1
          };
        }

        writeJson(response, 200, {
          verdict,
          executionPlan: buildV5ExecutionPlan(capability)
        });
        return;
      }

      if (request.url === "/v5/approval/issue") {
        const payload = await readJson<V5ApprovalIssuePayload>(request);
        const sessionState = findSessionState(sessions, payload.sessionId);
        const capability = sessionState?.capabilitiesV5.get(payload.capabilityId);

        if (sessionState?.usedCapabilitiesV5.has(payload.capabilityId)) {
          writeJson(response, 200, {
            verdict: {
              decision: "BLOCK",
              reasonCodes: ["CAPABILITY_REPLAYED"],
              riskScore: 0.99,
              safeConstraints: {
                claim_profile: "secure_v5"
              },
              telemetryTags: ["approval_v5_issue", "block"]
            }
          });
          return;
        }

        if (capability && payload.capabilityDigest !== capability.capabilityDigest) {
          writeJson(response, 200, {
            verdict: {
              decision: "BLOCK",
              reasonCodes: ["CAPABILITY_DIGEST_MISMATCH"],
              riskScore: 0.99,
              safeConstraints: {
                claim_profile: "secure_v5"
              },
              telemetryTags: ["approval_v5_issue", "block"]
            }
          });
          return;
        }

        const activeApproval = getActiveApprovalEnvelopeForCapability(sessionState, payload.capabilityId);
        if (activeApproval) {
          writeJson(response, 200, {
            verdict: {
              decision: "BLOCK",
              reasonCodes: ["APPROVAL_ALREADY_ISSUED_FOR_CAPABILITY"],
              riskScore: 0.99,
              safeConstraints: {
                claim_profile: "secure_v5"
              },
              telemetryTags: ["approval_v5_issue", "block"]
            },
            approvalEnvelope: activeApproval
          });
          return;
        }

        const brokerPayload =
          sessionState && capability
            ? createApprovalIntentPayloadV5({
                sessionId: sessionState.session.sessionId,
                workflowHash: sessionState.session.workflowHash,
                capabilityId: capability.capabilityId,
                capabilityDigest: capability.capabilityDigest,
                expiresInSeconds: payload.expiresInSeconds
              })
            : "";
        const brokerSignatureVerified = verifyApprovalIntentSignatureV5(
          brokerPayload,
          payload.brokerSignature,
          runtime.approvalBrokerPublicKey
        );
        const issued = issueApprovalEnvelopeV5({
          session: sessionState?.session,
          capability,
          brokerSignature: payload.brokerSignature,
          brokerSignatureVerified,
          expiresInSeconds: payload.expiresInSeconds
        });

        if (issued.approvalEnvelope && sessionState) {
          sessionState.approvalEnvelopesV5.set(
            issued.approvalEnvelope.approvalId,
            issued.approvalEnvelope
          );
        }

        writeJson(response, 200, issued);
        return;
      }

      if (request.url === "/v5/tool/prepare") {
        const payload = await readJson<V5ToolPreparePayload>(request);
        const sessionState = findSessionState(sessions, payload.sessionId);
        const approvalEnvelope = sessionState?.approvalEnvelopesV5.get(payload.approvalId);
        const capability = approvalEnvelope
          ? getCapabilityV5(sessionState, approvalEnvelope.capabilityId)
          : undefined;
        const verifiedEntry = approvalEnvelope
          ? lookupVerifiedRegistryEntry(
              runtime,
              approvalEnvelope.connectorId,
              approvalEnvelope.registryEntryId
            )
          : undefined;

        const prepared = prepareToolOnboardingV5({
          session: sessionState?.session,
          capability,
          approvalEnvelope,
          verifiedRegistryEntry: verifiedEntry
        });

        if (sessionState && prepared.onboardingSession) {
          const consumedAt = new Date().toISOString();
          if (capability) {
            consumeCapabilityV5(sessionState, capability, consumedAt);
          }
          if (approvalEnvelope) {
            sessionState.approvalEnvelopesV5.set(payload.approvalId, {
              ...approvalEnvelope,
              consumedAt,
              onboardingSessionId: prepared.onboardingSession.onboardingSessionId
            });
          }
          sessionState.onboardingSessionsV5.set(
            prepared.onboardingSession.onboardingSessionId,
            prepared.onboardingSession
          );
          sessionState.session = {
            ...sessionState.session,
            currentStep: sessionState.session.currentStep + 1
          };
        }

        writeJson(response, 200, {
          verdict: prepared.verdict,
          approvalEnvelope:
            sessionState?.approvalEnvelopesV5.get(payload.approvalId) ?? approvalEnvelope,
          verifiedRegistryEntry: verifiedEntry,
          onboardingSession: prepared.onboardingSession
        });
        return;
      }

      if (request.url === "/v5/tool/callback/verify") {
        const payload = await readJson<V5ToolCallbackPayload>(request);
        const sessionState = findSessionState(sessions, payload.sessionId);
        const approvalEnvelope = sessionState?.approvalEnvelopesV5.get(payload.approvalId);
        const capability = approvalEnvelope
          ? getCapabilityV5(sessionState, approvalEnvelope.capabilityId)
          : undefined;
        const onboardingSession = sessionState?.onboardingSessionsV5.get(payload.onboardingSessionId);
        const verifiedEntry = approvalEnvelope
          ? lookupVerifiedRegistryEntry(
              runtime,
              approvalEnvelope.connectorId,
              approvalEnvelope.registryEntryId
            )
          : undefined;

        const verified = verifyToolCallbackV5({
          session: sessionState?.session,
          capability,
          approvalEnvelope,
          onboardingSession,
          verifiedRegistryEntry: verifiedEntry,
          request: payload.request
        });

        if (sessionState && onboardingSession && verified.verdict.decision === "ALLOW") {
          sessionState.onboardingSessionsV5.set(payload.onboardingSessionId, {
            ...onboardingSession,
            status: "used"
          });
        }
        if (sessionState && verified.connectorHandle) {
          sessionState.connectorHandlesV5.set(
            verified.connectorHandle.handleId,
            verified.connectorHandle
          );
        }

        writeJson(response, 200, verified);
        return;
      }

      if (request.url === "/v5/artifact/ingest") {
        const payload = await readJson<V4ArtifactPayload>(request);
        const sessionState = findSessionState(sessions, payload.sessionId);
        if (!sessionState) {
          writeJson(response, 404, { error: "unknown_session" });
          return;
        }

        const capture: SurfaceCapture = {
          ...payload.capture,
          sessionId: payload.sessionId,
          taskId: sessionState.session.taskId
        };
        const observationResult = await compileObservationInIsolation({
          capture,
          workflowHash: sessionState.session.workflowHash,
          allowlistedEgress: runtime.parserAllowlistedEgress,
          compilerVersion: "v5",
          runtime: {
            knowledgeBase: runtime.knowledgeBase
          }
        });
        const compiledObservation = observationResult.compiledObservation as CompiledObservationV5;
        const plannerView = observationResult.plannerView as PlannerViewV5;
        const artifactAuthoritative =
          compiledObservation.parseStatus === "compiled" &&
          compiledObservation.authorityEligible &&
          !plannerView.blockedChannels.length &&
          !compiledObservation.riskFindings.length;
        const artifactVerdict =
          artifactAuthoritative
            ? {
                decision: "ALLOW",
                reasonCodes: [],
                riskScore: compiledObservation.riskScore,
                safeConstraints: {
                  claim_profile: "secure_v5",
                  authority_eligible: true
                },
                telemetryTags: ["artifact_v5", "allow"]
              }
            : {
                decision:
                  compiledObservation.parseStatus === "compiled"
                    ? "QUARANTINE_ARTIFACT"
                    : "BLOCK",
                reasonCodes: [
                  ...(compiledObservation.parseStatus === "compiled"
                    ? ["ARTIFACT_NOT_AUTHORITY_ELIGIBLE"]
                    : [
                        compiledObservation.parseStatus === "partial"
                          ? "PARSE_STATUS_PARTIAL"
                          : "PARSE_STATUS_UNSUPPORTED"
                      ])
                ],
                riskScore: 0.98,
                safeConstraints: {
                  claim_profile: "secure_v5",
                  authority_eligible: false
                },
                telemetryTags: [
                  "artifact_v5",
                  compiledObservation.parseStatus === "compiled" ? "quarantine" : "block"
                ]
              };

        sessionState.latestObservationV5 = compiledObservation;
        sessionState.observationsV5.set(compiledObservation.observationId, compiledObservation);

        writeJson(response, 200, {
          compiledObservation,
          plannerView,
          artifactVerdict
        });
        return;
      }

      if (request.url === "/v5/memory/write") {
        const payload = await readJson<MemoryWriteRequestV5>(request);
        const sessionState = findSessionState(sessions, payload.sessionId);
        const result = evaluateMemoryWriteV5(payload, sessionState?.session);

        let promotionCapability;
        if (sessionState && result.record) {
          sessionState.memoryRecords.set(result.record.recordId, result.record);
          if (result.record.tier === "candidate_durable") {
            promotionCapability = mintMemoryPromotionCapabilityV5(sessionState.session, {
              recordId: result.record.recordId,
              sourceDigest: result.record.sourceDigest,
              sourceObservationId: result.record.sourceObservationId,
              key: result.record.key,
              valueDigest: result.record.sourceDigest ?? hashValue(result.record.value)
            });
            sessionState.capabilitiesV5.set(
              promotionCapability.capabilityId,
              promotionCapability
            );
          }
        }

        writeJson(response, 200, {
          ...result,
          promotionCapability: promotionCapability
            ? {
                capabilityId: promotionCapability.capabilityId,
                capabilityDigest: promotionCapability.capabilityDigest,
                semanticDigest: promotionCapability.semanticDigest,
                title: promotionCapability.title,
                kind: promotionCapability.kind,
                expiresAt: promotionCapability.expiresAt
              }
            : undefined
        });
        return;
      }

      if (request.url === "/v5/memory/promote") {
        const payload = await readJson<MemoryPromotionRequestV5>(request);
        const sessionState = findSessionState(sessions, payload.sessionId);
        const record = sessionState?.memoryRecords.get(payload.recordId);
        const capability = sessionState?.capabilitiesV5.get(payload.capabilityId);
        const approvalEnvelope = sessionState?.approvalEnvelopesV5.get(payload.approvalId);
        const result = promoteMemoryRecordV5(
          payload,
          sessionState?.session,
          record,
          capability,
          approvalEnvelope
        );
        if (sessionState && result.promotedRecord) {
          if (record && result.promotedRecord.snapshotId) {
            const snapshotState = buildMemorySnapshotState(sessionState, record);
            sessionState.memorySnapshots.set(result.promotedRecord.snapshotId, {
              ...snapshotState,
              snapshotId: result.promotedRecord.snapshotId
            });
          }
          sessionState.memoryRecords.set(result.promotedRecord.recordId, result.promotedRecord);
          if (capability) {
            consumeCapabilityV5(sessionState, capability);
          }
          if (approvalEnvelope) {
            sessionState.approvalEnvelopesV5.set(payload.approvalId, {
              ...approvalEnvelope,
              consumedAt: new Date().toISOString()
            });
          }
          sessionState.session = {
            ...sessionState.session,
            currentStep: sessionState.session.currentStep + 1
          };
        }

        writeJson(response, 200, {
          ...result,
          approvalEnvelope:
            payload.approvalId && sessionState
              ? sessionState.approvalEnvelopesV5.get(payload.approvalId)
              : approvalEnvelope
        });
        return;
      }

      if (request.url === "/v5/memory/rollback") {
        const payload = await readJson<MemoryRollbackRequest>(request);
        const sessionState = findSessionState(sessions, payload.sessionId);
        const record = sessionState?.memoryRecords.get(payload.recordId);
        const snapshotState = sessionState?.memorySnapshots.get(payload.snapshotId) as
          | MemorySnapshotState
          | undefined;
        const result = rollbackMemoryRecordV5(
          payload,
          sessionState?.session,
          record,
          {
            snapshotRecord: snapshotState?.snapshotRecord,
            baselineAbsent: snapshotState?.baselineAbsent
          }
        );

        if (sessionState && result.verdict.decision === "ALLOW") {
          if (result.restoredRecord) {
            sessionState.memoryRecords.set(result.restoredRecord.recordId, result.restoredRecord);
          } else {
            sessionState.memoryRecords.delete(payload.recordId);
          }
        }

        writeJson(response, 200, {
          ...result,
          rollbackEvent:
            result.verdict.decision === "ALLOW"
              ? {
                  recordId: payload.recordId,
                  snapshotId: payload.snapshotId,
                  appliedAt: new Date().toISOString()
                }
              : undefined
        });
        return;
      }

      if (request.url === "/v4/session/start") {
        const payload = await readJson<SessionStartRequest>(request);
        const sessionState = createSessionState(payload, runtime);
        sessions.set(sessionState.session.sessionId, sessionState);
        writeJson(response, 200, {
          session: sessionState.session
        });
        return;
      }

      if (request.url === "/v4/observe") {
        const payload = await readJson<V4ObservePayload>(request);
        const sessionState = findSessionState(sessions, payload.sessionId);
        if (!sessionState) {
          writeJson(response, 404, { error: "unknown_session" });
          return;
        }

        const capture: SurfaceCapture = {
          ...payload.capture,
          sessionId: payload.sessionId,
          taskId: sessionState.session.taskId
        };

        const observation = await compileObservationInIsolation({
          capture,
          workflowHash: sessionState.session.workflowHash,
          allowlistedEgress: runtime.parserAllowlistedEgress,
          runtime: {
            knowledgeBase: runtime.knowledgeBase
          }
        });

        const failClosedObservation = applyV4FailClosedMediation(
          observation.compiledObservation,
          observation.plannerInput!,
          "observe"
        );

        let capabilities = mintCapabilitiesForObservation(
          sessionState.session,
          observation.compiledObservation,
          {
            sourceObservationId: observation.compiledObservation.observationId
          }
        );
        let plannerInput = failClosedObservation.plannerInput;

        if (shouldReduceAuthority(sessionState, observation.compiledObservation)) {
          plannerInput = applyAuthorityReduction(
            sessionState,
            observation.compiledObservation,
            plannerInput
          );
          capabilities = [];
        }

        sessionState.capabilities.clear();
        for (const capability of capabilities) {
          sessionState.capabilities.set(capability.capabilityId, capability);
        }
        sessionState.latestObservation = observation.compiledObservation;
        sessionState.observations.set(
          observation.compiledObservation.observationId,
          observation.compiledObservation
        );

        writeJson(response, 200, {
          compiledObservation: observation.compiledObservation,
          observationVerdict: failClosedObservation.verdict,
          plannerInput: attachCapabilitiesToPlannerInput(plannerInput, capabilities)
        });
        return;
      }

      if (request.url === "/v4/action/evaluate") {
        const payload = await readJson<CapabilityUseRequest>(request);
        const sessionState = findSessionState(sessions, payload.sessionId);
        const capability = sessionState?.capabilities.get(payload.capabilityId);
        const verdict = evaluateCapabilityUse(payload, sessionState?.session, capability, {
          alreadyUsed: sessionState?.usedCapabilities.has(payload.capabilityId) ?? false
        });

        if (verdict.decision === "ALLOW" && sessionState && capability) {
          sessionState.capabilities.delete(payload.capabilityId);
          sessionState.usedCapabilities.add(payload.capabilityId);
          sessionState.session = {
            ...sessionState.session,
            currentStep: sessionState.session.currentStep + 1
          };
        }

        writeJson(response, 200, {
          verdict,
          executionPlan:
            verdict.decision === "ALLOW" && capability
              ? {
                  verb: capability.kind,
                  targetUrl: capability.targetUrl,
                  targetOrigin: capability.targetOrigin,
                  selector: capability.selector,
                  derivedSinkClass: capability.derivedSinkClass,
                  derivedSensitiveSink: capability.derivedSensitiveSink
                }
              : undefined
        });
        return;
      }

      if (request.url === "/v4/approval/grant") {
        const payload = await readJson<ApprovalGrantRequest>(request);
        const sessionState = findSessionState(sessions, payload.sessionId);
        if (!sessionState) {
          writeJson(response, 404, { error: "unknown_session" });
          return;
        }

        const unknownCapability = (payload.capabilityIds ?? []).find(
          (capabilityId) => !sessionState.capabilities.has(capabilityId)
        );
        if (unknownCapability) {
          writeJson(response, 400, {
            error: "unknown_capability",
            capabilityId: unknownCapability
          });
          return;
        }

        if (
          payload.sinkClass === "connector_oauth" &&
          !(payload.capabilityIds ?? []).length
        ) {
          writeJson(response, 400, {
            error: "capability_ids_required",
            sinkClass: payload.sinkClass
          });
          return;
        }

        const approvalGrant = issueApprovalGrant(payload, sessionState);
        sessionState.approvalGrants.set(approvalGrant.approvalGrantId, approvalGrant);
        writeJson(response, 200, {
          approvalGrant
        });
        return;
      }

      if (request.url === "/v4/tool/prepare") {
        const payload = await readJson<V4ToolPreparePayload>(request);
        const sessionState = findSessionState(sessions, payload.sessionId);
        const approvalGrant = sessionState?.approvalGrants.get(payload.approvalGrantId);

        const prepared = prepareToolOnboardingV4(
          {
            ...payload.request,
            approvalGrantId: payload.approvalGrantId
          },
          sessionState?.session,
          approvalGrant,
          runtime
        );

        const onboardingSession =
          prepared.verdict.decision === "ALLOW" && payload.request.authType === "oauth" && approvalGrant
            ? createOnboardingSession(
                payload.request,
                runtime,
                approvalGrant,
                prepared.verifiedRegistryEntry
              )
            : undefined;

        if (sessionState && onboardingSession) {
          sessionState.onboardingSessions.set(onboardingSession.sessionId, onboardingSession);
        }

        writeJson(response, 200, {
          verdict: prepared.verdict,
          approvalVerdict: prepared.approvalVerdict,
          verifiedRegistryEntry: prepared.verifiedRegistryEntry,
          workflowBinding: prepared.workflowBinding,
          onboardingSession
        });
        return;
      }

      if (request.url === "/v4/tool/callback/verify") {
        const payload = await readJson<V4ToolCallbackPayload>(request);
        const sessionState = findSessionState(sessions, payload.sessionId);
        const approvalGrant = sessionState?.approvalGrants.get(payload.approvalGrantId);
        const session = sessionState?.onboardingSessions.get(payload.request.sessionId);
        const result = verifyToolCallbackV4(
          payload.request,
          sessionState?.session,
          session,
          approvalGrant,
          runtime
        );

        if (sessionState && session) {
          sessionState.onboardingSessions.set(payload.request.sessionId, {
            ...session,
            status: result.verdict.decision === "ALLOW" ? "used" : session.status
          });
        }

        writeJson(response, 200, result);
        return;
      }

      if (request.url === "/v4/artifact/ingest") {
        const payload = await readJson<V4ArtifactPayload>(request);
        const sessionState = findSessionState(sessions, payload.sessionId);
        if (!sessionState) {
          writeJson(response, 404, { error: "unknown_session" });
          return;
        }

        const capture: SurfaceCapture = {
          ...payload.capture,
          sessionId: payload.sessionId,
          taskId: sessionState.session.taskId
        };
        const observation = await compileObservationInIsolation({
          capture,
          workflowHash: sessionState.session.workflowHash,
          allowlistedEgress: runtime.parserAllowlistedEgress,
          runtime: {
            knowledgeBase: runtime.knowledgeBase
          }
        });

        const failClosedArtifact = applyV4FailClosedMediation(
          observation.compiledObservation,
          observation.plannerInput!,
          "artifact"
        );

        const legacyArtifact = buildLegacyObservationCapture(capture);
        const artifactResult =
          legacyArtifact !== undefined ? brokerArtifact(legacyArtifact, runtime) : undefined;

        sessionState.latestObservation = observation.compiledObservation;
        sessionState.observations.set(
          observation.compiledObservation.observationId,
          observation.compiledObservation
        );

        const effectiveArtifactVerdict = failClosedArtifact.failClosed
          ? failClosedArtifact.verdict
          : artifactResult?.verdict;
        const effectiveArtifact =
          failClosedArtifact.failClosed && artifactResult?.artifact
            ? {
                ...artifactResult.artifact,
                toolActivationPolicy: "block" as const,
                approvalRequiredForFollowOn: true
              }
            : artifactResult?.artifact;
        const plannerInput = shouldReduceAuthority(sessionState, observation.compiledObservation)
          ? applyAuthorityReduction(
              sessionState,
              observation.compiledObservation,
              failClosedArtifact.plannerInput
            )
          : failClosedArtifact.plannerInput;

        writeJson(response, 200, {
          compiledObservation: observation.compiledObservation,
          plannerInput,
          artifactVerdict: effectiveArtifactVerdict,
          artifact: effectiveArtifact
        });
        return;
      }

      if (request.url === "/v4/memory/write") {
        const payload = await readJson<V4MemoryWritePayload>(request);
        const sessionState = findSessionState(sessions, payload.sessionId);
        const result = evaluateMemoryWriteV4(payload, sessionState?.session, runtime);
        if (sessionState && result.record) {
          sessionState.memoryRecords.set(result.record.recordId, result.record);
        }

        writeJson(response, 200, result);
        return;
      }

      if (request.url === "/v4/memory/promote") {
        const payload = await readJson<MemoryPromotionRequest & { approvalGrantId?: string }>(
          request
        );
        const sessionState = findSessionState(sessions, payload.sessionId);
        const record = sessionState?.memoryRecords.get(payload.recordId);
        const approvalGrant =
          payload.approvalGrantId && sessionState
            ? sessionState.approvalGrants.get(payload.approvalGrantId)
            : undefined;
        const result = promoteMemoryRecordV4(
          payload,
          sessionState?.session,
          record,
          approvalGrant
        );
        if (sessionState && result.promotedRecord) {
          if (record && result.promotedRecord.snapshotId) {
            sessionState.memorySnapshots.set(result.promotedRecord.snapshotId, {
              ...record,
              tier: "trusted_durable",
              summaryOnly: false,
              snapshotId: result.promotedRecord.snapshotId,
              rollbackPointId: result.promotedRecord.rollbackPointId
            });
          }
          sessionState.memoryRecords.set(result.promotedRecord.recordId, result.promotedRecord);
        }

        writeJson(response, 200, result);
        return;
      }

      if (request.url === "/v4/memory/rollback") {
        const payload = await readJson<MemoryRollbackRequest>(request);
        const sessionState = findSessionState(sessions, payload.sessionId);
        const record = sessionState?.memoryRecords.get(payload.recordId);
        const snapshotRecord = sessionState?.memorySnapshots.get(payload.snapshotId) as
          | MemoryRecord
          | undefined;
        const result = rollbackMemoryRecordV4(
          payload,
          sessionState?.session,
          record,
          snapshotRecord
        );

        if (sessionState && result.restoredRecord) {
          sessionState.memoryRecords.set(result.restoredRecord.recordId, result.restoredRecord);
        }

        writeJson(response, 200, {
          ...result,
          rollbackEvent:
            result.verdict.decision === "ALLOW"
              ? {
                  recordId: payload.recordId,
                  snapshotId: payload.snapshotId,
                  appliedAt: new Date().toISOString()
                }
              : undefined
        });
        return;
      }

      writeJson(response, 404, { error: "not_found" });
    } catch (error) {
      writeJson(response, 500, {
        error: "server_error",
        message: error instanceof Error ? error.message : String(error)
      });
    }
  });
}

export async function startSafeBrowseDaemon(
  options: SafeBrowseDaemonOptions = {}
): Promise<Server> {
  const server = await createSafeBrowseServer(options);
  const port = options.port ?? 8787;
  const host = options.host ?? "127.0.0.1";

  await new Promise<void>((resolvePromise, rejectPromise) => {
    server.once("error", rejectPromise);
    server.listen(port, host, () => resolvePromise());
  });

  return server;
}

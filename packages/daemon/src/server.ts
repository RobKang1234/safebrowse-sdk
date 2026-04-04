import { createHash, createPublicKey, randomUUID, type KeyObject } from "node:crypto";
import { readFile, stat } from "node:fs/promises";
import { createServer, type IncomingMessage, type Server, type ServerResponse } from "node:http";
import { resolve } from "node:path";
import { fileURLToPath } from "node:url";

import {
  applyModelGuardAssessment,
  applyV6ObservationMediation,
  buildReplayBundle,
  buildModelGuardObservationRequest,
  compilePolicy,
  computeToolManifestHash,
  computeToolSchemaHash,
  createApprovalIntentPayloadV6,
  evaluateCapabilityUseV6,
  issueApprovalEnvelopeV6,
  mintCapabilitiesForObservationV6,
  mintMemoryPromotionCapabilityV6,
  prepareToolOnboardingV6,
  promoteMemoryRecordV6,
  rollbackMemoryRecordV6,
  stageMemoryRecordV6,
  tightenAuthoritiesWithModelGuard,
  verifyApprovalIntentSignatureV6,
  verifyToolCallbackV6,
  type ApprovalEnvelopeV6,
  type CapabilityDescriptorV6,
  type CompiledObservationV6,
  type ConnectorHandle,
  type KnowledgeBaseContext,
  type MemoryRecord,
  type MemoryRollbackRequest,
  type MemorySourceClassV6,
  type MemoryStageRequestV6,
  type ParserIsolationMode,
  type ParserWorkerProbe,
  type PolicyPack,
  type ReplayEvent,
  type RuntimeContext,
  type SafeVerdict,
  type SurfaceCapture,
  type TaskPurposeClass,
  type TargetPathClass,
  type TaskSession,
  type ToolCallbackVerificationRequest,
  type ToolOnboardingSessionV6,
  type V6ActionEvaluateRequest,
  type VerifiedRegistryBundle,
  type VerifiedRegistryEntry
} from "@safebrowse/core";
import {
  buildRegistryDefaults,
  loadKnowledgeBaseContext,
  loadPolicyPackFromPaths,
  loadVerifiedRegistryBundle,
  resolvePolicyLayerFiles
} from "./loaders.js";
import { createModelGuardClient } from "./modelGuard.js";
import { createParserIsolationService } from "./parserIsolation.js";

export interface SafeBrowseDaemonOptions {
  host?: string;
  port?: number;
  rootDir?: string;
  policyPack?: PolicyPack;
  knowledgeBase?: KnowledgeBaseContext;
  verifiedRegistry?: VerifiedRegistryBundle;
  parserAllowlistedEgress?: string[];
  parserIsolationMode?: ParserIsolationMode;
  deploymentProfile?: "development" | "secure_v6";
  approvalBrokerPublicKeyPath?: string;
  approvalBrokerPublicKeyPem?: string;
  approvalBrokerMode?: "signature_verification" | "external_service";
  modelGuardBaseUrl?: string;
  modelGuardTimeoutMs?: number;
  modelGuardEnforcementMode?: "off" | "tighten";
}

interface SessionState {
  session: TaskSession;
  latestObservation?: CompiledObservationV6;
  latestObservationVerdict?: SafeVerdict;
  observations: Map<string, CompiledObservationV6>;
  authorities: Map<string, CapabilityDescriptorV6>;
  usedAuthorities: Set<string>;
  approvalEnvelopes: Map<string, ApprovalEnvelopeV6>;
  onboardingSessions: Map<string, ToolOnboardingSessionV6>;
  connectorHandles: Map<string, ConnectorHandle>;
  memoryRecords: Map<string, MemoryRecord>;
  memorySourceClasses: Map<string, MemorySourceClassV6>;
  memorySnapshots: Map<string, MemorySnapshotState>;
  replayEvents: ReplayEvent[];
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

interface SessionStartRequest {
  taskId: string;
  userGoal: string;
  phase?: string;
  taskPurposeClass?: TaskPurposeClass;
  taskPhase?: string;
  allowedOrigins?: string[];
  allowedVerbs?: string[];
  forbiddenSinks?: string[];
  allowedPathClasses?: TargetPathClass[];
  approvalRequiredPathClasses?: TargetPathClass[];
  expiresInSeconds?: number;
}

interface V6ObservePayload {
  sessionId: string;
  capture: SurfaceCapture;
}

interface ApprovalIssuePayload {
  sessionId: string;
  authorityId?: string;
  authorityDigest?: string;
  capabilityId?: string;
  capabilityDigest?: string;
  brokerSignature: string;
  expiresInSeconds?: number;
}

interface ToolPreparePayload {
  sessionId: string;
  approvalId: string;
}

interface ToolCallbackPayload {
  sessionId: string;
  approvalId: string;
  onboardingSessionId: string;
  request: ToolCallbackVerificationRequest;
}

interface ArtifactIngestPayload {
  sessionId: string;
  capture: SurfaceCapture;
}

interface MemoryPromotePayload {
  sessionId: string;
  recordId: string;
  ticketId: string;
  ticketDigest: string;
  approvalId: string;
}

interface ReplayPayload {
  sessionId: string;
}

const PARSER_HEALTH_REFRESH_INTERVAL_MS = 30_000;

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

function logServerError(error: unknown): void {
  if (error instanceof Error) {
    console.error("SafeBrowse daemon error:", error.stack ?? error.message);
    return;
  }
  console.error("SafeBrowse daemon error:", error);
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
    parserIsolationMode: ParserIsolationMode;
    deploymentProfile: "development" | "secure_v6";
    approvalBrokerPublicKey?: KeyObject;
    approvalBrokerConfigured: boolean;
    approvalBrokerMode: "signature_verification" | "external_service";
    modelGuardBaseUrl?: string;
    modelGuardTimeoutMs: number;
    modelGuardEnforcementMode: "off" | "tighten";
  }
> {
  const rootDir = options.rootDir ?? (await resolveDefaultRootDir());
  const deploymentProfile = options.deploymentProfile ?? "development";
  const secureDeployment = deploymentProfile === "secure_v6";
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
    parserIsolationMode:
      secureDeployment
        ? "node_permission_process"
        : options.parserIsolationMode ?? "scrubbed_process",
    deploymentProfile,
    approvalBrokerPublicKey: approvalBrokerPublicKeyPem
      ? createPublicKey(approvalBrokerPublicKeyPem)
      : undefined,
    approvalBrokerConfigured: Boolean(approvalBrokerPublicKeyPem),
    approvalBrokerMode:
      secureDeployment ? "external_service" : options.approvalBrokerMode ?? "signature_verification",
    modelGuardBaseUrl: options.modelGuardBaseUrl?.trim() || undefined,
    modelGuardTimeoutMs: options.modelGuardTimeoutMs ?? 2_500,
    modelGuardEnforcementMode: options.modelGuardEnforcementMode ?? "off"
  };
}

function plusSeconds(value: string, seconds: number): string {
  return new Date(new Date(value).getTime() + seconds * 1_000).toISOString();
}

function createWorkflowHash(payload: SessionStartRequest): string {
  return hashValue({
    taskId: payload.taskId,
    userGoal: payload.userGoal,
    phase: payload.phase ?? "",
    taskPurposeClass: payload.taskPurposeClass ?? "",
    taskPhase: payload.taskPhase ?? "",
    allowedOrigins: payload.allowedOrigins ?? [],
    allowedVerbs: payload.allowedVerbs ?? [],
    forbiddenSinks: payload.forbiddenSinks ?? [],
    allowedPathClasses: payload.allowedPathClasses ?? [],
    approvalRequiredPathClasses: payload.approvalRequiredPathClasses ?? []
  });
}

function secureParserIsolationSatisfied(probe: ParserWorkerProbe): boolean {
  return (
    probe.mode === "node_permission_process" &&
    probe.processIsolated &&
    probe.egressDenied &&
    probe.permissionModelEnabled &&
    probe.childProcessDenied &&
    probe.workerThreadsDenied &&
    probe.envKeys.length === 0
  );
}

function claimBearingReady(
  runtime: {
    deploymentProfile: "development" | "secure_v6";
    approvalBrokerConfigured: boolean;
    approvalBrokerMode: "signature_verification" | "external_service";
    approvalBrokerPublicKey?: KeyObject;
    verifiedRegistry?: VerifiedRegistryBundle;
    parserIsolationMode: ParserIsolationMode;
  },
  probe: ParserWorkerProbe
): boolean {
  return (
    runtime.deploymentProfile === "secure_v6" &&
    runtime.approvalBrokerConfigured &&
    Boolean(runtime.approvalBrokerPublicKey) &&
    runtime.approvalBrokerMode === "external_service" &&
    runtime.verifiedRegistry?.signatureVerified === true &&
    runtime.parserIsolationMode === "node_permission_process" &&
    secureParserIsolationSatisfied(probe)
  );
}

function createSessionState(
  request: SessionStartRequest,
  runtime: {
    policy: RuntimeContext["policy"];
    deploymentProfile: "development" | "secure_v6";
  },
  secureReady: boolean
): SessionState {
  const createdAt = new Date().toISOString();
  const allowedOrigins =
    request.allowedOrigins ?? [...runtime.policy.readOnlyOrigins, ...runtime.policy.writableOrigins];
  const allowedVerbs = request.allowedVerbs ?? [...runtime.policy.allowedActions];
  const session: TaskSession = {
    sessionId: randomUUID(),
    taskId: request.taskId,
    userGoal: request.userGoal,
    phase: request.phase,
    taskPurposeClass: request.taskPurposeClass,
    taskPhase: request.taskPhase,
    allowedOrigins,
    allowedVerbs,
    forbiddenSinks: request.forbiddenSinks ?? [],
    allowedPathClasses: request.allowedPathClasses,
    approvalRequiredPathClasses: request.approvalRequiredPathClasses,
    workflowHash: createWorkflowHash({
      ...request,
      allowedOrigins,
      allowedVerbs
    }),
    currentStep: 0,
    createdAt,
    expiresAt: plusSeconds(createdAt, request.expiresInSeconds ?? 1800),
    claimProfile: secureReady ? "secure_v6" : undefined,
    approvalBrokerRequired: runtime.deploymentProfile === "secure_v6",
    legacyRoutesDisabled: true
  };

  return {
    session,
    observations: new Map(),
    authorities: new Map(),
    usedAuthorities: new Set(),
    approvalEnvelopes: new Map(),
    onboardingSessions: new Map(),
    connectorHandles: new Map(),
    memoryRecords: new Map(),
    memorySourceClasses: new Map(),
    memorySnapshots: new Map(),
    replayEvents: []
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

function appendReplayEvent(
  sessionState: SessionState | undefined,
  event: Omit<ReplayEvent, "eventId" | "timestamp">
): string | undefined {
  if (!sessionState) {
    return undefined;
  }

  const replayEvent: ReplayEvent = {
    eventId: randomUUID(),
    timestamp: new Date().toISOString(),
    ...event
  };
  sessionState.replayEvents.push(replayEvent);
  return replayEvent.eventId;
}

function authorityCandidateFromDescriptor(authority: CapabilityDescriptorV6) {
  return {
    authorityId: authority.capabilityId,
    authorityDigest: authority.capabilityDigest,
    semanticDigest: authority.semanticDigest,
    title: authority.title,
    kind: authority.kind,
    targetPathClass: authority.targetPathClass,
    requiresApproval: authority.requiresApproval,
    evidenceSpanIds: authority.evidenceSpanIds,
    parameterSchema: authority.parameterSchema,
    expiresAt: authority.expiresAt
  };
}

function consumeAuthority(sessionState: SessionState, authority: CapabilityDescriptorV6): void {
  sessionState.authorities.set(authority.capabilityId, {
    ...authority,
    consumedAt: new Date().toISOString()
  });
  sessionState.usedAuthorities.add(authority.capabilityId);
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

function buildArtifactRef(
  capture: SurfaceCapture,
  observation: CompiledObservationV6
) {
  const extractionMethod =
    capture.surfaceType === "html"
      ? "dom"
      : capture.surfaceType === "tool_manifest" || capture.surfaceType === "memory_candidate"
        ? "api"
        : capture.surfaceType === "image"
          ? "ocr"
          : "download";
  const surfaceKind =
    capture.surfaceType === "tool_manifest"
      ? "tool_manifest"
      : capture.surfaceType === "memory_candidate"
        ? "memory"
        : capture.surfaceType;

  return {
    artifactId: observation.observationId,
    surfaceKind,
    sourceOrigin: observation.sourceOrigin,
    viewerOrigin: observation.frameOrigin,
    mismatchSignals:
      observation.parseStatus === "compiled" ? [] : [`parse_status_${observation.parseStatus}`],
    metadataSignals: observation.policyFindings.map((finding) => finding.code),
    provenance: {
      extractionMethod,
      lineageChain: [],
      derivedTaintClass: "tainted" as const
    },
    authorityEligible: observation.authorityEligible
  };
}

function buildMemorySnapshotState(
  sessionState: SessionState,
  record: MemoryRecord
): MemorySnapshotState {
  const priorTrustedRecord = [...sessionState.memoryRecords.values()]
    .filter(
      (candidate) =>
        candidate.recordId !== record.recordId &&
        candidate.key === record.key &&
        candidate.tier === "trusted_durable"
    )
    .sort((left, right) => right.createdAt.localeCompare(left.createdAt))[0];

  return {
    snapshotId: "",
    sessionId: sessionState.session.sessionId,
    recordId: record.recordId,
    key: record.key,
    createdAt: new Date().toISOString(),
    baselineAbsent: !priorTrustedRecord,
    snapshotRecord: priorTrustedRecord
  };
}

function retiredRouteResponse(route: string) {
  return {
    error: "route_retired_use_v6",
    route,
    replacementPrefix: "/v6",
    deprecated: true
  };
}

function isRetiredRoute(url: string): boolean {
  return (
    url.startsWith("/v1/") ||
    url.startsWith("/v2/") ||
    url.startsWith("/v4/") ||
    url.startsWith("/v5/")
  );
}

export async function createSafeBrowseServer(
  options: SafeBrowseDaemonOptions = {}
): Promise<Server> {
  const runtime = await buildRuntimeContext(options);
  const modelGuardClient = createModelGuardClient({
    baseUrl: runtime.modelGuardBaseUrl,
    timeoutMs: runtime.modelGuardTimeoutMs,
    enforcementMode: runtime.modelGuardEnforcementMode
  });
  const parserIsolationService = createParserIsolationService(runtime.parserIsolationMode, {
    allowlistedEgress: runtime.parserAllowlistedEgress,
    runtime
  });
  let parserProbeSnapshot = await parserIsolationService.refreshProbe();
  let modelGuardHealthSnapshot = await modelGuardClient.refreshHealth();
  const secureReady = claimBearingReady(runtime, parserProbeSnapshot.probe);
  const sessions = new Map<string, SessionState>();

  const parserHealthRefreshTimer = setInterval(() => {
    void parserIsolationService
      .refreshProbe()
      .then((snapshot) => {
        parserProbeSnapshot = snapshot;
      })
      .catch(() => undefined);
    void modelGuardClient
      .refreshHealth()
      .then((snapshot) => {
        modelGuardHealthSnapshot = snapshot;
      })
      .catch(() => undefined);
  }, PARSER_HEALTH_REFRESH_INTERVAL_MS);
  parserHealthRefreshTimer.unref?.();

  const server = createServer(async (request, response) => {
    try {
      const requestUrl = request.url ?? "/";

      if (request.method === "GET" && requestUrl === "/health") {
        writeJson(response, 200, {
          status: "ok",
          deploymentProfile: runtime.deploymentProfile,
          claimBearingReady: claimBearingReady(runtime, parserProbeSnapshot.probe),
          legacyRoutesEnabled: false,
          approvalBroker: {
            configured: runtime.approvalBrokerConfigured,
            mode: runtime.approvalBrokerMode
          },
          parserIsolation: {
            configuredMode: runtime.parserIsolationMode,
            lastCheckedAt: parserProbeSnapshot.lastCheckedAt,
            ...parserProbeSnapshot.probe
          },
          verifiedRegistry: runtime.verifiedRegistry
            ? {
                bundleId: runtime.verifiedRegistry.bundleId,
                version: runtime.verifiedRegistry.version,
                signer: runtime.verifiedRegistry.signer,
                signatureVerified: runtime.verifiedRegistry.signatureVerified
              }
            : undefined,
          policyLayers: runtime.policy.layerProvenance,
          captureAttestation: {
            htmlDom: true,
            required: true
          },
          modelGuard: {
            configured: modelGuardHealthSnapshot.configured,
            ready: modelGuardHealthSnapshot.ready,
            runtimeMode: modelGuardHealthSnapshot.runtimeMode,
            enforcementMode: modelGuardHealthSnapshot.enforcementMode,
            bundleVersion: modelGuardHealthSnapshot.bundleVersion,
            featureSchemaVersion: modelGuardHealthSnapshot.featureSchemaVersion
          }
        });
        return;
      }

      if (isRetiredRoute(requestUrl)) {
        writeJson(response, 410, retiredRouteResponse(requestUrl));
        return;
      }

      if (request.method !== "POST" || !requestUrl.startsWith("/v6/")) {
        writeJson(response, 404, { error: "not_found" });
        return;
      }

      if (requestUrl === "/v6/session/start") {
        const payload = await readJson<SessionStartRequest>(request);
        const sessionState = createSessionState(payload, runtime, secureReady);
        sessions.set(sessionState.session.sessionId, sessionState);

        appendReplayEvent(sessionState, {
          kind: "observation",
          actor: "sdk",
          payload: {
            route: requestUrl,
            sessionId: sessionState.session.sessionId,
            taskId: sessionState.session.taskId
          }
        });

        writeJson(response, 200, {
          session: sessionState.session
        });
        return;
      }

      if (requestUrl === "/v6/observe") {
        const payload = await readJson<V6ObservePayload>(request);
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

        const parsed = await parserIsolationService.compileObservation({
          capture,
          workflowHash: sessionState.session.workflowHash,
          runtime,
          compilerVersion: "v6"
        });
        let compiledObservation = parsed.compiledObservation;
        let plannerView = parsed.plannerView!;
        let mediated = applyV6ObservationMediation(compiledObservation, plannerView);
        const verifiedRegistryEntry =
          capture.surfaceType === "tool_manifest"
            ? lookupVerifiedRegistryEntry(runtime, capture.toolId, capture.toolId)
            : undefined;
        const manifestHash =
          capture.surfaceType === "tool_manifest"
            ? parsed.toolManifestDigests?.manifestHash ??
              computeToolManifestHash({
                toolId: capture.toolId,
                description: capture.description,
                authType: capture.authType,
                requestedScopes: capture.requestedScopes,
                callbackUri: capture.callbackUri
              })
            : undefined;
        const schemaHash =
          capture.surfaceType === "tool_manifest"
            ? parsed.toolManifestDigests?.schemaHash ??
              computeToolSchemaHash(capture.schemaDescriptions)
            : undefined;

        if (modelGuardClient.configured && mediated.verdict.decision === "ALLOW") {
          try {
            const scored = await modelGuardClient.scoreObservation(
              buildModelGuardObservationRequest(sessionState.session, compiledObservation, plannerView)
            );
            const applied = applyModelGuardAssessment(
              compiledObservation,
              plannerView,
              mediated.verdict,
              scored.assessment
            );
            compiledObservation = applied.compiledObservation;
            plannerView = applied.plannerView;
            mediated = {
              plannerView,
              verdict: applied.verdict,
              failClosed: false
            };
          } catch {
            if (modelGuardClient.enforcementMode === "tighten") {
              compiledObservation = {
                ...compiledObservation,
                authorityEligible: false
              };
              plannerView = {
                ...plannerView,
                visibleExcerpt: "",
                riskMarkers: [...new Set([...plannerView.riskMarkers, "model_guard_unavailable"])]
              };
              mediated = {
                plannerView,
                verdict: {
                  decision: "REPLAN_READ_ONLY",
                  reasonCodes: ["MODEL_GUARD_UNAVAILABLE"],
                  riskScore: Math.max(0.6, compiledObservation.riskScore),
                  safeConstraints: {
                    claim_profile: "secure_v6",
                    authority_eligible: false
                  },
                  telemetryTags: ["v6_observation", "model_guard_unavailable"]
                },
                failClosed: false
              };
            }
          }
        }

        const authorities =
          mediated.verdict.decision === "BLOCK"
            ? []
            : mintCapabilitiesForObservationV6(
                sessionState.session,
                compiledObservation,
                plannerView,
                capture.surfaceType === "tool_manifest" && verifiedRegistryEntry
                  ? {
                      verifiedRegistryEntry,
                      registryEntryId: capture.toolId,
                      connectorId: capture.toolId,
                      requestedScopes: capture.requestedScopes,
                      callbackUri: capture.callbackUri,
                      callbackOrigin: capture.callbackOrigin,
                      manifestAuthType: capture.authType,
                      manifestHash,
                      schemaHash
                    }
                  : {}
              );
        const tightenedAuthorities = tightenAuthoritiesWithModelGuard(
          authorities,
          compiledObservation.modelAssessment
        );

        for (const authority of tightenedAuthorities) {
          sessionState.authorities.set(authority.capabilityId, authority);
        }

        sessionState.latestObservation = compiledObservation;
        sessionState.latestObservationVerdict = mediated.verdict;
        sessionState.observations.set(
          compiledObservation.observationId,
          compiledObservation
        );

        const replayEventId = appendReplayEvent(sessionState, {
          kind: "observation",
          actor: "sdk",
          payload: {
            route: requestUrl,
            observationId: compiledObservation.observationId,
            parseStatus: compiledObservation.parseStatus,
            authorityCount: tightenedAuthorities.length,
            decision: mediated.verdict.decision,
            modelAssessment: compiledObservation.modelAssessment
              ? {
                  bundleVersion: compiledObservation.modelAssessment.bundleVersion,
                  calibratedDecisionLabel: compiledObservation.modelAssessment.calibratedDecisionLabel,
                  coarseReasonCodes: compiledObservation.modelAssessment.coarseReasonCodes,
                  evidenceChunkIds: compiledObservation.modelAssessment.evidenceChunkIds
                }
              : null
          }
        });

        writeJson(response, 200, {
          compiledObservation,
          plannerView,
          authorityCandidates: tightenedAuthorities.map(authorityCandidateFromDescriptor),
          capabilities: tightenedAuthorities.map(authorityCandidateFromDescriptor),
          artifactRefs: [],
          observationVerdict: mediated.verdict,
          replayEventId: replayEventId ?? randomUUID()
        });
        return;
      }

      if (requestUrl === "/v6/action/evaluate") {
        const payload = await readJson<V6ActionEvaluateRequest>(request);
        const sessionState = findSessionState(sessions, payload.sessionId);
        const authority = sessionState?.authorities.get(payload.authorityId);
        const approvalEnvelope =
          payload.approvalId && sessionState
            ? sessionState.approvalEnvelopes.get(payload.approvalId)
            : undefined;
        const authorityDecision = evaluateCapabilityUseV6(payload, sessionState?.session, authority, {
          alreadyUsed: sessionState?.usedAuthorities.has(payload.authorityId) ?? false,
          approvalEnvelope
        });

        if (sessionState && authority && authorityDecision.decision === "ALLOW") {
          consumeAuthority(sessionState, authority);
          if (approvalEnvelope) {
            sessionState.approvalEnvelopes.set(approvalEnvelope.approvalId, {
              ...approvalEnvelope,
              consumedAt: new Date().toISOString()
            });
          }
          sessionState.session = {
            ...sessionState.session,
            currentStep: sessionState.session.currentStep + 1
          };
        }

        appendReplayEvent(sessionState, {
          kind: "action",
          actor: "sdk",
          payload: {
            route: requestUrl,
            authorityId: payload.authorityId,
            decision: authorityDecision.decision
          }
        });

        writeJson(response, 200, {
          observationDecision:
            sessionState?.latestObservationVerdict ?? {
              decision: "ALLOW",
              reasonCodes: [],
              riskScore: 0
            },
          authorityDecision,
          effectDecision: authorityDecision,
          executionPlan:
            authorityDecision.decision === "ALLOW" && authority
              ? {
                  verb: authority.kind,
                  targetUrl: authority.targetUrl,
                  targetOrigin: authority.targetOrigin,
                  selector: authority.selector,
                  targetPathClass: authority.targetPathClass,
                  derivedSinkClass: authority.derivedSinkClass,
                  derivedSensitiveSink: authority.derivedSensitiveSink
                }
              : undefined
        });
        return;
      }

      if (requestUrl === "/v6/approval/issue") {
        const payload = await readJson<ApprovalIssuePayload>(request);
        const sessionState = findSessionState(sessions, payload.sessionId);
        const authorityId = payload.authorityId ?? payload.capabilityId ?? "";
        const authorityDigest = payload.authorityDigest ?? payload.capabilityDigest ?? "";
        const authority = sessionState?.authorities.get(authorityId);

        if (!sessionState || !authority) {
          writeJson(response, 404, {
            error: !sessionState ? "unknown_session" : "unknown_authority"
          });
          return;
        }

        const signatureValid =
          authority.capabilityDigest === authorityDigest &&
          verifyApprovalIntentSignatureV6(
            createApprovalIntentPayloadV6({
              sessionId: sessionState.session.sessionId,
              workflowHash: sessionState.session.workflowHash,
              capabilityId: authority.capabilityId,
              capabilityDigest: authority.capabilityDigest,
              expiresInSeconds: payload.expiresInSeconds
            }),
            payload.brokerSignature,
            runtime.approvalBrokerPublicKey
          );

        const issued = issueApprovalEnvelopeV6({
          session: sessionState.session,
          capability: authority,
          brokerSignature: payload.brokerSignature,
          brokerSignatureVerified: signatureValid,
          expiresInSeconds: payload.expiresInSeconds
        });

        if (issued.approvalEnvelope) {
          sessionState.approvalEnvelopes.set(
            issued.approvalEnvelope.approvalId,
            issued.approvalEnvelope
          );
        }

        appendReplayEvent(sessionState, {
          kind: "tool",
          actor: "sdk",
          payload: {
            route: requestUrl,
            authorityId,
            decision: issued.verdict.decision
          }
        });

        writeJson(response, 200, issued);
        return;
      }

      if (requestUrl === "/v6/tool/prepare") {
        const payload = await readJson<ToolPreparePayload>(request);
        const sessionState = findSessionState(sessions, payload.sessionId);
        const approvalEnvelope = sessionState?.approvalEnvelopes.get(payload.approvalId);
        const authority =
          approvalEnvelope && sessionState
            ? sessionState.authorities.get(approvalEnvelope.capabilityId)
            : undefined;
        const verifiedRegistryEntry =
          authority?.registryEntryId
            ? lookupVerifiedRegistryEntry(runtime, authority.connectorId, authority.registryEntryId)
            : undefined;
        const prepared = prepareToolOnboardingV6({
          session: sessionState?.session,
          capability: authority,
          approvalEnvelope,
          verifiedRegistryEntry
        });

        if (sessionState && approvalEnvelope && authority && prepared.onboardingSession) {
          sessionState.onboardingSessions.set(
            prepared.onboardingSession.onboardingSessionId,
            prepared.onboardingSession
          );
          sessionState.approvalEnvelopes.set(approvalEnvelope.approvalId, {
            ...approvalEnvelope,
            consumedAt: new Date().toISOString(),
            onboardingSessionId: prepared.onboardingSession.onboardingSessionId
          });
          consumeAuthority(sessionState, authority);
          sessionState.session = {
            ...sessionState.session,
            currentStep: sessionState.session.currentStep + 1
          };
        }

        appendReplayEvent(sessionState, {
          kind: "tool",
          actor: "sdk",
          payload: {
            route: requestUrl,
            approvalId: payload.approvalId,
            decision: prepared.verdict.decision
          }
        });

        writeJson(response, 200, prepared);
        return;
      }

      if (requestUrl === "/v6/tool/callback/verify") {
        const payload = await readJson<ToolCallbackPayload>(request);
        const sessionState = findSessionState(sessions, payload.sessionId);
        const approvalEnvelope = sessionState?.approvalEnvelopes.get(payload.approvalId);
        const onboardingSession = sessionState?.onboardingSessions.get(payload.onboardingSessionId);
        const authority =
          approvalEnvelope && sessionState
            ? sessionState.authorities.get(approvalEnvelope.capabilityId)
            : undefined;
        const verifiedRegistryEntry =
          authority?.registryEntryId
            ? lookupVerifiedRegistryEntry(runtime, authority.connectorId, authority.registryEntryId)
            : undefined;
        const verified = verifyToolCallbackV6({
          session: sessionState?.session,
          capability: authority,
          approvalEnvelope,
          onboardingSession,
          verifiedRegistryEntry,
          request: payload.request
        });

        if (sessionState && onboardingSession && verified.connectorHandle) {
          sessionState.onboardingSessions.set(onboardingSession.onboardingSessionId, {
            ...onboardingSession,
            status: "used"
          });
          sessionState.connectorHandles.set(
            verified.connectorHandle.handleId,
            verified.connectorHandle
          );
        }

        appendReplayEvent(sessionState, {
          kind: "tool",
          actor: "sdk",
          payload: {
            route: requestUrl,
            onboardingSessionId: payload.onboardingSessionId,
            decision: verified.verdict.decision
          }
        });

        writeJson(response, 200, verified);
        return;
      }

      if (requestUrl === "/v6/artifact/ingest") {
        const payload = await readJson<ArtifactIngestPayload>(request);
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

        const parsed = await parserIsolationService.compileObservation({
          capture,
          workflowHash: sessionState.session.workflowHash,
          runtime,
          compilerVersion: "v6"
        });
        const mediated = applyV6ObservationMediation(
          parsed.compiledObservation,
          parsed.plannerView!
        );
        const artifactRef = buildArtifactRef(capture, parsed.compiledObservation);
        sessionState.latestObservation = parsed.compiledObservation;
        sessionState.latestObservationVerdict = mediated.verdict;
        sessionState.observations.set(
          parsed.compiledObservation.observationId,
          parsed.compiledObservation
        );

        const replayEventId = appendReplayEvent(sessionState, {
          kind: "artifact",
          actor: "sdk",
          payload: {
            route: requestUrl,
            observationId: parsed.compiledObservation.observationId,
            decision: mediated.verdict.decision
          }
        });

        writeJson(response, 200, {
          compiledObservation: parsed.compiledObservation,
          plannerView: mediated.plannerView,
          artifactRef,
          mismatchSignals: artifactRef.mismatchSignals,
          artifactVerdict: mediated.verdict,
          replayEventId: replayEventId ?? randomUUID()
        });
        return;
      }

      if (requestUrl === "/v6/memory/stage") {
        const payload = await readJson<MemoryStageRequestV6>(request);
        const sessionState = findSessionState(sessions, payload.sessionId);
        const result = stageMemoryRecordV6(payload, sessionState?.session);

        let promotionAuthority;
        if (sessionState && result.record) {
          sessionState.memoryRecords.set(result.record.recordId, result.record);
          sessionState.memorySourceClasses.set(result.record.recordId, payload.sourceClass);
          promotionAuthority = mintMemoryPromotionCapabilityV6(sessionState.session, {
            recordId: result.record.recordId,
            sourceDigest: result.record.sourceDigest,
            sourceObservationId: result.record.sourceObservationId,
            key: result.record.key,
            valueDigest: result.record.sourceDigest ?? hashValue(result.record.value)
          });
          sessionState.authorities.set(promotionAuthority.capabilityId, promotionAuthority);
        }

        appendReplayEvent(sessionState, {
          kind: "memory",
          actor: "sdk",
          payload: {
            route: requestUrl,
            recordId: result.record?.recordId ?? null,
            decision: result.verdict.decision
          }
        });

        writeJson(response, 200, {
          ...result,
          promotionAuthority: promotionAuthority
            ? authorityCandidateFromDescriptor(promotionAuthority)
            : undefined,
          promotionTicket: promotionAuthority
            ? {
                ticketId: promotionAuthority.capabilityId,
                ticketDigest: promotionAuthority.capabilityDigest,
                semanticDigest: promotionAuthority.semanticDigest,
                recordId: result.record?.recordId,
                sourceClass: payload.sourceClass,
                expiresAt: promotionAuthority.expiresAt
              }
            : undefined
        });
        return;
      }

      if (requestUrl === "/v6/memory/promote") {
        const payload = await readJson<MemoryPromotePayload>(request);
        const sessionState = findSessionState(sessions, payload.sessionId);
        const record = sessionState?.memoryRecords.get(payload.recordId);
        const authority = sessionState?.authorities.get(payload.ticketId);
        const approvalEnvelope = sessionState?.approvalEnvelopes.get(payload.approvalId);
        const snapshotState =
          sessionState && record ? buildMemorySnapshotState(sessionState, record) : undefined;
        const result = promoteMemoryRecordV6(
          payload,
          sessionState?.session,
          record,
          authority,
          approvalEnvelope,
          {
            sourceClass: record
              ? sessionState?.memorySourceClasses.get(record.recordId)
              : undefined,
            priorTrustedRecord: snapshotState?.snapshotRecord
          }
        );

        if (sessionState && result.promotedRecord) {
          if (snapshotState && result.promotedRecord.snapshotId) {
            sessionState.memorySnapshots.set(result.promotedRecord.snapshotId, {
              ...snapshotState,
              snapshotId: result.promotedRecord.snapshotId
            });
          }
          sessionState.memoryRecords.set(result.promotedRecord.recordId, result.promotedRecord);
          if (authority) {
            consumeAuthority(sessionState, authority);
          }
          if (approvalEnvelope) {
            sessionState.approvalEnvelopes.set(payload.approvalId, {
              ...approvalEnvelope,
              consumedAt: new Date().toISOString()
            });
          }
          sessionState.session = {
            ...sessionState.session,
            currentStep: sessionState.session.currentStep + 1
          };
        }

        appendReplayEvent(sessionState, {
          kind: "memory",
          actor: "sdk",
          payload: {
            route: requestUrl,
            recordId: payload.recordId,
            decision: result.verdict.decision
          }
        });

        writeJson(response, 200, {
          ...result,
          approvalEnvelope:
            payload.approvalId && sessionState
              ? sessionState.approvalEnvelopes.get(payload.approvalId)
              : approvalEnvelope
        });
        return;
      }

      if (requestUrl === "/v6/memory/rollback") {
        const payload = await readJson<MemoryRollbackRequest>(request);
        const sessionState = findSessionState(sessions, payload.sessionId);
        const record = sessionState?.memoryRecords.get(payload.recordId);
        const snapshotState = sessionState?.memorySnapshots.get(payload.snapshotId);
        const result = rollbackMemoryRecordV6(payload, sessionState?.session, record, {
          snapshotRecord: snapshotState?.snapshotRecord,
          baselineAbsent: snapshotState?.baselineAbsent
        });

        if (sessionState && result.verdict.decision === "ALLOW") {
          if (result.restoredRecord) {
            sessionState.memoryRecords.set(result.restoredRecord.recordId, result.restoredRecord);
          } else {
            sessionState.memoryRecords.delete(payload.recordId);
          }
        }

        appendReplayEvent(sessionState, {
          kind: "memory",
          actor: "sdk",
          payload: {
            route: requestUrl,
            recordId: payload.recordId,
            snapshotId: payload.snapshotId,
            decision: result.verdict.decision
          }
        });

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

      if (requestUrl === "/v6/replay/bundle") {
        const payload = await readJson<ReplayPayload>(request);
        const sessionState = findSessionState(sessions, payload.sessionId);
        if (!sessionState) {
          writeJson(response, 404, { error: "unknown_session" });
          return;
        }

        writeJson(response, 200, buildReplayBundle(sessionState.replayEvents, runtime));
        return;
      }

      writeJson(response, 404, { error: "not_found" });
    } catch (error) {
      logServerError(error);
      writeJson(response, 500, {
        error: "server_error"
      });
    }
  });

  const originalClose = server.close.bind(server);
  server.close = ((callback?: (error?: Error) => void) => {
    clearInterval(parserHealthRefreshTimer);
    return originalClose((error?: Error) => {
      void Promise.allSettled([parserIsolationService.close(), modelGuardClient.close()]).finally(() => {
        callback?.(error);
      });
    });
  }) as Server["close"];

  return server;
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

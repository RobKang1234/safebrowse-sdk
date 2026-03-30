import { createHash, randomUUID } from "node:crypto";
import { stat } from "node:fs/promises";
import { createServer, type IncomingMessage, type Server, type ServerResponse } from "node:http";
import { resolve } from "node:path";
import { fileURLToPath } from "node:url";

import {
  applyV4FailClosedMediation,
  attachCapabilitiesToPlannerInput,
  brokerArtifact,
  brokerArtifactV2,
  buildReplayBundle,
  compilePolicy,
  createApprovalGrantHash,
  evaluateAction,
  evaluateCapabilityUse,
  evaluateMemoryWrite,
  evaluateMemoryWriteV4,
  evaluateToolRequest,
  mintCapabilitiesForObservation,
  prepareToolOnboarding,
  prepareToolOnboardingV4,
  promoteMemoryRecordV4,
  sanitizeObservation,
  verifyToolCallback,
  verifyToolCallbackV4,
  type ActionProposal,
  type ApprovalGrant,
  type ArtifactInput,
  type ArtifactV2Input,
  type CapabilityDescriptor,
  type CapabilityUseRequest,
  type CompiledObservation,
  type KnowledgeBaseContext,
  type MemoryPromotionRequest,
  type MemoryRecord,
  type MemoryWriteRequest,
  type PolicyPack,
  type ReplayEvent,
  type RuntimeContext,
  type SurfaceCapture,
  type TaskSession,
  type ToolCallbackVerificationRequest,
  type ToolOnboardingSession,
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
}

interface SessionState {
  session: TaskSession;
  latestObservation?: CompiledObservation;
  capabilities: Map<string, CapabilityDescriptor>;
  usedCapabilities: Set<string>;
  approvalGrants: Map<string, ApprovalGrant>;
  memoryRecords: Map<string, MemoryRecord>;
  onboardingSessions: Map<string, ToolOnboardingSession>;
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

  return {
    policy: compilePolicy(policyPack),
    knowledgeBase,
    verifiedRegistry,
    parserAllowlistedEgress: options.parserAllowlistedEgress ?? []
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
  runtime: RuntimeContext
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
    expiresAt: plusSeconds(createdAt, request.expiresInSeconds ?? 1800)
  };

  return {
    session,
    capabilities: new Map(),
    usedCapabilities: new Set(),
    approvalGrants: new Map(),
    memoryRecords: new Map(),
    onboardingSessions: new Map()
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
          version: runtime.policy.version,
          policyLayers: runtime.policy.layerProvenance,
          verifiedRegistry: runtime.verifiedRegistry
            ? {
                bundleId: runtime.verifiedRegistry.bundleId,
                version: runtime.verifiedRegistry.version,
                signatureVerified: runtime.verifiedRegistry.signatureVerified,
                entryCount: runtime.verifiedRegistry.entries.length
              }
            : undefined,
          parserIsolation: parserProbe
        });
        return;
      }

      if (request.method !== "POST") {
        writeJson(response, 405, { error: "method_not_allowed" });
        return;
      }

      if (request.url === "/v1/observe") {
        const payload = await readJson<Parameters<typeof sanitizeObservation>[0]>(request);
        writeJson(response, 200, sanitizeObservation(payload, runtime));
        return;
      }

      if (request.url === "/v1/action") {
        const payload = await readJson<ActionProposal>(request);
        writeJson(response, 200, evaluateAction(payload, runtime));
        return;
      }

      if (request.url === "/v1/artifact") {
        const payload = await readJson<ArtifactInput>(request);
        writeJson(response, 200, brokerArtifact(payload, runtime));
        return;
      }

      if (request.url === "/v1/tool") {
        const payload = await readJson<ToolRequest>(request);
        writeJson(response, 200, evaluateToolRequest(payload, runtime));
        return;
      }

      if (request.url === "/v1/memory") {
        const payload = await readJson<MemoryWriteRequest>(request);
        writeJson(response, 200, evaluateMemoryWrite(payload, runtime));
        return;
      }

      if (request.url === "/v1/replay") {
        const payload = await readJson<{ events: ReplayEvent[] }>(request);
        writeJson(response, 200, buildReplayBundle(payload.events, runtime));
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
          onboardingSession
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
        writeJson(response, 200, result);
        return;
      }

      if (request.url === "/v2/artifact") {
        const payload = await readJson<ArtifactV2Input>(request);
        writeJson(response, 200, brokerArtifactV2(payload, runtime));
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
          observation.plannerInput,
          "observe"
        );

        const capabilities = mintCapabilitiesForObservation(
          sessionState.session,
          observation.compiledObservation,
          {
            sourceObservationId: observation.compiledObservation.observationId
          }
        );

        sessionState.capabilities.clear();
        for (const capability of capabilities) {
          sessionState.capabilities.set(capability.capabilityId, capability);
        }
        sessionState.latestObservation = observation.compiledObservation;

        writeJson(response, 200, {
          compiledObservation: observation.compiledObservation,
          observationVerdict: failClosedObservation.verdict,
          plannerInput: attachCapabilitiesToPlannerInput(
            failClosedObservation.plannerInput,
            capabilities
          )
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
                  selector: capability.selector
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
          observation.plannerInput,
          "artifact"
        );

        const legacyArtifact = buildLegacyObservationCapture(capture);
        const artifactResult =
          legacyArtifact !== undefined ? brokerArtifact(legacyArtifact, runtime) : undefined;

        sessionState.latestObservation = observation.compiledObservation;

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

        writeJson(response, 200, {
          compiledObservation: observation.compiledObservation,
          plannerInput: failClosedArtifact.plannerInput,
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
          sessionState.memoryRecords.set(result.promotedRecord.recordId, result.promotedRecord);
        }

        writeJson(response, 200, result);
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

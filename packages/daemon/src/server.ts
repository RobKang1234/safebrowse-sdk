import { randomUUID } from "node:crypto";
import { createServer, type IncomingMessage, type Server, type ServerResponse } from "node:http";
import { resolve } from "node:path";

import {
  brokerArtifact,
  brokerArtifactV2,
  buildReplayBundle,
  compilePolicy,
  evaluateAction,
  evaluateMemoryWrite,
  evaluateToolRequest,
  prepareToolOnboarding,
  sanitizeObservation,
  verifyToolCallback,
  type ActionProposal,
  type ArtifactInput,
  type ArtifactV2Input,
  type KnowledgeBaseContext,
  type MemoryWriteRequest,
  type PolicyPack,
  type ReplayEvent,
  type RuntimeContext,
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
} from "@safebrowse/kb-tools";
import type { VerifiedRegistryBundle } from "@safebrowse/core";

export interface SafeBrowseDaemonOptions {
  host?: string;
  port?: number;
  rootDir?: string;
  policyPack?: PolicyPack;
  knowledgeBase?: KnowledgeBaseContext;
  verifiedRegistry?: VerifiedRegistryBundle;
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

async function buildRuntimeContext(
  options: SafeBrowseDaemonOptions
): Promise<RuntimeContext & { knowledgeBase: KnowledgeBaseContext; verifiedRegistry?: VerifiedRegistryBundle }> {
  const rootDir = options.rootDir ?? process.cwd();
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
    verifiedRegistry
  };
}

function plusMinutes(value: string, minutes: number): string {
  return new Date(new Date(value).getTime() + minutes * 60_000).toISOString();
}

function createOnboardingSession(
  request: ToolRequest,
  runtime: RuntimeContext & { verifiedRegistry?: VerifiedRegistryBundle },
  workflowBindingId?: string
): ToolOnboardingSession | undefined {
  const callbackUri =
    request.oauthContext?.callbackUri ??
    request.callbackUri ??
    request.oauthContext?.redirectUri ??
    request.requestedRedirectUri;

  if (!callbackUri) {
    return undefined;
  }

  const createdAt = (runtime.now?.() ?? new Date()).toISOString();
  return {
    sessionId: randomUUID(),
    approvalBindingId: request.approvalBindingId ?? randomUUID(),
    workflowBindingId,
    toolId: request.toolId,
    registryEntryId: request.registryEntryId ?? request.toolId,
    registryBundleId:
      request.registryBundleId ?? runtime.verifiedRegistry?.bundleId ?? "unverified-registry",
    callbackUri,
    callbackOrigin: new URL(callbackUri).origin,
    requestedScopes: request.requestedScopes ?? request.oauthContext?.requestedScopes ?? [],
    state: randomUUID(),
    pkceMethod: "S256",
    createdAt,
    expiresAt: plusMinutes(createdAt, 5),
    status: "prepared"
  };
}

export async function createSafeBrowseServer(
  options: SafeBrowseDaemonOptions = {}
): Promise<Server> {
  const runtime = await buildRuntimeContext(options);
  const onboardingSessions = new Map<string, ToolOnboardingSession>();

  return createServer(async (request, response) => {
    if (!request.url) {
      writeJson(response, 400, { error: "missing_url" });
      return;
    }

    try {
      if (request.method === "GET" && request.url === "/health") {
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
            : undefined
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
            ? createOnboardingSession(payload, runtime, prepared.workflowBinding?.bindingId)
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


import { createServer, type IncomingMessage, type Server, type ServerResponse } from "node:http";
import { resolve } from "node:path";

import {
  brokerArtifact,
  buildReplayBundle,
  compilePolicy,
  evaluateAction,
  evaluateMemoryWrite,
  evaluateToolRequest,
  sanitizeObservation,
  type ActionProposal,
  type ArtifactInput,
  type KnowledgeBaseContext,
  type MemoryWriteRequest,
  type PolicyPack,
  type ReplayEvent,
  type RuntimeContext,
  type ToolRequest
} from "@safebrowse/core";
import {
  loadKnowledgeBaseContext,
  loadPolicyPackFromPaths,
  resolvePolicyLayerFiles
} from "@safebrowse/kb-tools";

export interface SafeBrowseDaemonOptions {
  host?: string;
  port?: number;
  rootDir?: string;
  policyPack?: PolicyPack;
  knowledgeBase?: KnowledgeBaseContext;
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
): Promise<RuntimeContext & { knowledgeBase: KnowledgeBaseContext }> {
  const rootDir = options.rootDir ?? process.cwd();
  const policyPack =
    options.policyPack ??
    (await loadPolicyPackFromPaths(resolvePolicyLayerFiles(resolve(rootDir))));
  const knowledgeBase =
    options.knowledgeBase ?? (await loadKnowledgeBaseContext(resolve(rootDir, "knowledge_base")));

  return {
    policy: compilePolicy(policyPack),
    knowledgeBase
  };
}

export async function createSafeBrowseServer(
  options: SafeBrowseDaemonOptions = {}
): Promise<Server> {
  const runtime = await buildRuntimeContext(options);

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
          version: runtime.policy.version
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


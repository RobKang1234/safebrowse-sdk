#!/usr/bin/env node
import { createPrivateKey, createPublicKey, generateKeyPairSync, sign, type KeyObject } from "node:crypto";
import { mkdir, mkdtemp, readFile, writeFile } from "node:fs/promises";
import { createServer, type IncomingMessage, type Server, type ServerResponse } from "node:http";
import type { AddressInfo } from "node:net";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import process from "node:process";

import { createApprovalIntentPayloadV6 } from "@safebrowse/core";

export interface ApprovalBrokerOptions {
  host?: string;
  port?: number;
  privateKeyPath?: string;
  privateKeyPem?: string;
  authToken?: string;
}

export interface ApprovalBrokerSignRequest {
  sessionId: string;
  workflowHash: string;
  capabilityId: string;
  capabilityDigest: string;
  expiresInSeconds?: number;
}

export interface ApprovalBrokerHealth {
  status: "ok";
  publicKeyPem: string;
  authTokenRequired: boolean;
  mode: "external_service";
}

export interface ApprovalBrokerSignResponse {
  brokerSignature: string;
  payload: string;
  publicKeyPem: string;
  mode: "external_service";
}

interface ParsedBrokerOptions extends ApprovalBrokerOptions {
  help?: boolean;
  writePublicKeyPath?: string;
}

const HELP_TEXT = `SafeBrowse approval broker

Usage:
  safebrowse-approval-broker [--host 127.0.0.1] [--port 8788] --private-key-path <path> [--write-public-key-path <path>]

Environment:
  SAFEBROWSE_BROKER_HOST
  SAFEBROWSE_BROKER_PORT
  SAFEBROWSE_BROKER_PRIVATE_KEY_PATH
  SAFEBROWSE_BROKER_AUTH_TOKEN
  SAFEBROWSE_BROKER_WRITE_PUBLIC_KEY_PATH
`;

function parsePort(value: string): number {
  const port = Number.parseInt(value, 10);
  if (!Number.isInteger(port) || port <= 0 || port > 65_535) {
    throw new Error(`Invalid port: ${value}`);
  }
  return port;
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

function isHttpWhitespace(value: string): boolean {
  return value === " " || value === "\t";
}

function logError(error: unknown): void {
  if (error instanceof Error) {
    console.error("Approval broker error:", error.stack ?? error.message);
    return;
  }
  console.error("Approval broker error:", error);
}

function bearerToken(request: IncomingMessage): string | undefined {
  const header = request.headers.authorization;
  if (!header) {
    return undefined;
  }
  const value = Array.isArray(header) ? header[0] : header;
  let index = 0;

  while (index < value.length && isHttpWhitespace(value[index])) {
    index += 1;
  }

  if (value.slice(index, index + 6).toLowerCase() !== "bearer") {
    return undefined;
  }
  index += 6;

  if (index >= value.length || !isHttpWhitespace(value[index])) {
    return undefined;
  }
  while (index < value.length && isHttpWhitespace(value[index])) {
    index += 1;
  }

  const token = value.slice(index).trim();
  return token.length > 0 ? token : undefined;
}

function createApprovalSignature(
  privateKey: KeyObject,
  payload: ApprovalBrokerSignRequest
): ApprovalBrokerSignResponse {
  const signingPayload = createApprovalIntentPayloadV6(payload);
  return {
    brokerSignature: sign(null, Buffer.from(signingPayload, "utf8"), privateKey).toString("base64"),
    payload: signingPayload,
    publicKeyPem: createPublicKey(privateKey).export({ format: "pem", type: "spki" }).toString(),
    mode: "external_service"
  };
}

export function parseApprovalBrokerOptions(
  argv: string[],
  env: NodeJS.ProcessEnv = process.env
): ParsedBrokerOptions {
  const options: ParsedBrokerOptions = {};
  const queue = [...argv];

  const envHost = env.SAFEBROWSE_BROKER_HOST?.trim();
  const envPort = env.SAFEBROWSE_BROKER_PORT?.trim();
  const envPrivateKeyPath = env.SAFEBROWSE_BROKER_PRIVATE_KEY_PATH?.trim();
  const envAuthToken = env.SAFEBROWSE_BROKER_AUTH_TOKEN?.trim();
  const envWritePublicKeyPath = env.SAFEBROWSE_BROKER_WRITE_PUBLIC_KEY_PATH?.trim();

  if (envHost) {
    options.host = envHost;
  }
  if (envPort) {
    options.port = parsePort(envPort);
  }
  if (envPrivateKeyPath) {
    options.privateKeyPath = resolve(envPrivateKeyPath);
  }
  if (envAuthToken) {
    options.authToken = envAuthToken;
  }
  if (envWritePublicKeyPath) {
    options.writePublicKeyPath = resolve(envWritePublicKeyPath);
  }

  while (queue.length > 0) {
    const arg = queue.shift();
    if (!arg) {
      continue;
    }
    if (arg === "--help" || arg === "-h") {
      options.help = true;
      continue;
    }
    if (arg === "--host") {
      const value = queue.shift();
      if (!value) {
        throw new Error("Missing value for --host");
      }
      options.host = value;
      continue;
    }
    if (arg === "--port") {
      const value = queue.shift();
      if (!value) {
        throw new Error("Missing value for --port");
      }
      options.port = parsePort(value);
      continue;
    }
    if (arg === "--private-key-path") {
      const value = queue.shift();
      if (!value) {
        throw new Error("Missing value for --private-key-path");
      }
      options.privateKeyPath = resolve(value);
      continue;
    }
    if (arg === "--auth-token") {
      const value = queue.shift();
      if (!value) {
        throw new Error("Missing value for --auth-token");
      }
      options.authToken = value;
      continue;
    }
    if (arg === "--write-public-key-path") {
      const value = queue.shift();
      if (!value) {
        throw new Error("Missing value for --write-public-key-path");
      }
      options.writePublicKeyPath = resolve(value);
      continue;
    }
    throw new Error(`Unknown argument: ${arg}`);
  }

  return options;
}

export async function createApprovalBrokerServer(
  options: ApprovalBrokerOptions = {}
): Promise<{
  server: Server;
  publicKeyPem: string;
}> {
  const privateKeyPem =
    options.privateKeyPem ??
    (options.privateKeyPath ? await readFile(options.privateKeyPath, "utf8") : undefined);

  if (!privateKeyPem) {
    throw new Error("Approval broker requires a private key.");
  }

  const privateKey = createPrivateKey(privateKeyPem);
  const publicKeyPem = createPublicKey(privateKey).export({ format: "pem", type: "spki" }).toString();

  const server = createServer(async (request, response) => {
    try {
      if (request.method === "GET" && request.url === "/health") {
        writeJson(response, 200, {
          status: "ok",
          publicKeyPem,
          authTokenRequired: Boolean(options.authToken),
          mode: "external_service"
        } satisfies ApprovalBrokerHealth);
        return;
      }

      if (request.method !== "POST" || request.url !== "/v6/approval/sign") {
        writeJson(response, 404, { error: "not_found" });
        return;
      }

      if (options.authToken && bearerToken(request) !== options.authToken) {
        writeJson(response, 401, { error: "unauthorized" });
        return;
      }

      const payload = await readJson<ApprovalBrokerSignRequest>(request);
      if (!payload.sessionId || !payload.workflowHash || !payload.capabilityId || !payload.capabilityDigest) {
        writeJson(response, 400, { error: "invalid_payload" });
        return;
      }

      writeJson(response, 200, createApprovalSignature(privateKey, payload));
    } catch (error) {
      logError(error);
      writeJson(response, 500, {
        error: "broker_error"
      });
    }
  });

  if (options.privateKeyPath && options.authToken && options.authToken.trim().length < 12) {
    throw new Error("Approval broker auth token must be at least 12 characters.");
  }

  return {
    server,
    publicKeyPem
  };
}

export async function startApprovalBroker(
  options: ApprovalBrokerOptions = {}
): Promise<{
  server: Server;
  publicKeyPem: string;
  host: string;
  port: number;
}> {
  const host = options.host ?? "127.0.0.1";
  const port = options.port ?? 8788;
  const { server, publicKeyPem } = await createApprovalBrokerServer(options);

  await new Promise<void>((resolvePromise, rejectPromise) => {
    server.once("error", rejectPromise);
    server.listen(port, host, () => resolvePromise());
  });

  return {
    server,
    publicKeyPem,
    host,
    port:
      typeof server.address() === "object" && server.address()
        ? (server.address() as AddressInfo).port
        : port
  };
}

export async function ensureApprovalBrokerKeypair(
  outputDir: string,
  options: {
    privateKeyDir?: string;
  } = {}
): Promise<{
  privateKeyPath: string;
  publicKeyPath: string;
  publicKeyPem: string;
  privateKeyDir: string;
}> {
  const { publicKey, privateKey } = generateKeyPairSync("ed25519");
  const publicOutputDir = resolve(outputDir);
  const privateKeyDir =
    options.privateKeyDir?.trim()
      ? resolve(options.privateKeyDir)
      : await mkdtemp(join(tmpdir(), "safebrowse-approval-broker-"));
  const privateKeyPath = resolve(privateKeyDir, "approval-broker-private.pem");
  const publicKeyPath = resolve(publicOutputDir, "approval-broker-public.pem");
  const privateKeyPem = privateKey.export({ format: "pem", type: "pkcs8" }).toString();
  const publicKeyPem = publicKey.export({ format: "pem", type: "spki" }).toString();
  await mkdir(publicOutputDir, { recursive: true });
  await mkdir(privateKeyDir, { recursive: true });
  await writeFile(privateKeyPath, privateKeyPem, "utf8");
  await writeFile(publicKeyPath, publicKeyPem, "utf8");
  return {
    privateKeyPath,
    publicKeyPath,
    publicKeyPem,
    privateKeyDir
  };
}

export async function issueApprovalSignature(
  baseUrl: string,
  authToken: string | undefined,
  payload: ApprovalBrokerSignRequest
): Promise<ApprovalBrokerSignResponse> {
  const response = await fetch(`${baseUrl}/v6/approval/sign`, {
    method: "POST",
    headers: {
      "content-type": "application/json",
      ...(authToken ? { authorization: `Bearer ${authToken}` } : {})
    },
    body: JSON.stringify(payload)
  });

  if (!response.ok) {
    throw new Error(`Approval broker returned ${response.status} for /v6/approval/sign`);
  }

  return response.json() as Promise<ApprovalBrokerSignResponse>;
}

export function formatApprovalBrokerHelp(): string {
  return HELP_TEXT;
}

export async function runApprovalBrokerCli(
  argv: string[] = process.argv.slice(2),
  env: NodeJS.ProcessEnv = process.env
): Promise<void> {
  const options = parseApprovalBrokerOptions(argv, env);
  if (options.help) {
    console.log(formatApprovalBrokerHelp());
    return;
  }
  const broker = await startApprovalBroker(options);
  if (options.writePublicKeyPath) {
    await writeFile(options.writePublicKeyPath, broker.publicKeyPem, "utf8");
  }

  console.log(
    JSON.stringify(
      {
        status: "listening",
        address: broker.server.address(),
        mode: "external_service",
        publicKeyPath: options.writePublicKeyPath
      },
      null,
      2
    )
  );

  const shutdown = () => {
    broker.server.close(() => {
      process.exit(0);
    });
  };

  process.once("SIGINT", shutdown);
  process.once("SIGTERM", shutdown);
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  runApprovalBrokerCli().catch((error) => {
    logError(error);
    console.error(formatApprovalBrokerHelp());
    process.exitCode = 1;
  });
}

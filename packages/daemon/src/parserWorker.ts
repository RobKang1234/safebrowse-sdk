import { existsSync } from "node:fs";
import { createRequire } from "node:module";
import os from "node:os";
import process from "node:process";
import { fileURLToPath } from "node:url";

import type { RuntimeContext, SurfaceCapture } from "@safebrowse/core";

const require = createRequire(import.meta.url);

function denyNetwork(message = "Parser worker egress denied"): void {
  const denial = () => {
    throw new Error(message);
  };

  const http = require("node:http");
  const https = require("node:https");
  const net = require("node:net");
  const tls = require("node:tls");
  const dns = require("node:dns");

  http.request = denial;
  http.get = denial;
  https.request = denial;
  https.get = denial;
  net.connect = denial;
  net.createConnection = denial;
  tls.connect = denial;
  dns.lookup = denial;
  dns.resolve = denial;
  dns.resolve4 = denial;
  dns.resolve6 = denial;

  Object.assign(globalThis, {
    fetch: async () => {
      throw new Error(message);
    }
  });
}

function lockDownEnvironment(): void {
  for (const key of Object.keys(process.env)) {
    delete process.env[key];
  }
  denyNetwork();
}

async function probeIsolation(): Promise<{
  mode: "scrubbed_process" | "node_permission_process";
  envKeys: string[];
  egressDenied: boolean;
  processIsolated: boolean;
  permissionModelEnabled: boolean;
  fsReadRestricted: boolean;
  childProcessDenied: boolean;
  workerThreadsDenied: boolean;
}> {
  let egressDenied = false;
  try {
    await globalThis.fetch("https://example.com");
  } catch {
    egressDenied = true;
  }

  const permissionModelEnabled = Boolean(process.permission);
  const fsReadRestricted = permissionModelEnabled
    ? !process.permission!.has("fs.read", os.tmpdir()) &&
      !process.permission!.has("fs.read", os.homedir())
    : false;
  return {
    mode: permissionModelEnabled ? "node_permission_process" : "scrubbed_process",
    envKeys: Object.keys(process.env),
    egressDenied,
    processIsolated: true,
    permissionModelEnabled,
    fsReadRestricted,
    childProcessDenied: permissionModelEnabled ? !process.permission!.has("child") : false,
    workerThreadsDenied: permissionModelEnabled ? !process.permission!.has("worker") : false
  };
}

lockDownEnvironment();

let cachedProbePromise: Promise<Awaited<ReturnType<typeof probeIsolation>>> | undefined;
let cachedCoreRuntimePromise:
  | Promise<{
      compileObservationV6: typeof import("@safebrowse/core").compileObservationV6;
      computeToolManifestHash: typeof import("@safebrowse/core").computeToolManifestHash;
      computeToolSchemaHash: typeof import("@safebrowse/core").computeToolSchemaHash;
    }>
  | undefined;
let workerRuntimeDefaults: Partial<RuntimeContext> | undefined;
let workerAllowlistedEgress: string[] = [];
let workerParserIsolationMode: "scrubbed_process" | "node_permission_process" | undefined;

async function getCachedProbe() {
  if (!cachedProbePromise) {
    cachedProbePromise = probeIsolation();
  }
  return cachedProbePromise;
}

async function loadCoreRuntime(): Promise<{
  compileObservationV6: typeof import("@safebrowse/core").compileObservationV6;
  computeToolManifestHash: typeof import("@safebrowse/core").computeToolManifestHash;
  computeToolSchemaHash: typeof import("@safebrowse/core").computeToolSchemaHash;
}> {
  if (cachedCoreRuntimePromise) {
    return cachedCoreRuntimePromise;
  }

  cachedCoreRuntimePromise = (async () => {
    if (import.meta.url.endsWith(".ts")) {
      const distEntryUrl = new URL("../../core/dist/index.js", import.meta.url);
      if (existsSync(fileURLToPath(distEntryUrl))) {
        return import(distEntryUrl.href);
      }
      const sourceEntryUrl = new URL("../../core/src/index.ts", import.meta.url).href;
      return import(sourceEntryUrl);
    }

    return import("@safebrowse/core");
  })();

  return cachedCoreRuntimePromise;
}

type ParserWorkerMessage =
  | {
      requestId: string;
      payload: {
        kind: "configure";
        parserIsolationMode?: "scrubbed_process" | "node_permission_process";
        allowlistedEgress?: string[];
        runtime?: Partial<RuntimeContext>;
      };
    }
  | {
      requestId: string;
      payload: {
        kind: "probe";
      };
    }
  | {
      requestId: string;
      payload: {
        kind: "parse";
        compilerVersion?: "v6";
        parserIsolationMode?: "scrubbed_process" | "node_permission_process";
        capture: SurfaceCapture;
        workflowHash?: string;
        allowlistedEgress?: string[];
        runtime?: Partial<RuntimeContext>;
      };
    };

function sendResponse(
  requestId: string,
  message:
    | {
        ok: true;
        probe?: Awaited<ReturnType<typeof probeIsolation>>;
        result?: {
          compiledObservation: ReturnType<typeof import("@safebrowse/core").compileObservationV6>["compiledObservation"];
          plannerView?: ReturnType<typeof import("@safebrowse/core").compileObservationV6>["plannerView"];
          toolManifestDigests?: {
            manifestHash?: string;
            schemaHash?: string;
          };
        };
      }
    | {
        ok: false;
        error: string;
      }
): void {
  process.send?.({
    requestId,
    ...message
  });
}

process.on("message", async (message: ParserWorkerMessage) => {
  try {
    const payload = message.payload;
    if (payload.kind === "configure") {
      workerRuntimeDefaults = payload.runtime;
      workerAllowlistedEgress = payload.allowlistedEgress ?? [];
      workerParserIsolationMode = payload.parserIsolationMode;
      await loadCoreRuntime();
      sendResponse(message.requestId, {
        ok: true
      });
      return;
    }

    if (payload.kind === "probe") {
      sendResponse(message.requestId, {
        ok: true,
        probe: await getCachedProbe()
      });
      return;
    }

    const parserIsolationMode =
      payload.parserIsolationMode ??
      workerParserIsolationMode ??
      (await getCachedProbe()).mode;
    void parserIsolationMode;

    const { compileObservationV6, computeToolManifestHash, computeToolSchemaHash } =
      await loadCoreRuntime();
    const probe = await getCachedProbe();
    const runtime = payload.runtime ?? workerRuntimeDefaults ?? {};
    const allowlistedEgress = payload.allowlistedEgress ?? workerAllowlistedEgress;
    const result = compileObservationV6(payload.capture, runtime, {
      workflowHash: payload.workflowHash,
      parserIsolation: {
        mode: probe.mode,
        processIsolated: probe.processIsolated,
        envScrubbed: probe.envKeys.length === 0,
        egressDenied: probe.egressDenied,
        permissionModelEnabled: probe.permissionModelEnabled,
        fsReadRestricted: probe.fsReadRestricted,
        childProcessDenied: probe.childProcessDenied,
        workerThreadsDenied: probe.workerThreadsDenied,
        envKeys: probe.envKeys,
        allowlistedEgress
      }
    });
    const toolManifestDigests =
      payload.capture.surfaceType === "tool_manifest"
        ? {
            manifestHash: computeToolManifestHash({
              toolId: payload.capture.toolId,
              description: payload.capture.description,
              authType: payload.capture.authType,
              requestedScopes: payload.capture.requestedScopes,
              callbackUri: payload.capture.callbackUri
            }),
            schemaHash: computeToolSchemaHash(payload.capture.schemaDescriptions)
          }
        : undefined;

    sendResponse(message.requestId, {
      ok: true,
      result: {
        ...result,
        toolManifestDigests
      }
    });
  } catch (error) {
    sendResponse(message.requestId, {
      ok: false,
      error: error instanceof Error ? error.message : String(error)
    });
  }
});

import { createRequire } from "node:module";
import process from "node:process";

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
  envKeys: string[];
  egressDenied: boolean;
  processIsolated: boolean;
}> {
  let egressDenied = false;
  try {
    await globalThis.fetch("https://example.com");
  } catch {
    egressDenied = true;
  }

  return {
    envKeys: Object.keys(process.env),
    egressDenied,
    processIsolated: true
  };
}

lockDownEnvironment();

async function loadCoreRuntime(): Promise<{
  compileObservation: typeof import("@safebrowse/core").compileObservation;
}> {
  if (import.meta.url.endsWith(".ts")) {
    const sourceEntryUrl = new URL("../../core/src/index.ts", import.meta.url).href;
    return import(sourceEntryUrl);
  }

  return import("@safebrowse/core");
}

type ParserWorkerMessage =
  | {
      kind: "probe";
    }
  | {
      kind: "parse";
      capture: SurfaceCapture;
      workflowHash?: string;
      allowlistedEgress?: string[];
      runtime?: Partial<RuntimeContext>;
    };

process.on("message", async (message: ParserWorkerMessage) => {
  try {
    const { compileObservation } = await loadCoreRuntime();

    if (message.kind === "probe") {
      process.send?.({
        ok: true,
        probe: await probeIsolation()
      });
      return;
    }

    const result = compileObservation(message.capture, message.runtime ?? {}, {
      workflowHash: message.workflowHash,
      parserIsolation: {
        processIsolated: true,
        secretAccess: false,
        arbitraryEgress: false,
        allowlistedEgress: message.allowlistedEgress ?? []
      }
    });

    process.send?.({
      ok: true,
      result
    });
  } catch (error) {
    process.send?.({
      ok: false,
      error: error instanceof Error ? error.message : String(error)
    });
  }
});

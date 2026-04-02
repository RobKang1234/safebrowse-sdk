import { existsSync } from "node:fs";
import { createRequire } from "node:module";
import os from "node:os";
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
    ? !process.permission!.has("fs.read", os.tmpdir()) && !process.permission!.has("fs.read", os.homedir())
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

async function loadCoreRuntime(
  parserIsolationMode?: "scrubbed_process" | "node_permission_process"
): Promise<{
  compileObservation: typeof import("@safebrowse/core").compileObservation;
  compileObservationV5: typeof import("@safebrowse/core").compileObservationV5;
}> {
  if (import.meta.url.endsWith(".ts")) {
    if (parserIsolationMode === "node_permission_process") {
      const distEntryUrl = new URL("../../core/dist/index.js", import.meta.url);
      if (existsSync(distEntryUrl)) {
        return import(distEntryUrl.href);
      }
      throw new Error("secure_v5 parser worker requires a built @safebrowse/core dist runtime");
    }
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
      compilerVersion?: "v4" | "v5";
      parserIsolationMode?: "scrubbed_process" | "node_permission_process";
      capture: SurfaceCapture;
      workflowHash?: string;
      allowlistedEgress?: string[];
      runtime?: Partial<RuntimeContext>;
    };

process.on("message", async (message: ParserWorkerMessage) => {
  try {
    if (message.kind === "probe") {
      process.send?.({
        ok: true,
        probe: await probeIsolation()
      });
      return;
    }

    const { compileObservation, compileObservationV5 } = await loadCoreRuntime(message.parserIsolationMode);
    const compiler = message.compilerVersion === "v5" ? compileObservationV5 : compileObservation;
    const probe = await probeIsolation();
    const result = compiler(message.capture, message.runtime ?? {}, {
      workflowHash: message.workflowHash,
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

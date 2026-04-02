import { existsSync } from "node:fs";
import { fork } from "node:child_process";
import { fileURLToPath } from "node:url";
import { resolve, dirname } from "node:path";

import type {
  CompiledObservation,
  ParserIsolationMode,
  ParserWorkerProbe,
  RuntimeContext,
  StructuredPlannerInput,
  SurfaceCapture
} from "@safebrowse/core";

const moduleDir = dirname(fileURLToPath(import.meta.url));
const compiledWorkerPath = resolve(moduleDir, "parserWorker.js");
const sourceWorkerPath = resolve(moduleDir, "parserWorker.ts");
const workerPath = existsSync(compiledWorkerPath) ? compiledWorkerPath : sourceWorkerPath;

type WorkerPayload =
  | {
      kind: "probe";
    }
  | {
      kind: "parse";
      compilerVersion?: "v4" | "v5";
      parserIsolationMode?: ParserIsolationMode;
      capture: SurfaceCapture;
      workflowHash?: string;
      allowlistedEgress?: string[];
      runtime?: Partial<RuntimeContext>;
    };

type WorkerResponse =
  | {
      ok: true;
      probe?: ParserWorkerProbe;
      result?: {
        compiledObservation: CompiledObservation;
        plannerInput: StructuredPlannerInput;
      };
    }
  | {
      ok: false;
      error: string;
    };

function parserReadRoots(): string[] {
  return [...new Set([resolve(process.cwd()), resolve(dirname(workerPath), "..", "..")])];
}

function buildExecArgv(mode: ParserIsolationMode): string[] {
  const baseArgs = workerPath.endsWith(".ts")
    ? mode === "node_permission_process"
      ? ["--experimental-strip-types"]
      : ["--import", "tsx"]
    : [];
  if (mode !== "node_permission_process") {
    return baseArgs;
  }

  return [
    "--permission",
    ...parserReadRoots().map((root) => `--allow-fs-read=${root}`),
    ...baseArgs
  ];
}

function runWorker<T>(payload: WorkerPayload, mode: ParserIsolationMode): Promise<T> {
  return new Promise<T>((resolvePromise, rejectPromise) => {
    const child = fork(workerPath, [], {
      env:
        workerPath.endsWith(".ts") && mode !== "node_permission_process"
          ? { TSX_DISABLE_CACHE: "1" }
          : {},
      stdio: ["ignore", "ignore", "ignore", "ipc"],
      execArgv: buildExecArgv(mode)
    });

    const finish = (error?: Error, value?: T) => {
      child.removeAllListeners();
      child.kill();
      if (error) {
        rejectPromise(error);
        return;
      }
      resolvePromise(value as T);
    };

    child.once("error", (error) => finish(error));
    child.once("message", (message: WorkerResponse) => {
      if (!message.ok) {
        finish(new Error(message.error));
        return;
      }

      finish(undefined, (message.probe ?? message.result) as T);
    });
    child.once("exit", (code) => {
      if (code && code !== 0) {
        finish(new Error(`parser worker exited with code ${code}`));
      }
    });

    child.send(payload);
  });
}

export function compileObservationInIsolation(input: {
  capture: SurfaceCapture;
  workflowHash?: string;
  allowlistedEgress?: string[];
  runtime?: Partial<RuntimeContext>;
  compilerVersion?: "v4" | "v5";
  parserIsolationMode?: ParserIsolationMode;
}): Promise<{
  compiledObservation: CompiledObservation;
  plannerInput?: StructuredPlannerInput;
  plannerView?: unknown;
}> {
  const mode = input.parserIsolationMode ?? "scrubbed_process";
  return runWorker(
    {
      kind: "parse",
      compilerVersion: input.compilerVersion,
      parserIsolationMode: mode,
      capture: input.capture,
      workflowHash: input.workflowHash,
      allowlistedEgress: input.allowlistedEgress,
      runtime: input.runtime
    },
    mode
  );
}

export function probeParserIsolation(
  parserIsolationMode: ParserIsolationMode = "scrubbed_process"
): Promise<ParserWorkerProbe> {
  return runWorker(
    {
      kind: "probe"
    },
    parserIsolationMode
  );
}

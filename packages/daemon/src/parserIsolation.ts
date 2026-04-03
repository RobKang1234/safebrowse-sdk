import { randomUUID } from "node:crypto";
import { existsSync } from "node:fs";
import { fork, type ChildProcess } from "node:child_process";
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
      kind: "configure";
      parserIsolationMode?: ParserIsolationMode;
      allowlistedEgress?: string[];
      runtime?: Partial<RuntimeContext>;
    }
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

type WorkerRequestEnvelope = {
  requestId: string;
  payload: WorkerPayload;
};

type ToolManifestDigests = {
  manifestHash?: string;
  schemaHash?: string;
};

type WorkerResponseEnvelope =
  | {
      requestId: string;
      ok: true;
      probe?: ParserWorkerProbe;
      result?: {
        compiledObservation: CompiledObservation;
        plannerInput?: StructuredPlannerInput;
        plannerView?: unknown;
        toolManifestDigests?: ToolManifestDigests;
      };
    }
  | {
      requestId: string;
      ok: false;
      error: string;
    };

export interface ParserIsolationProbeSnapshot {
  probe: ParserWorkerProbe;
  lastCheckedAt: string;
}

export interface ParserIsolationService {
  compileObservation(input: {
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
    toolManifestDigests?: ToolManifestDigests;
  }>;
  getCachedProbe(): Promise<ParserIsolationProbeSnapshot>;
  refreshProbe(): Promise<ParserIsolationProbeSnapshot>;
  close(): Promise<void>;
}

interface ParserIsolationServiceOptions {
  allowlistedEgress?: string[];
  runtime?: Partial<RuntimeContext>;
}

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

type PendingRequest<T> = {
  resolve: (value: T) => void;
  reject: (error: Error) => void;
};

class ParserIsolationServiceImpl implements ParserIsolationService {
  private child?: ChildProcess;

  private closed = false;

  private cachedProbe?: ParserIsolationProbeSnapshot;

  private startup?: Promise<void>;

  private readonly pending = new Map<string, PendingRequest<unknown>>();

  constructor(
    private readonly mode: ParserIsolationMode,
    private readonly options: ParserIsolationServiceOptions = {}
  ) {}

  async compileObservation(input: {
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
    toolManifestDigests?: ToolManifestDigests;
  }> {
    const result = await this.sendRequest<{
      compiledObservation: CompiledObservation;
      plannerInput?: StructuredPlannerInput;
      plannerView?: unknown;
      toolManifestDigests?: ToolManifestDigests;
    }>({
      kind: "parse",
      compilerVersion: input.compilerVersion,
      parserIsolationMode: input.parserIsolationMode ?? this.mode,
      capture: input.capture,
      workflowHash: input.workflowHash,
      allowlistedEgress:
        input.allowlistedEgress ?? this.options.allowlistedEgress,
      runtime: input.runtime ?? this.options.runtime
    });

    return result;
  }

  async getCachedProbe(): Promise<ParserIsolationProbeSnapshot> {
    if (this.cachedProbe) {
      return this.cachedProbe;
    }

    return this.refreshProbe();
  }

  async refreshProbe(): Promise<ParserIsolationProbeSnapshot> {
    const probe = await this.sendRequest<ParserWorkerProbe>({
      kind: "probe"
    });

    this.cachedProbe = {
      probe,
      lastCheckedAt: new Date().toISOString()
    };
    return this.cachedProbe;
  }

  async close(): Promise<void> {
    this.closed = true;
    this.cachedProbe = undefined;
    const pendingError = new Error("parser isolation service closed");
    for (const [requestId, pending] of this.pending.entries()) {
      this.pending.delete(requestId);
      pending.reject(pendingError);
    }
    this.startup = undefined;

    const child = this.child;
    this.child = undefined;
    if (!child) {
      return;
    }

    await new Promise<void>((resolvePromise) => {
      child.once("close", () => resolvePromise());
      child.kill();
    });
  }

  private async ensureWorker(): Promise<void> {
    if (this.closed) {
      throw new Error("parser isolation service closed");
    }

    if (this.child?.connected) {
      return;
    }

    if (this.startup) {
      return this.startup;
    }

    this.startup = (async () => {
      const child = fork(workerPath, [], {
        env:
          workerPath.endsWith(".ts") && this.mode !== "node_permission_process"
            ? { TSX_DISABLE_CACHE: "1" }
            : {},
        stdio: ["ignore", "ignore", "ignore", "ipc"],
        execArgv: buildExecArgv(this.mode)
      });
      child.unref();

      child.on("message", (message: unknown) => this.handleMessage(message));
      child.on("error", (error) => this.handleWorkerFailure(error));
      child.on("exit", (code, signal) => {
        const suffix = signal ? ` (${signal})` : "";
        this.handleWorkerFailure(
          code && code !== 0 ? new Error(`parser worker exited with code ${code}${suffix}`) : undefined
        );
      });

      this.child = child;

      if (this.options.allowlistedEgress || this.options.runtime) {
        await this.sendRequest<void>({
          kind: "configure",
          parserIsolationMode: this.mode,
          allowlistedEgress: this.options.allowlistedEgress,
          runtime: this.options.runtime
        });
      }
    })().finally(() => {
      this.startup = undefined;
    });

    return this.startup;
  }

  private handleMessage(message: unknown): void {
    if (!message || typeof message !== "object" || !("requestId" in message)) {
      return;
    }

    const response = message as WorkerResponseEnvelope;
    const pending = this.pending.get(response.requestId);
    if (!pending) {
      return;
    }

    this.pending.delete(response.requestId);
    if (!response.ok) {
      pending.reject(new Error(response.error));
      return;
    }

    pending.resolve((response.probe ?? response.result) as unknown);
  }

  private handleWorkerFailure(error?: Error): void {
    this.cachedProbe = undefined;
    const child = this.child;
    this.child = undefined;
    if (child) {
      child.removeAllListeners();
    }

    if (this.closed && this.pending.size === 0) {
      return;
    }

    const failure = error ?? new Error("parser worker exited unexpectedly");
    for (const [requestId, pending] of this.pending.entries()) {
      this.pending.delete(requestId);
      pending.reject(failure);
    }
  }

  private async sendRequest<T>(payload: WorkerPayload): Promise<T> {
    await this.ensureWorker();

    const child = this.child;
    if (!child?.connected) {
      throw new Error("parser worker is not connected");
    }

    return new Promise<T>((resolvePromise, rejectPromise) => {
      const requestId = randomUUID();
      this.pending.set(requestId, {
        resolve: (value) => resolvePromise(value as T),
        reject: rejectPromise
      });

      try {
        child.send({
          requestId,
          payload
        } satisfies WorkerRequestEnvelope);
      } catch (error) {
        this.pending.delete(requestId);
        rejectPromise(error instanceof Error ? error : new Error(String(error)));
      }
    });
  }
}

const defaultServices = new Map<ParserIsolationMode, ParserIsolationService>();

function defaultServiceForMode(mode: ParserIsolationMode): ParserIsolationService {
  let service = defaultServices.get(mode);
  if (!service) {
    service = createParserIsolationService(mode);
    defaultServices.set(mode, service);
  }
  return service;
}

export function createParserIsolationService(
  parserIsolationMode: ParserIsolationMode = "scrubbed_process",
  options: ParserIsolationServiceOptions = {}
): ParserIsolationService {
  return new ParserIsolationServiceImpl(parserIsolationMode, options);
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
  toolManifestDigests?: ToolManifestDigests;
}> {
  const mode = input.parserIsolationMode ?? "scrubbed_process";
  return defaultServiceForMode(mode).compileObservation({
    ...input,
    parserIsolationMode: mode
  });
}

export function probeParserIsolation(
  parserIsolationMode: ParserIsolationMode = "scrubbed_process"
): Promise<ParserWorkerProbe> {
  return defaultServiceForMode(parserIsolationMode)
    .refreshProbe()
    .then((snapshot) => snapshot.probe);
}

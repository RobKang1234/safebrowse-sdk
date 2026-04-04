import type {
  ModelGuardHealthResponse,
  ModelGuardObservationRequest,
  ModelGuardObservationResponse
} from "@safebrowse/core";

export interface ModelGuardClientOptions {
  baseUrl?: string;
  timeoutMs?: number;
  enforcementMode?: "off" | "tighten";
}

export interface ModelGuardHealthSnapshot {
  configured: boolean;
  ready: boolean;
  runtimeMode: "python_sidecar";
  enforcementMode: "off" | "tighten";
  bundleVersion?: string;
  featureSchemaVersion?: string;
  lastCheckedAt?: string;
}

export interface ModelGuardClient {
  configured: boolean;
  enforcementMode: "off" | "tighten";
  scoreObservation(request: ModelGuardObservationRequest): Promise<ModelGuardObservationResponse>;
  getCachedHealth(): Promise<ModelGuardHealthSnapshot>;
  refreshHealth(): Promise<ModelGuardHealthSnapshot>;
  close(): Promise<void>;
}

function normalizeBaseUrl(value: string | undefined): string | undefined {
  const trimmed = value?.trim();
  if (!trimmed) {
    return undefined;
  }
  return trimmed.replace(/\/+$/, "");
}

function defaultHealthSnapshot(
  configured: boolean,
  enforcementMode: "off" | "tighten"
): ModelGuardHealthSnapshot {
  return {
    configured,
    ready: false,
    runtimeMode: "python_sidecar",
    enforcementMode
  };
}

class DisabledModelGuardClient implements ModelGuardClient {
  readonly configured = false;

  constructor(readonly enforcementMode: "off" | "tighten" = "off") {}

  async scoreObservation(): Promise<ModelGuardObservationResponse> {
    throw new Error("model guard is not configured");
  }

  async getCachedHealth(): Promise<ModelGuardHealthSnapshot> {
    return defaultHealthSnapshot(false, this.enforcementMode);
  }

  async refreshHealth(): Promise<ModelGuardHealthSnapshot> {
    return defaultHealthSnapshot(false, this.enforcementMode);
  }

  async close(): Promise<void> {
    return;
  }
}

class HttpModelGuardClient implements ModelGuardClient {
  readonly configured = true;

  private cachedHealth: ModelGuardHealthSnapshot;

  constructor(
    private readonly baseUrl: string,
    private readonly timeoutMs: number,
    readonly enforcementMode: "off" | "tighten"
  ) {
    this.cachedHealth = defaultHealthSnapshot(true, enforcementMode);
  }

  async scoreObservation(request: ModelGuardObservationRequest): Promise<ModelGuardObservationResponse> {
    const response = await fetch(`${this.baseUrl}/v1/score/observation`, {
      method: "POST",
      headers: {
        "content-type": "application/json"
      },
      body: JSON.stringify(request),
      signal: AbortSignal.timeout(this.timeoutMs)
    });
    if (!response.ok) {
      throw new Error(`model guard returned ${response.status}`);
    }
    return (await response.json()) as ModelGuardObservationResponse;
  }

  async getCachedHealth(): Promise<ModelGuardHealthSnapshot> {
    return this.cachedHealth;
  }

  async refreshHealth(): Promise<ModelGuardHealthSnapshot> {
    try {
      const response = await fetch(`${this.baseUrl}/health`, {
        method: "GET",
        signal: AbortSignal.timeout(this.timeoutMs)
      });
      if (!response.ok) {
        throw new Error(`model guard returned ${response.status}`);
      }
      const payload = (await response.json()) as ModelGuardHealthResponse;
      this.cachedHealth = {
        configured: true,
        ready: payload.ready,
        runtimeMode: payload.runtimeMode,
        enforcementMode: this.enforcementMode,
        bundleVersion: payload.bundleVersion,
        featureSchemaVersion: payload.featureSchemaVersion,
        lastCheckedAt: new Date().toISOString()
      };
    } catch {
      this.cachedHealth = {
        ...defaultHealthSnapshot(true, this.enforcementMode),
        lastCheckedAt: new Date().toISOString()
      };
    }
    return this.cachedHealth;
  }

  async close(): Promise<void> {
    return;
  }
}

export function createModelGuardClient(options: ModelGuardClientOptions = {}): ModelGuardClient {
  const baseUrl = normalizeBaseUrl(options.baseUrl);
  const enforcementMode = options.enforcementMode ?? "off";
  const timeoutMs = options.timeoutMs ?? 2_500;
  if (!baseUrl) {
    return new DisabledModelGuardClient(enforcementMode);
  }
  return new HttpModelGuardClient(baseUrl, timeoutMs, enforcementMode);
}

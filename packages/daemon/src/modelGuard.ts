import type {
  ModelGuardDecisionLabel,
  ModelGuardEnforcementMode,
  ModelGuardEvidenceChunk,
  ModelGuardHealthResponse,
  ModelGuardObservationRequest,
  ModelGuardObservationResponse
} from "@safebrowse/core";

const SUPPORTED_FEATURE_SCHEMA_VERSIONS = new Set(["recipe_v1", "v1"]);
const DECISION_LABELS = new Set<ModelGuardDecisionLabel>([
  "allow_read_only",
  "require_shadow_replay",
  "require_user_approval",
  "deny"
]);
const ENFORCEMENT_MODES = new Set<ModelGuardEnforcementMode>(["off", "shadow", "tighten"]);
const MAX_REASON_CODES = 32;
const MAX_EVIDENCE_CHUNKS = 12;
const MAX_EVIDENCE_EXCERPT_CHARS = 1_000;

export interface ModelGuardClientOptions {
  baseUrl?: string;
  timeoutMs?: number;
  enforcementMode?: ModelGuardEnforcementMode;
}

export interface ModelGuardHealthSnapshot {
  configured: boolean;
  ready: boolean;
  runtimeMode: "python_sidecar";
  enforcementMode: ModelGuardEnforcementMode;
  bundleVersion?: string;
  featureSchemaVersion?: string;
  bundleDigest?: string;
  componentDigests?: Record<string, string>;
  lastCheckedAt?: string;
  validationError?: string;
}

export interface ModelGuardClient {
  configured: boolean;
  enforcementMode: ModelGuardEnforcementMode;
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
  let end = trimmed.length;
  while (end > 0 && trimmed.charCodeAt(end - 1) === 47) {
    end -= 1;
  }
  return trimmed.slice(0, end);
}

function defaultHealthSnapshot(
  configured: boolean,
  enforcementMode: ModelGuardEnforcementMode,
  validationError?: string
): ModelGuardHealthSnapshot {
  return {
    configured,
    ready: false,
    runtimeMode: "python_sidecar",
    enforcementMode,
    ...(validationError ? { validationError } : {})
  };
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function isFiniteProbability(value: unknown): value is number {
  return typeof value === "number" && Number.isFinite(value) && value >= 0 && value <= 1;
}

function isFiniteNumber(value: unknown): value is number {
  return typeof value === "number" && Number.isFinite(value);
}

function requiredString(value: unknown, field: string): string {
  if (typeof value !== "string" || value.trim().length === 0) {
    throw new Error(`invalid model guard ${field}`);
  }
  return value;
}

function optionalString(value: unknown, field: string): string | undefined {
  if (value === undefined) {
    return undefined;
  }
  return requiredString(value, field);
}

function validateFeatureSchemaVersion(value: unknown): string {
  const version = requiredString(value, "feature schema version");
  if (!SUPPORTED_FEATURE_SCHEMA_VERSIONS.has(version)) {
    throw new Error(`unsupported model guard feature schema version: ${version}`);
  }
  return version;
}

function validateComponentDigests(value: unknown): Record<string, string> | undefined {
  if (value === undefined) {
    return undefined;
  }
  if (!isRecord(value)) {
    throw new Error("invalid model guard component digests");
  }
  const digests: Record<string, string> = {};
  for (const [key, digest] of Object.entries(value)) {
    if (!/^[A-Za-z0-9_.:-]{1,80}$/.test(key)) {
      throw new Error("invalid model guard component digest key");
    }
    if (typeof digest !== "string" || !/^[A-Fa-f0-9]{32,128}$/.test(digest)) {
      throw new Error("invalid model guard component digest value");
    }
    digests[key] = digest;
  }
  return digests;
}

function validateReasonCodes(value: unknown): string[] {
  if (!Array.isArray(value) || value.length > MAX_REASON_CODES) {
    throw new Error("invalid model guard reason codes");
  }
  return value.map((entry) => {
    if (typeof entry !== "string" || !/^[A-Z0-9_:-]{1,128}$/.test(entry)) {
      throw new Error("invalid model guard reason code");
    }
    return entry;
  });
}

function validateEvidenceChunkIds(value: unknown): string[] {
  if (!Array.isArray(value) || value.length > MAX_EVIDENCE_CHUNKS) {
    throw new Error("invalid model guard evidence chunk ids");
  }
  return value.map((entry) => {
    if (typeof entry !== "string" || entry.trim().length === 0 || entry.length > 128) {
      throw new Error("invalid model guard evidence chunk id");
    }
    return entry;
  });
}

function validateEvidenceChunks(value: unknown): ModelGuardEvidenceChunk[] | undefined {
  if (value === undefined) {
    return undefined;
  }
  if (!Array.isArray(value) || value.length > MAX_EVIDENCE_CHUNKS) {
    throw new Error("invalid model guard evidence chunks");
  }
  return value.map((entry) => {
    if (!isRecord(entry)) {
      throw new Error("invalid model guard evidence chunk");
    }
    const chunkId = requiredString(entry.chunkId, "evidence chunk id");
    const excerpt = requiredString(entry.excerpt, "evidence chunk excerpt").slice(
      0,
      MAX_EVIDENCE_EXCERPT_CHARS
    );
    if (entry.score !== undefined && !isFiniteNumber(entry.score)) {
      throw new Error("invalid model guard evidence chunk score");
    }
    return {
      chunkId,
      ...(typeof entry.score === "number" ? { score: entry.score } : {}),
      excerpt
    };
  });
}

function validateHealthPayload(payload: unknown): ModelGuardHealthResponse {
  if (!isRecord(payload)) {
    throw new Error("invalid model guard health payload");
  }
  if (payload.status !== "ok" && payload.status !== "error") {
    throw new Error("invalid model guard health status");
  }
  if (typeof payload.ready !== "boolean") {
    throw new Error("invalid model guard health ready flag");
  }
  if (payload.runtimeMode !== "python_sidecar") {
    throw new Error("invalid model guard runtime mode");
  }
  if (!ENFORCEMENT_MODES.has(payload.enforcementMode as ModelGuardEnforcementMode)) {
    throw new Error("invalid model guard health enforcement mode");
  }

  const ready = payload.status === "ok" && payload.ready;
  const bundleVersion = optionalString(payload.bundleVersion, "bundle version");
  const featureSchemaVersion = ready
    ? validateFeatureSchemaVersion(payload.featureSchemaVersion)
    : optionalString(payload.featureSchemaVersion, "feature schema version");
  const bundleDigest = optionalString(payload.bundleDigest, "bundle digest");
  const componentDigests = validateComponentDigests(payload.componentDigests);

  return {
    status: payload.status,
    ready,
    runtimeMode: "python_sidecar",
    enforcementMode: payload.enforcementMode as ModelGuardEnforcementMode,
    ...(bundleVersion ? { bundleVersion } : {}),
    ...(featureSchemaVersion ? { featureSchemaVersion } : {}),
    ...(bundleDigest ? { bundleDigest } : {}),
    ...(componentDigests ? { componentDigests } : {})
  };
}

function validateObservationResponsePayload(
  payload: unknown,
  health: ModelGuardHealthSnapshot,
  enforcementMode: ModelGuardEnforcementMode
): ModelGuardObservationResponse {
  if (!isRecord(payload) || !isRecord(payload.assessment)) {
    throw new Error("invalid model guard observation response");
  }
  const assessment = payload.assessment;
  const decisionLabel = assessment.decisionLabel;
  const calibratedDecisionLabel = assessment.calibratedDecisionLabel;
  if (!DECISION_LABELS.has(decisionLabel as ModelGuardDecisionLabel)) {
    throw new Error("invalid model guard decision label");
  }
  if (!DECISION_LABELS.has(calibratedDecisionLabel as ModelGuardDecisionLabel)) {
    throw new Error("invalid model guard calibrated decision label");
  }
  if (!isFiniteProbability(assessment.binaryThreatProbability)) {
    throw new Error("invalid model guard probability");
  }
  if (!isRecord(assessment.pipeline)) {
    throw new Error("invalid model guard pipeline metadata");
  }
  const pipeline = assessment.pipeline;
  if (pipeline.runtimeMode !== "python_sidecar") {
    throw new Error("invalid model guard assessment runtime mode");
  }
  if (typeof pipeline.scoredAt !== "string" || pipeline.scoredAt.trim().length === 0) {
    throw new Error("invalid model guard scored timestamp");
  }

  const bundleVersion = requiredString(assessment.bundleVersion, "bundle version");
  const featureSchemaVersion = validateFeatureSchemaVersion(assessment.featureSchemaVersion);
  if (health.bundleVersion && health.bundleVersion !== bundleVersion) {
    throw new Error("model guard bundle version changed after health check");
  }
  if (health.featureSchemaVersion && health.featureSchemaVersion !== featureSchemaVersion) {
    throw new Error("model guard feature schema version changed after health check");
  }

  const bundleDigest = optionalString(assessment.bundleDigest, "bundle digest") ?? health.bundleDigest;
  const componentDigests =
    validateComponentDigests(assessment.componentDigests) ?? health.componentDigests;
  const evidenceChunks = validateEvidenceChunks(payload.evidenceChunks);

  return {
    assessment: {
      assessmentId: requiredString(assessment.assessmentId, "assessment id"),
      bundleVersion,
      featureSchemaVersion,
      ...(bundleDigest ? { bundleDigest } : {}),
      ...(componentDigests ? { componentDigests } : {}),
      binaryThreatProbability: assessment.binaryThreatProbability,
      decisionLabel: decisionLabel as ModelGuardDecisionLabel,
      calibratedDecisionLabel: calibratedDecisionLabel as ModelGuardDecisionLabel,
      coarseReasonCodes: validateReasonCodes(assessment.coarseReasonCodes),
      evidenceChunkIds: validateEvidenceChunkIds(assessment.evidenceChunkIds),
      pipeline: {
        runtimeMode: "python_sidecar",
        enforcementMode,
        scoredAt: pipeline.scoredAt,
        ...(typeof pipeline.latencyMs === "number" && Number.isFinite(pipeline.latencyMs)
          ? { latencyMs: pipeline.latencyMs }
          : {}),
        ...(typeof pipeline.sentinelVersion === "string"
          ? { sentinelVersion: pipeline.sentinelVersion }
          : {}),
        ...(typeof pipeline.expertVersion === "string"
          ? { expertVersion: pipeline.expertVersion }
          : {}),
        ...(typeof pipeline.stackerVersion === "string"
          ? { stackerVersion: pipeline.stackerVersion }
          : {})
      }
    },
    ...(evidenceChunks ? { evidenceChunks } : {})
  };
}

class DisabledModelGuardClient implements ModelGuardClient {
  readonly configured = false;

  constructor(readonly enforcementMode: ModelGuardEnforcementMode = "off") {}

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
    readonly enforcementMode: ModelGuardEnforcementMode
  ) {
    this.cachedHealth = defaultHealthSnapshot(true, enforcementMode);
  }

  async scoreObservation(request: ModelGuardObservationRequest): Promise<ModelGuardObservationResponse> {
    if (this.enforcementMode === "off") {
      throw new Error("model guard scoring is disabled");
    }
    if (!this.cachedHealth.ready) {
      throw new Error("model guard is not ready");
    }
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
    return validateObservationResponsePayload(
      await response.json(),
      this.cachedHealth,
      this.enforcementMode
    );
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
      const payload = validateHealthPayload(await response.json());
      this.cachedHealth = {
        configured: true,
        ready: payload.ready,
        runtimeMode: payload.runtimeMode,
        enforcementMode: this.enforcementMode,
        bundleVersion: payload.bundleVersion,
        featureSchemaVersion: payload.featureSchemaVersion,
        bundleDigest: payload.bundleDigest,
        componentDigests: payload.componentDigests,
        lastCheckedAt: new Date().toISOString()
      };
    } catch (error) {
      this.cachedHealth = {
        ...defaultHealthSnapshot(
          true,
          this.enforcementMode,
          error instanceof Error ? error.message : "model guard health check failed"
        ),
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

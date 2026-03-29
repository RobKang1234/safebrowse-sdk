export type JsonPrimitive = string | number | boolean | null;
export type JsonValue = JsonPrimitive | JsonObject | JsonValue[];

export interface JsonObject {
  [key: string]: JsonValue;
}

export type SafeDecision =
  | "ALLOW"
  | "BLOCK"
  | "REPLAN_READ_ONLY"
  | "USER_CONFIRM"
  | "QUARANTINE_ARTIFACT"
  | "ESCALATE_INCIDENT";

export type TaintClass =
  | "trusted"
  | "user-provided"
  | "session-discovered"
  | "untrusted"
  | "tainted";

export type VisibilityClass =
  | "visible"
  | "hidden"
  | "metadata"
  | "annotation"
  | "dynamic";

export type ExtractionMethod =
  | "dom"
  | "ax-tree"
  | "ocr"
  | "download"
  | "api"
  | "manual";

export type ArtifactKind =
  | "page"
  | "document"
  | "pdf"
  | "image"
  | "archive"
  | "tool_manifest"
  | "memory"
  | "unknown";

export interface TrustSignalSet {
  sourceOrigin: string;
  frameOrigin: string;
  sameOriginRelation: "same-origin" | "same-site" | "cross-site" | "cross-channel";
  visibilityClass: VisibilityClass;
  extractionMethod: ExtractionMethod;
  artifactKind: ArtifactKind;
  taintClass: TaintClass;
  approvalBindingId?: string;
  lineageChain: string[];
  userSharedFlag: boolean;
  sessionDiscoveredFlag: boolean;
}

export type OriginatingSurface =
  | "page"
  | "artifact"
  | "tool_description"
  | "tool_schema"
  | "memory"
  | "api";

export interface ObservationFragment {
  fragmentId: string;
  text: string;
  visibilityClass: VisibilityClass;
  medium: "text" | "ocr" | "metadata" | "annotation";
  sourceOrigin: string;
  frameOrigin: string;
  selector?: string;
  tainted: boolean;
}

export interface RawObservationInput {
  observationId?: string;
  taskId?: string;
  sourceType?: "page" | "document" | "tool_text" | "memory" | "api";
  text?: string;
  fragments?: Array<Partial<ObservationFragment> & Pick<ObservationFragment, "text">>;
  trustSignals?: Partial<TrustSignalSet>;
  rawHash?: string;
}

export interface ObservationEnvelope {
  observationId: string;
  taskId?: string;
  sourceType: "page" | "document" | "tool_text" | "memory" | "api";
  text: string;
  normalizedText: string;
  fragments: ObservationFragment[];
  trustSignals: TrustSignalSet;
  suspicionFlags: string[];
  matchedPatternIds: string[];
  riskScore: number;
  rawHash?: string;
  createdAt: string;
}

export interface TaskEnvelope {
  taskId: string;
  userGoal: string;
  phase?: string;
  allowedOrigins?: string[];
  allowedVerbs?: string[];
  forbiddenSinks?: string[];
}

export interface ActionProposal {
  actionId: string;
  taskId?: string;
  verb: string;
  currentOrigin?: string;
  targetOrigin?: string;
  targetUrl?: string;
  parameters?: Record<string, JsonValue>;
  dataRefs?: string[];
  riskClass?: "low" | "medium" | "high" | "critical";
  requestedWrite?: boolean;
  sensitiveSink?: boolean;
  userInitiated?: boolean;
  summary?: string;
  lineage?: string[];
  trustSignals: Partial<TrustSignalSet>;
}

export interface SafeVerdict {
  decision: SafeDecision;
  reasonCodes: string[];
  riskScore: number;
  safeConstraints?: Record<string, JsonValue>;
  matchedPatternIds?: string[];
  incidentPlaybookId?: string;
  telemetryTags?: string[];
}

export interface ArtifactInput {
  artifactId?: string;
  path?: string;
  bytes?: Uint8Array;
  mimeType: string;
  surfaceKind?: ArtifactKind;
  sourceOrigin?: string;
  viewerOrigin?: string;
  downloadOrigin?: string;
  extractionMethod?: ExtractionMethod;
  renderedText?: string;
  extractedText?: string;
  ocrText?: string;
  annotations?: string[];
  metadataText?: string[];
  trustSignals?: Partial<TrustSignalSet>;
}

export interface ArtifactEnvelope {
  artifactId: string;
  mimeType: string;
  surfaceKind: ArtifactKind;
  sourceOrigin: string;
  viewerOrigin?: string;
  downloadOrigin?: string;
  extractionMethod: ExtractionMethod;
  sha256: string;
  sizeBytes: number;
  mismatchSignals: string[];
  metadataSignals: string[];
  trustSignals: TrustSignalSet;
  lineageChain: string[];
  derivedTaintClass?: TaintClass;
  toolActivationPolicy?: "allow" | "user_confirm" | "block";
  approvalRequiredForFollowOn?: boolean;
  sourceObservationId?: string;
  createdAt: string;
}

export interface ArtifactBrokerResult {
  artifact: ArtifactEnvelope;
  verdict: SafeVerdict;
}

export interface ToolRequest {
  requestId: string;
  toolId: string;
  description: string;
  schemaDescriptions?: string[];
  authType?: "none" | "oauth" | "api_key";
  requestedRedirectUri?: string;
  allowedRedirectUris?: string[];
  tokenPassthroughRequested?: boolean;
  egressHosts?: string[];
  registrySigned?: boolean;
  registrySigner?: string;
  allowLocalhostEgress?: boolean;
  registryEntryId?: string;
  registryBundleId?: string;
  manifestHash?: string;
  schemaHash?: string;
  requestedScopes?: string[];
  callbackUri?: string;
  callbackOrigin?: string;
  sourceObservationId?: string;
  sourceArtifactId?: string;
  originatingSurface?: OriginatingSurface;
  approvalBindingId?: string;
  oauthContext?: OAuthContext;
  trustSignals?: Partial<TrustSignalSet>;
}

export interface OAuthContext {
  authorizationServer?: string;
  redirectUri?: string;
  callbackUri?: string;
  callbackOrigin?: string;
  requiresPkce?: boolean;
  pkceMethod?: "S256" | "plain";
  requestedScopes?: string[];
}

export interface VerifiedRegistryEntry {
  registryEntryId: string;
  adapterId: string;
  bundleId: string;
  bundleVersion: string;
  signer: string;
  authType: "none" | "oauth" | "api_key";
  package?: string;
  mode?: string;
  capabilities: string[];
  allowedTransports: string[];
  allowedRedirectUris: string[];
  allowedCallbackOrigins: string[];
  allowedScopes: string[];
  manifestHash?: string;
  schemaHash?: string;
  expiresAt?: string;
  allowPrivateEgress?: boolean;
  allowLoopbackCallbacks?: boolean;
}

export interface VerifiedRegistryBundle {
  bundleId: string;
  version: string;
  signer: string;
  generatedAt: string;
  expiresAt?: string;
  publicKeyId?: string;
  signatureVerified: boolean;
  entries: VerifiedRegistryEntry[];
}

export interface WorkflowBinding {
  bindingId: string;
  sourceObservationId?: string;
  sourceArtifactId?: string;
  originatingSurface: OriginatingSurface;
  lineageChain: string[];
  derivedTaintClass: TaintClass;
  createdAt: string;
}

export interface ToolOnboardingSession {
  sessionId: string;
  approvalBindingId: string;
  workflowBindingId?: string;
  toolId: string;
  registryEntryId: string;
  registryBundleId: string;
  callbackUri: string;
  callbackOrigin: string;
  requestedScopes: string[];
  state: string;
  pkceMethod: "S256";
  createdAt: string;
  expiresAt: string;
  status: "prepared" | "used" | "expired";
}

export interface ToolPreparationResult {
  verdict: SafeVerdict;
  verifiedRegistryEntry?: VerifiedRegistryEntry;
  workflowBinding?: WorkflowBinding;
}

export interface ToolCallbackVerificationRequest {
  sessionId: string;
  callbackUri: string;
  callbackOrigin: string;
  state: string;
  payload?: Record<string, JsonValue>;
}

export interface ToolCallbackVerificationResult {
  verdict: SafeVerdict;
  sessionId: string;
  verifiedAt: string;
}

export interface ArtifactV2Input extends ArtifactInput {
  sourceObservationId?: string;
  followOnToolRequest?: ToolRequest;
}

export interface ArtifactV2Result extends ArtifactBrokerResult {
  followOnToolVerdict?: SafeVerdict;
  workflowBinding?: WorkflowBinding;
}

export interface MemoryWriteRequest {
  entryId: string;
  key: string;
  value: JsonValue;
  source: "user" | "web" | "system";
  durable: boolean;
  previousValue?: JsonValue;
  trustSignals?: Partial<TrustSignalSet>;
}

export interface ReplayEvent {
  eventId: string;
  kind: "observation" | "action" | "artifact" | "tool" | "memory" | "verdict";
  payload: JsonValue;
  trustSignals?: Partial<TrustSignalSet>;
  timestamp?: string;
}

export interface ReplayBundle {
  bundleId: string;
  createdAt: string;
  policyVersion: string;
  profile: string;
  policyLayers?: PolicyLayerProvenance[];
  eventDigests: string[];
  events: ReplayEvent[];
  metrics: {
    totalEvents: number;
    blockingDecisions: number;
    reviewDecisions: number;
  };
}

export interface PolicyLayerProvenance {
  name: string;
  version: string;
  profile: string;
}

export interface PolicyLayer {
  name: string;
  version: string;
  profile: string;
  origins?: {
    readOnlyAllow?: string[];
    writableAllow?: string[];
  };
  actions?: {
    allow?: string[];
    requireApproval?: string[];
    deny?: string[];
  };
  artifacts?: {
    enableDocumentHandoff?: boolean;
    quarantineOnHiddenTextMismatch?: boolean;
    allowMimeTypes?: string[];
  };
  memory?: {
    durableWrites?: "allow" | "deny" | "approval";
    protectedKeys?: string[];
  };
  toolProtocol?: {
    forbidTokenPassthrough?: boolean;
    enforceExactRedirectUri?: boolean;
    allowedRegistrySigners?: string[];
    requireVerifiedRegistry?: boolean;
    requireApprovalBinding?: boolean;
    requireOauthStateBinding?: boolean;
    taintedConnectorFlowDecision?: "block" | "user_confirm";
    allowLoopbackCallbacksInDev?: boolean;
  };
  telemetry?: {
    replayBundle?: boolean;
    redactSensitiveValues?: boolean;
    sampling?: "full" | "adaptive" | "off";
  };
  raw?: Record<string, JsonValue>;
}

export interface PolicyPack {
  packId: string;
  profile: string;
  version: string;
  layers: PolicyLayer[];
  metadata?: Record<string, JsonValue>;
}

export interface KBOverlay {
  overlayId: string;
  targetKbIds: string[];
  additions: Array<Record<string, unknown>>;
  metadata?: Record<string, JsonValue>;
}

export interface CompiledPolicy {
  packId: string;
  profile: string;
  version: string;
  layerOrder: string[];
  layerProvenance: PolicyLayerProvenance[];
  readOnlyOrigins: ReadonlySet<string>;
  writableOrigins: ReadonlySet<string>;
  allowedActions: ReadonlySet<string>;
  approvalActions: ReadonlySet<string>;
  deniedActions: ReadonlySet<string>;
  allowedMimeTypes: ReadonlySet<string>;
  protectedMemoryKeys: ReadonlySet<string>;
  memoryDurableWrites: "allow" | "deny" | "approval";
  forbidTokenPassthrough: boolean;
  enforceExactRedirectUri: boolean;
  allowedRegistrySigners: ReadonlySet<string>;
  requireVerifiedRegistry: boolean;
  requireApprovalBinding: boolean;
  requireOauthStateBinding: boolean;
  taintedConnectorFlowDecision: "block" | "user_confirm";
  allowLoopbackCallbacksInDev: boolean;
  enableDocumentHandoff: boolean;
  quarantineOnHiddenTextMismatch: boolean;
  replayBundle: boolean;
  redactSensitiveValues: boolean;
  telemetrySampling: "full" | "adaptive" | "off";
  compiledAt: string;
}

export interface KnowledgeBaseContext {
  promptInjectionPatterns: Array<Record<string, unknown>>;
  actionIntegrityPatterns: Array<Record<string, unknown>>;
  artifactSurfacePatterns: Array<Record<string, unknown>>;
  toolProtocolPatterns: Array<Record<string, unknown>>;
  memoryContextPatterns: Array<Record<string, unknown>>;
  trustSignalsCatalog: Array<Record<string, unknown>>;
  policyControls: Array<Record<string, unknown>>;
  incidentPlaybooks: Array<Record<string, unknown>>;
  evaluationScenarios: Array<Record<string, unknown>>;
  sourceRegistry: Array<Record<string, unknown>>;
}

export interface MetadataCriticInput {
  actionId: string;
  verb: string;
  targetOrigin: string;
  requestedWrite: boolean;
  taintClass: TaintClass;
  sameOriginRelation: TrustSignalSet["sameOriginRelation"];
  reasonCodes: string[];
}

export interface RuntimeContext {
  policy: CompiledPolicy;
  knowledgeBase?: Partial<KnowledgeBaseContext>;
  taskEnvelope?: TaskEnvelope;
  verifiedRegistry?: VerifiedRegistryBundle;
  metadataOnlyCritic?: (input: MetadataCriticInput) => number;
  now?: () => Date;
}

export interface PromptGuardResult {
  suspicionFlags: string[];
  matchedPatternIds: string[];
  riskScore: number;
}


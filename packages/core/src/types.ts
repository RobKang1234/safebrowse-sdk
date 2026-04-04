export type JsonPrimitive = string | number | boolean | null;
export type JsonValue = JsonPrimitive | JsonObject | JsonValue[];

export interface JsonObject {
  [key: string]: JsonValue;
}

export type SafeDecision =
  | "ALLOW"
  | "BLOCK"
  | "REPLAN_READ_ONLY"
  | "APPROVAL_REQUIRED"
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
  taskPurposeClass?: TaskPurposeClass;
  taskPhase?: string;
  allowedOrigins?: string[];
  allowedVerbs?: string[];
  forbiddenSinks?: string[];
  allowedPathClasses?: TargetPathClass[];
  approvalRequiredPathClasses?: TargetPathClass[];
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
  approvalGrantId?: string;
  capabilityId?: string;
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
  sinkSensitivity?: "read_only" | "external_sensitive_sink";
  writeCapability?: boolean;
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

export type V4SurfaceType =
  | "html"
  | "pdf"
  | "image"
  | "tool_manifest"
  | "memory_candidate";

export type ProvenanceChannel =
  | "visible_text"
  | "hidden_text"
  | "metadata"
  | "annotation"
  | "ocr"
  | "comment"
  | "link"
  | "schema"
  | "memory_candidate"
  | "fact";

export interface SurfaceLinkCapture {
  href: string;
  text?: string;
  selector?: string;
  frameOrigin?: string;
}

interface BaseSurfaceCapture {
  captureId?: string;
  sessionId?: string;
  taskId?: string;
  url: string;
  frameUrl?: string;
  userShared?: boolean;
  trustSignals?: Partial<TrustSignalSet>;
}

export interface HtmlSurfaceCapture extends BaseSurfaceCapture {
  surfaceType: "html";
  html?: string;
  visibleText?: string;
  title?: string;
  hiddenText?: string[];
  metadataText?: string[];
  annotations?: string[];
  links?: SurfaceLinkCapture[];
  domDigest?: string;
  nestedUnsupportedComponents?: string[];
  captureAttestation?: CaptureAttestation;
}

export interface PdfSurfaceCapture extends BaseSurfaceCapture {
  surfaceType: "pdf";
  renderedText?: string;
  extractedText?: string;
  ocrText?: string;
  annotations?: string[];
  metadataText?: string[];
  attachments?: string[];
  sourceDigest?: string;
}

export interface ImageSurfaceCapture extends BaseSurfaceCapture {
  surfaceType: "image";
  ocrText?: string;
  metadataText?: string[];
  captionText?: string;
  sourceDigest?: string;
}

export interface ToolManifestSurfaceCapture extends BaseSurfaceCapture {
  surfaceType: "tool_manifest";
  toolId: string;
  description: string;
  schemaDescriptions?: string[];
  authType?: "none" | "oauth" | "api_key";
  requestedScopes?: string[];
  callbackUri?: string;
  callbackOrigin?: string;
  packageName?: string;
  mode?: string;
}

export interface MemoryCandidateSurfaceCapture extends BaseSurfaceCapture {
  surfaceType: "memory_candidate";
  key: string;
  value: JsonValue;
  durable: boolean;
  source: "user" | "web" | "model" | "system";
}

export type SurfaceCapture =
  | HtmlSurfaceCapture
  | PdfSurfaceCapture
  | ImageSurfaceCapture
  | ToolManifestSurfaceCapture
  | MemoryCandidateSurfaceCapture;

export interface ProvenanceSpan {
  spanId: string;
  channel: ProvenanceChannel;
  text: string;
  sourceOrigin: string;
  frameOrigin: string;
  visibilityClass: VisibilityClass;
  extractionMethod: ExtractionMethod;
  taintClass: TaintClass;
  lineageChain: string[];
  selector?: string;
  supportingDigest?: string;
  sourceNodePathHash?: string;
  blockedForAuthority?: boolean;
  visibleOnlyFlag?: boolean;
}

export interface ExtractedTarget {
  targetId: string;
  kind: "navigate" | "download_artifact" | "connector_prepare";
  href?: string;
  selector?: string;
  sourceSpanIds: string[];
  sourceOrigin: string;
  frameOrigin: string;
  targetOrigin: string;
  displayText: string;
  sourceNodePathHash?: string;
  sourceChannelSet?: ProvenanceChannel[];
  visibleOnlyFlag?: boolean;
}

export type ParserIsolationMode = "scrubbed_process" | "node_permission_process";

export interface ParserIsolationReport {
  mode: ParserIsolationMode;
  processIsolated: boolean;
  envScrubbed: boolean;
  egressDenied: boolean;
  permissionModelEnabled: boolean;
  fsReadRestricted: boolean;
  childProcessDenied: boolean;
  workerThreadsDenied: boolean;
  envKeys: string[];
  allowlistedEgress: string[];
}

export interface CompiledObservation {
  observationId: string;
  sessionId?: string;
  taskId?: string;
  surfaceType: V4SurfaceType;
  sourceOrigin: string;
  frameOrigin: string;
  sourceDigest: string;
  workflowHash?: string;
  parseStatus: "compiled" | "partial" | "unsupported" | "failed";
  parserIsolation: ParserIsolationReport;
  spans: ProvenanceSpan[];
  extractedFacts: string[];
  extractedTargets: ExtractedTarget[];
  riskFindings: string[];
  suspicionFlags: string[];
  matchedPatternIds: string[];
  riskScore: number;
  secretFindings: string[];
  createdAt: string;
}

export interface PlannerCapabilityOption {
  capabilityId: string;
  title: string;
  kind: CapabilityDescriptor["kind"];
  parameterSchema: Record<string, JsonValue>;
  expiresAt: string;
}

export interface StructuredPlannerInput {
  observationId: string;
  sessionId?: string;
  surfaceType: V4SurfaceType;
  visibleExcerpt: string;
  facts: string[];
  quotedUntrustedBlocks: Array<{
    channel: ProvenanceChannel;
    text: string;
    spanId: string;
  }>;
  riskMarkers: string[];
  blockedChannels: ProvenanceChannel[];
  secretRedactionsApplied: boolean;
  candidateCapabilities: PlannerCapabilityOption[];
}

export interface TaskSession {
  sessionId: string;
  taskId: string;
  userGoal: string;
  phase?: string;
  taskPurposeClass?: TaskPurposeClass;
  taskPhase?: string;
  allowedOrigins: string[];
  allowedVerbs: string[];
  forbiddenSinks: string[];
  allowedPathClasses?: TargetPathClass[];
  approvalRequiredPathClasses?: TargetPathClass[];
  workflowHash: string;
  currentStep: number;
  createdAt: string;
  expiresAt: string;
  claimProfile?: "secure_v6";
  approvalBrokerRequired?: boolean;
  legacyRoutesDisabled?: boolean;
}

export type TaskPurposeClass =
  | "content_read"
  | "docs_navigation"
  | "workflow_continue"
  | "reconciliation_review"
  | "connector_setup"
  | "account_settings"
  | "admin"
  | "export"
  | "finalize"
  | "authorize"
  | "billing"
  | "payment";

export type TargetPathClass =
  | "content_read"
  | "docs_navigation"
  | "workflow_continue"
  | "reconciliation_review"
  | "account_settings"
  | "admin"
  | "export"
  | "finalize"
  | "authorize"
  | "billing"
  | "payment"
  | "connector_setup"
  | "reconciliation"
  | "logout"
  | "delete"
  | "destructive_action"
  | "credential_reset";

export interface CaptureAttestation {
  captureMethod: "rendered_dom" | "ax_tree" | "api" | "download" | "ocr";
  visibilityAttested: boolean;
  frameCoverage: "none" | "partial" | "full";
  shadowDomCoverage: "none" | "partial" | "full";
  unsupportedSubtrees: string[];
  evidenceHash?: string;
}

export interface CapabilityDescriptor {
  capabilityId: string;
  sessionId: string;
  workflowStep: number;
  kind:
    | "navigate"
    | "download_artifact"
    | "connector_prepare"
    | "memory_promote";
  targetClass:
    | "browser_navigation"
    | "artifact_ingest"
    | "connector"
    | "memory_promotion";
  originBoundTo: string;
  targetOrigin: string;
  targetUrl?: string;
  selector?: string;
  sourceObservationId: string;
  sourceArtifactId?: string;
  sourceDigest: string;
  frameOrigins: string[];
  sourceSpanIds: string[];
  parameterSchema: Record<string, JsonValue>;
  derivedSinkClass: "browser_navigation" | "connector_oauth" | "memory_promotion";
  derivedSensitiveSink: boolean;
  expiresAt: string;
  nonReplayable: true;
  workflowHash: string;
  title: string;
}

export interface PlannerViewV5 {
  observationId: string;
  sessionId?: string;
  surfaceType: V4SurfaceType;
  visibleExcerpt: string;
  facts: string[];
  quotedTaintedBlocks: Array<{
    channel: ProvenanceChannel;
    text: string;
    spanId: string;
  }>;
  blockedChannels: ProvenanceChannel[];
  riskMarkers: string[];
  secretRedactionsApplied: boolean;
}

export interface CompiledObservationV5 extends CompiledObservation {
  authorityEligible: boolean;
  provenanceDigest: string;
}

export interface CapabilityDescriptorV5 {
  capabilityId: string;
  capabilityDigest: string;
  semanticDigest: string;
  sessionId: string;
  workflowHash: string;
  workflowStep: number;
  kind: "navigate" | "connector_prepare" | "memory_promote";
  targetClass: "browser_navigation" | "connector" | "memory_promotion";
  originBoundTo: string;
  targetOrigin: string;
  targetUrl?: string;
  selector?: string;
  sourceObservationId: string;
  sourceDigest: string;
  frameOrigins: string[];
  sourceSpanIds: string[];
  sourceNodePathHash?: string;
  mintedFromChannels: ProvenanceChannel[];
  visibleOnlyFlag: boolean;
  parameterSchema: Record<string, JsonValue>;
  derivedSinkClass: "browser_navigation" | "connector_oauth" | "memory_promotion";
  derivedSensitiveSink: boolean;
  registryEntryId?: string;
  registryBundleId?: string;
  registryBundleVersion?: string;
  registrySigner?: string;
  connectorId?: string;
  requestedScopes?: string[];
  callbackUri?: string;
  callbackOrigin?: string;
  manifestHash?: string;
  schemaHash?: string;
  memoryRecordId?: string;
  expiresAt: string;
  nonReplayable: true;
  consumedAt?: string;
  title: string;
}

export interface CapabilityUseRequestV5 {
  sessionId: string;
  capabilityId: string;
  capabilityDigest: string;
  parameters?: Record<string, JsonValue>;
}

export interface ApprovalEnvelopeV5 {
  approvalId: string;
  sessionId: string;
  workflowHash: string;
  workflowStep: number;
  capabilityId: string;
  capabilityDigest: string;
  semanticDigest: string;
  sinkClass: "connector_oauth" | "memory_promotion";
  connectorId?: string;
  registryEntryId?: string;
  registryBundleId?: string;
  registryBundleVersion?: string;
  registrySigner?: string;
  requestedScopes: string[];
  requestedScopesHash: string;
  callbackUri?: string;
  callbackOrigin?: string;
  manifestHash?: string;
  schemaHash?: string;
  targetOrigin: string;
  issuedAt: string;
  expiresAt: string;
  brokerSignature: string;
  signedByBroker: true;
  consumedAt?: string;
  onboardingSessionId?: string;
}

export interface ConnectorHandle {
  handleId: string;
  sessionId: string;
  approvalId: string;
  connectorId: string;
  registryEntryId: string;
  registryBundleId?: string;
  registryBundleVersion?: string;
  registrySigner?: string;
  manifestHash?: string;
  schemaHash?: string;
  scopeSet: string[];
  issuedAt: string;
  expiresAt: string;
  status: "active" | "expired";
}

export interface ToolOnboardingSessionV5 {
  onboardingSessionId: string;
  sessionId: string;
  approvalId: string;
  capabilityDigest: string;
  connectorId: string;
  registryEntryId: string;
  registryBundleId?: string;
  registryBundleVersion?: string;
  registrySigner?: string;
  callbackUri: string;
  callbackOrigin: string;
  requestedScopes: string[];
  manifestHash?: string;
  schemaHash?: string;
  state: string;
  pkceMethod: "S256";
  createdAt: string;
  expiresAt: string;
  status: "prepared" | "used" | "expired";
}

export interface V5ObservationResponse {
  compiledObservation: CompiledObservationV5;
  plannerView: PlannerViewV5;
  capabilities: Array<{
    capabilityId: string;
    capabilityDigest: string;
    semanticDigest: string;
    title: string;
    kind: CapabilityDescriptorV5["kind"];
    parameterSchema: Record<string, JsonValue>;
    expiresAt: string;
  }>;
  observationVerdict: SafeVerdict;
}

export interface CapabilityUseRequest {
  sessionId: string;
  capabilityId: string;
  sourceObservationId: string;
  sourceDigest: string;
  parameters?: Record<string, JsonValue>;
}

export interface ApprovalGrant {
  approvalGrantId: string;
  sessionId: string;
  workflowHash: string;
  connectorId: string;
  scopes: string[];
  sinkClass: "connector_oauth" | "memory_promotion" | "outbound_navigation";
  capabilityIds: string[];
  targetOrigin: string;
  issuedAt: string;
  expiresAt: string;
  grantHash: string;
}

export type MemoryTier = "trusted_durable" | "candidate_durable" | "tainted_ephemeral";
export type MemorySourceClass =
  | "user_provided"
  | "web_observed"
  | "model_inferred"
  | "validated_system"
  | "system_generated";

export interface MemoryRecord {
  recordId: string;
  sessionId: string;
  key: string;
  value: JsonValue;
  summaryValue: JsonValue;
  tier: MemoryTier;
  source: "user" | "web" | "model" | "system";
  sourceClass: MemorySourceClass;
  sourceObservationId?: string;
  sourceDigest?: string;
  corroboration?: MemoryCorroborationV5[];
  secretFindings: string[];
  summaryOnly: boolean;
  createdAt: string;
  expiresAt?: string;
  snapshotId?: string;
  rollbackPointId?: string;
  lineageChain?: string[];
  delayedTriggerIndicators?: string[];
  priorTrustedRecordId?: string;
}

export interface MemoryPromotionRequest {
  sessionId: string;
  recordId: string;
  approvalGrantId?: string;
  validationEvidence?: string[];
}

export interface MemoryWriteRequestV5 {
  sessionId: string;
  inputKind: "user_note";
  key: string;
  value: JsonValue;
  durable: boolean;
}

export interface MemoryPromotionRequestV5 {
  sessionId: string;
  recordId: string;
  capabilityId: string;
  capabilityDigest: string;
  approvalId: string;
}

export interface MemoryRollbackRequest {
  sessionId: string;
  recordId: string;
  snapshotId: string;
}

export interface MemoryRollbackResult {
  verdict: SafeVerdict;
  restoredRecord?: MemoryRecord;
}

export type MemoryStageSourceClassV5 =
  | "user_note"
  | "web_observation"
  | "model_summary"
  | "retrieval_fact"
  | "system_validation";

export type MemorySourceClassV6 = MemoryStageSourceClassV5;

export interface MemoryCorroborationV5 {
  source: string;
  digest?: string;
  note?: string;
}

export type MemoryCorroborationV6 = MemoryCorroborationV5;

export interface MemoryStageRequestV5 {
  sessionId: string;
  key: string;
  value: JsonValue;
  sourceClass: MemoryStageSourceClassV5;
  durable: boolean;
  sourceObservationId?: string;
  sourceDigest?: string;
  corroboration?: MemoryCorroborationV5[];
  lineageChain?: string[];
  delayedTriggerIndicators?: string[];
}

export type MemoryStageRequestV6 = MemoryStageRequestV5;

export interface MemoryPromotionTicketV5 {
  ticketId: string;
  ticketDigest: string;
  semanticDigest: string;
  recordId: string;
  sourceClass: MemoryStageSourceClassV5;
  expiresAt: string;
}

export type MemoryPromotionTicketV6 = MemoryPromotionTicketV5;

export interface StagedMemoryPromotionRequestV5 {
  sessionId: string;
  recordId: string;
  ticketId: string;
  ticketDigest: string;
  approvalId: string;
}

export type MemoryPromotionRequestV6 = StagedMemoryPromotionRequestV5;

export interface V5AuthorityCandidate {
  authorityId: string;
  authorityDigest: string;
  semanticDigest: string;
  title: string;
  kind: CapabilityDescriptorV5["kind"];
  parameterSchema: Record<string, JsonValue>;
  expiresAt: string;
}

export interface AuthorityFinding {
  findingId: string;
  code: string;
  severity: "low" | "medium" | "high";
  evidenceSpanIds: string[];
  targetPathClass?: TargetPathClass;
}

export interface CompiledObservationV6 extends CompiledObservationV5 {
  provenanceFindings: AuthorityFinding[];
  semanticAuthorityFindings: AuthorityFinding[];
  policyFindings: AuthorityFinding[];
  authorityReductionReasonIds: string[];
  factsOnlyReasonCodes: string[];
  evidenceSpanIds: string[];
  captureAttestation: CaptureAttestation;
}

export interface PlannerViewV6 extends PlannerViewV5 {
  authorityReductionReasonIds: string[];
  factsOnlyReasonCodes: string[];
  evidenceSpanIds: string[];
}

export interface CapabilityDescriptorV6 extends CapabilityDescriptorV5 {
  targetPathClass: TargetPathClass;
  requiresApproval: boolean;
  evidenceSpanIds: string[];
}

export interface CapabilityUseRequestV6 {
  sessionId: string;
  authorityId: string;
  authorityDigest: string;
  approvalId?: string;
  parameters?: Record<string, JsonValue>;
}

export interface ApprovalEnvelopeV6 extends Omit<ApprovalEnvelopeV5, "sinkClass"> {
  sinkClass: "browser_navigation" | "connector_oauth" | "memory_promotion";
  targetPathClass?: TargetPathClass;
  evidenceSpanIds?: string[];
}

export interface ToolOnboardingSessionV6 extends ToolOnboardingSessionV5 {}

export interface V6AuthorityCandidate {
  authorityId: string;
  authorityDigest: string;
  semanticDigest: string;
  title: string;
  kind: CapabilityDescriptorV6["kind"];
  targetPathClass: TargetPathClass;
  requiresApproval: boolean;
  evidenceSpanIds: string[];
  parameterSchema: Record<string, JsonValue>;
  expiresAt: string;
}

export interface V5ArtifactRef {
  artifactId: string;
  surfaceKind: ArtifactKind;
  sourceOrigin: string;
  viewerOrigin?: string;
  mismatchSignals: string[];
  metadataSignals: string[];
  provenance: {
    extractionMethod: ExtractionMethod;
    lineageChain: string[];
    derivedTaintClass?: TaintClass;
  };
  authorityEligible: boolean;
}

export type V6ArtifactRef = V5ArtifactRef;

export interface V5ObserveResponse {
  compiledObservation: CompiledObservationV5;
  plannerView: PlannerViewV5;
  authorityCandidates: V5AuthorityCandidate[];
  artifactRefs: V5ArtifactRef[];
  observationVerdict: SafeVerdict;
  replayEventId: string;
}

export interface V6ObserveResponse {
  compiledObservation: CompiledObservationV6;
  plannerView: PlannerViewV6;
  authorityCandidates: V6AuthorityCandidate[];
  artifactRefs: V6ArtifactRef[];
  observationVerdict: SafeVerdict;
  replayEventId: string;
}

export interface V5ActionEvaluateRequest {
  sessionId: string;
  authorityId: string;
  authorityDigest: string;
  parameters?: Record<string, JsonValue>;
}

export interface V6ActionEvaluateRequest {
  sessionId: string;
  authorityId: string;
  authorityDigest: string;
  approvalId?: string;
  parameters?: Record<string, JsonValue>;
}

export interface V5ActionEvaluateResponse {
  observationDecision: SafeVerdict;
  authorityDecision: SafeVerdict;
  effectDecision: SafeVerdict;
  executionPlan?: Record<string, JsonValue>;
}

export interface V6ActionEvaluateResponse {
  observationDecision: SafeVerdict;
  authorityDecision: SafeVerdict;
  effectDecision: SafeVerdict;
  executionPlan?: Record<string, JsonValue>;
}

export interface V5ArtifactIngestResponse {
  compiledObservation: CompiledObservationV5;
  plannerView: PlannerViewV5;
  artifactRef: V5ArtifactRef;
  mismatchSignals: string[];
  artifactVerdict: SafeVerdict;
  replayEventId: string;
}

export interface V6ArtifactIngestResponse {
  compiledObservation: CompiledObservationV6;
  plannerView: PlannerViewV6;
  artifactRef: V6ArtifactRef;
  mismatchSignals: string[];
  artifactVerdict: SafeVerdict;
  replayEventId: string;
}

export interface ParserWorkerProbe {
  mode: ParserIsolationMode;
  envKeys: string[];
  egressDenied: boolean;
  processIsolated: boolean;
  permissionModelEnabled: boolean;
  fsReadRestricted: boolean;
  childProcessDenied: boolean;
  workerThreadsDenied: boolean;
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
  source: "user" | "web" | "model" | "system";
  sourceClass?: MemorySourceClass;
  durable: boolean;
  previousValue?: JsonValue;
  trustSignals?: Partial<TrustSignalSet>;
}

export type ReplayActor = "raw" | "raw_model" | "sdk" | "system" | "user";

export interface ReplayEvent {
  eventId: string;
  kind: "observation" | "action" | "artifact" | "tool" | "memory" | "verdict";
  payload: JsonValue;
  trustSignals?: Partial<TrustSignalSet>;
  actor?: ReplayActor;
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
    actorCounts?: Partial<Record<ReplayActor, number>>;
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


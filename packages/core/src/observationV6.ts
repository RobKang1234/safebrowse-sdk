import {
  type AuthorityFinding,
  type CaptureAttestation,
  type CompiledObservationV6,
  type PlannerViewV6,
  type RuntimeContext,
  type SafeVerdict,
  type SurfaceCapture
} from "./types.js";
import { compileObservationBase } from "./observationBase.js";
import { redactSecretsInText } from "./secretIsolation.js";
import { classifyTargetPathClass } from "./pathPolicyV6.js";
import { clamp, sha256Hex, stableStringify, uniq } from "./utils.js";

function defaultCaptureAttestation(capture: SurfaceCapture): CaptureAttestation {
  if (capture.surfaceType !== "html") {
    return {
      captureMethod: capture.surfaceType === "tool_manifest" ? "api" : capture.surfaceType === "image" ? "ocr" : "download",
      visibilityAttested: true,
      frameCoverage: "full",
      shadowDomCoverage: "full",
      unsupportedSubtrees: []
    };
  }

  return (
    capture.captureAttestation ?? {
      captureMethod: "rendered_dom",
      visibilityAttested: false,
      frameCoverage: "partial",
      shadowDomCoverage: "partial",
      unsupportedSubtrees: []
    }
  );
}

function createFinding(
  code: string,
  severity: "low" | "medium" | "high",
  evidenceSpanIds: string[],
  targetPathClass?: CompiledObservationV6["semanticAuthorityFindings"][number]["targetPathClass"]
): AuthorityFinding {
  return {
    findingId: sha256Hex(stableStringify({ code, severity, evidenceSpanIds, targetPathClass })).slice(0, 16),
    code,
    severity,
    evidenceSpanIds,
    ...(targetPathClass ? { targetPathClass } : {})
  };
}

function visibleTextFromObservation(observation: CompiledObservationV6): string {
  return observation.spans
    .filter((span) => span.channel === "visible_text")
    .map((span) => span.text)
    .join(" ")
    .toLowerCase();
}

function evidenceSpanIdsForChannels(
  observation: CompiledObservationV6,
  channels: Array<CompiledObservationV6["spans"][number]["channel"]>
): string[] {
  return observation.spans
    .filter((span) => channels.includes(span.channel))
    .map((span) => span.spanId);
}

function baseAuthorityEligibleForV6(observation: CompiledObservationV6): boolean {
  if (observation.parseStatus !== "compiled" || observation.secretFindings.length > 0) {
    return false;
  }

  if (observation.surfaceType === "html") {
    return !observation.spans.some((span) => span.blockedForAuthority) && observation.riskFindings.length === 0;
  }

  if (observation.surfaceType === "email_message") {
    return !observation.riskFindings.some((code) =>
      [
        "surface_attestation_missing",
        "quoted_thread_prompting_present",
        "unsupported_nested_renderer"
      ].includes(code)
    );
  }

  if (["docx", "xlsx", "pptx"].includes(observation.surfaceType)) {
    return !observation.riskFindings.some((code) =>
      [
        "surface_attestation_missing",
        "hidden_office_content_present",
        "office_external_relationship_present",
        "office_embedded_object_present",
        "unsupported_nested_renderer"
      ].includes(code)
    );
  }

  if (observation.surfaceType === "external_api_response") {
    return !observation.riskFindings.some((code) => ["surface_attestation_missing"].includes(code));
  }

  if (observation.surfaceType === "attachment_bundle") {
    return false;
  }

  return !observation.spans.some((span) => span.blockedForAuthority) && observation.riskFindings.length === 0;
}

function deriveProvenanceFindings(observation: CompiledObservationV6): AuthorityFinding[] {
  const blockedFindings = observation.spans
    .filter((span) => span.blockedForAuthority)
    .map((span) =>
      createFinding(`BLOCKED_${span.channel.toUpperCase()}`, "medium", [span.spanId])
    );

  const riskFindings = observation.riskFindings.map((risk) =>
    createFinding(risk, "medium", [])
  );

  return uniq([...blockedFindings, ...riskFindings].map((finding) => stableStringify(finding))).map(
    (serialized) => JSON.parse(serialized) as AuthorityFinding
  );
}

function deriveSemanticAuthorityFindings(observation: CompiledObservationV6): AuthorityFinding[] {
  const visibleText = visibleTextFromObservation(observation);
  const findings: AuthorityFinding[] = [];
  const coerciveSignals = observation.suspicionFlags.filter((flag) =>
    ["prompt_override_language", "privilege_claim_language", "social_engineering_pressure"].includes(flag)
  );

  for (const target of observation.extractedTargets) {
    const targetPathClass = classifyTargetPathClass({
      targetUrl: target.href,
      displayText: target.displayText,
      selector: target.selector
    });

    if (coerciveSignals.length) {
      findings.push(
        createFinding(
          "VISIBLE_OVERRIDE_ATTACHED_TO_EFFECTFUL_TARGET",
          "high",
          target.sourceSpanIds,
          targetPathClass
        )
      );
    }

    if (
      targetPathClass !== "content_read" &&
      targetPathClass !== "docs_navigation" &&
      /(continue|next step|proceed|follow|approval|authorize|finalize|payment|billing|reconcil|export|only trusted)/i.test(
        visibleText
      )
    ) {
      findings.push(
        createFinding("VISIBLE_WORKFLOW_STEERING", "high", target.sourceSpanIds, targetPathClass)
      );
    }
  }

  return uniq(findings.map((finding) => stableStringify(finding))).map(
    (serialized) => JSON.parse(serialized) as AuthorityFinding
  );
}

function derivePolicyFindings(observation: CompiledObservationV6): AuthorityFinding[] {
  const findings: AuthorityFinding[] = [];
  const hasRiskFinding = (code: string) => observation.riskFindings.includes(code);

  if (observation.surfaceType === "html" && !observation.captureAttestation.visibilityAttested) {
    findings.push(createFinding("VISIBILITY_ATTESTATION_REQUIRED", "high", []));
  }
  if (
    observation.surfaceType === "html" &&
    (observation.captureAttestation.frameCoverage !== "full" ||
      observation.captureAttestation.shadowDomCoverage !== "full" ||
      observation.captureAttestation.unsupportedSubtrees.length > 0)
  ) {
    findings.push(createFinding("VISIBILITY_ATTESTATION_PARTIAL", "medium", []));
  }

  if (
    ["email_message", "docx", "xlsx", "pptx", "external_api_response", "attachment_bundle"].includes(
      observation.surfaceType
    ) &&
    hasRiskFinding("surface_attestation_missing")
  ) {
    findings.push(createFinding("SURFACE_ATTESTATION_REQUIRED", "high", []));
  }

  if (observation.surfaceType === "email_message" && hasRiskFinding("quoted_thread_prompting_present")) {
    findings.push(
      createFinding(
        "QUOTED_THREAD_PROMPTING_PRESENT",
        "high",
        evidenceSpanIdsForChannels(observation, ["quoted_thread"])
      )
    );
  }

  if (
    ["docx", "xlsx", "pptx"].includes(observation.surfaceType) &&
    hasRiskFinding("hidden_office_content_present")
  ) {
    findings.push(
      createFinding(
        "HIDDEN_OFFICE_CONTENT_PRESENT",
        "high",
        evidenceSpanIdsForChannels(observation, [
          "hidden_sheet",
          "hidden_slide",
          "tracked_change",
          "office_comment",
          "office_note",
          "office_formula"
        ])
      )
    );
  }

  if (
    ["docx", "xlsx", "pptx"].includes(observation.surfaceType) &&
    hasRiskFinding("office_external_relationship_present")
  ) {
    findings.push(
      createFinding(
        "OFFICE_EXTERNAL_RELATIONSHIP_PRESENT",
        "high",
        evidenceSpanIdsForChannels(observation, ["external_relationship"])
      )
    );
  }

  if (
    ["docx", "xlsx", "pptx"].includes(observation.surfaceType) &&
    hasRiskFinding("office_embedded_object_present")
  ) {
    findings.push(
      createFinding(
        "OFFICE_EMBEDDED_OBJECT_PRESENT",
        "high",
        evidenceSpanIdsForChannels(observation, ["embedded_object"])
      )
    );
  }

  if (
    ["docx", "xlsx", "pptx", "attachment_bundle"].includes(observation.surfaceType) &&
    (hasRiskFinding("unsupported_nested_renderer") ||
      hasRiskFinding("external_relationship_hydration_attempt") ||
      hasRiskFinding("encrypted_attachment_present"))
  ) {
    findings.push(
      createFinding(
        "ARTIFACT_EXTRACTION_RESTRICTED",
        "high",
        evidenceSpanIdsForChannels(observation, [
          "attachment_reference",
          "external_relationship",
          "embedded_object"
        ])
      )
    );
  }

  return findings;
}

function buildPlannerViewV6(observation: CompiledObservationV6): PlannerViewV6 {
  const baseVisibleExcerpt = redactSecretsInText(
    observation.spans
      .filter((span) => span.channel === "visible_text")
      .map((span) => span.text)
      .join(" ")
  ).text.slice(0, 3000);

  return {
    observationId: observation.observationId,
    sessionId: observation.sessionId,
    surfaceType: observation.surfaceType,
    visibleExcerpt:
      observation.authorityReductionReasonIds.length > 0 || observation.parseStatus !== "compiled"
        ? ""
        : baseVisibleExcerpt,
    facts: observation.extractedFacts.map((fact) => redactSecretsInText(fact).text),
    quotedTaintedBlocks: observation.spans
      .filter(
        (span) =>
          span.blockedForAuthority ||
          ["metadata", "annotation", "schema", "memory_candidate"].includes(span.channel)
      )
      .slice(0, 6)
      .map((span) => ({
        channel: span.channel,
        text: redactSecretsInText(span.text).text.slice(0, 500),
        spanId: span.spanId
      })),
    blockedChannels: uniq(
      observation.spans.filter((span) => span.blockedForAuthority).map((span) => span.channel)
    ),
    riskMarkers: uniq([
      ...observation.suspicionFlags,
      ...observation.riskFindings,
      ...observation.provenanceFindings.map((finding) => finding.code.toLowerCase()),
      ...observation.semanticAuthorityFindings.map((finding) => finding.code.toLowerCase()),
      ...observation.policyFindings.map((finding) => finding.code.toLowerCase()),
      ...(observation.secretFindings.length ? ["secret_redaction_applied"] : [])
    ]),
    secretRedactionsApplied: observation.secretFindings.length > 0,
    authorityReductionReasonIds: observation.authorityReductionReasonIds,
    factsOnlyReasonCodes: observation.factsOnlyReasonCodes,
    evidenceSpanIds: observation.evidenceSpanIds
  };
}

export function compileObservationV6(
  capture: SurfaceCapture,
  context: Partial<RuntimeContext> = {},
  options: {
    parserIsolation?: CompiledObservationV6["parserIsolation"];
    workflowHash?: string;
  } = {}
): {
  compiledObservation: CompiledObservationV6;
  plannerView: PlannerViewV6;
} {
  const base = compileObservationBase(capture, context, options);
  const captureAttestation = defaultCaptureAttestation(capture);
  const parseStatus =
    capture.surfaceType === "html" && !captureAttestation.visibilityAttested
      ? "unsupported"
      : capture.surfaceType === "html" &&
          (captureAttestation.frameCoverage !== "full" ||
            captureAttestation.shadowDomCoverage !== "full" ||
            captureAttestation.unsupportedSubtrees.length > 0)
        ? "partial"
        : base.compiledObservation.parseStatus;

  const compiledObservation: CompiledObservationV6 = {
    ...base.compiledObservation,
    parseStatus,
    captureAttestation,
    provenanceFindings: [],
    semanticAuthorityFindings: [],
    policyFindings: [],
    authorityReductionReasonIds: [],
    factsOnlyReasonCodes: [],
    evidenceSpanIds: []
  };

  compiledObservation.provenanceFindings = deriveProvenanceFindings(compiledObservation);
  compiledObservation.semanticAuthorityFindings = deriveSemanticAuthorityFindings(compiledObservation);
  compiledObservation.policyFindings = derivePolicyFindings(compiledObservation);
  compiledObservation.authorityReductionReasonIds = [
    ...compiledObservation.semanticAuthorityFindings.map((finding) => finding.findingId),
    ...compiledObservation.policyFindings.map((finding) => finding.findingId)
  ];
  compiledObservation.factsOnlyReasonCodes = [
    ...compiledObservation.semanticAuthorityFindings.map((finding) => finding.code),
    ...compiledObservation.policyFindings.map((finding) => finding.code)
  ];
  compiledObservation.evidenceSpanIds = uniq([
    ...compiledObservation.provenanceFindings.flatMap((finding) => finding.evidenceSpanIds),
    ...compiledObservation.semanticAuthorityFindings.flatMap((finding) => finding.evidenceSpanIds),
    ...compiledObservation.policyFindings.flatMap((finding) => finding.evidenceSpanIds)
  ]);
  compiledObservation.authorityEligible =
    baseAuthorityEligibleForV6(compiledObservation) &&
    compiledObservation.semanticAuthorityFindings.length === 0 &&
    compiledObservation.policyFindings.length === 0;
  compiledObservation.riskScore = clamp(
    Math.max(
      compiledObservation.riskScore,
      compiledObservation.semanticAuthorityFindings.length * 0.18,
      compiledObservation.policyFindings.length * 0.2
    )
  );

  return {
    compiledObservation,
    plannerView: buildPlannerViewV6(compiledObservation)
  };
}

export function applyV6ObservationMediation(
  compiledObservation: CompiledObservationV6,
  plannerView: PlannerViewV6
): {
  plannerView: PlannerViewV6;
  verdict: SafeVerdict;
  failClosed: boolean;
} {
  if (compiledObservation.parseStatus !== "compiled") {
    return {
      plannerView: {
        ...plannerView,
        visibleExcerpt: "",
        facts: [],
        quotedTaintedBlocks: [],
        riskMarkers: uniq([...plannerView.riskMarkers, `parse_status_${compiledObservation.parseStatus}`])
      },
      verdict: {
        decision: "BLOCK",
        reasonCodes: [
          compiledObservation.parseStatus === "partial" ? "PARSE_STATUS_PARTIAL" : "PARSE_STATUS_UNSUPPORTED"
        ],
        riskScore: 0.98,
        safeConstraints: {
          claim_profile: "secure_v6",
          authority_eligible: false,
          planner_safe_content_removed: true
        },
        telemetryTags: ["v6_observation", "fail_closed"]
      },
      failClosed: true
    };
  }

  if (compiledObservation.authorityReductionReasonIds.length > 0 || !compiledObservation.authorityEligible) {
    return {
      plannerView: {
        ...plannerView,
        visibleExcerpt: ""
      },
      verdict: {
        decision: "REPLAN_READ_ONLY",
        reasonCodes:
          compiledObservation.factsOnlyReasonCodes.length > 0
            ? compiledObservation.factsOnlyReasonCodes
            : ["AUTHORITY_REDUCED_TO_FACTS_ONLY"],
        riskScore: clamp(Math.max(0.2, compiledObservation.riskScore)),
        safeConstraints: {
          claim_profile: "secure_v6",
          authority_eligible: false
        },
        telemetryTags: ["v6_observation", "facts_only"]
      },
      failClosed: false
    };
  }

  return {
    plannerView,
    verdict: {
      decision: "ALLOW",
      reasonCodes: [],
      riskScore: clamp(Math.max(0.05, compiledObservation.riskScore)),
      safeConstraints: {
        claim_profile: "secure_v6",
        authority_eligible: true
      },
      telemetryTags: ["v6_observation", "authority_eligible"]
    },
    failClosed: false
  };
}

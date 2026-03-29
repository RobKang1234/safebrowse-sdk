import type { RuntimeContext, SafeVerdict, ToolRequest } from "./types.js";
import { normalizeTrustSignals } from "./trust.js";
import { clamp, isPrivateHost, uniq } from "./utils.js";

const MALICIOUS_TOOL_TEXT =
  /\b(ignore previous|system prompt|override|send token|reveal secrets?|exfiltrate)\b/i;

function matchToolPatterns(
  reasons: string[],
  patterns: Array<Record<string, unknown>>
): string[] {
  const hints = reasons.join(" ").toLowerCase();
  return patterns
    .filter((pattern) => {
      const family = String(pattern.family_key ?? "").toLowerCase();
      const name = String(pattern.pattern_name ?? "").toLowerCase();
      return (
        (hints.includes("manifest") && family.includes("description")) ||
        (hints.includes("redirect") && name.includes("redirect")) ||
        (hints.includes("token") && name.includes("token")) ||
        (hints.includes("ssrf") && family.includes("ssrf"))
      );
    })
    .slice(0, 8)
    .map((pattern) => String(pattern.pattern_id ?? "unknown-tool-pattern"));
}

export function evaluateToolRequest(
  request: ToolRequest,
  context: RuntimeContext
): SafeVerdict {
  normalizeTrustSignals({
    artifactKind: "tool_manifest",
    extractionMethod: "api",
    ...(request.trustSignals ?? {})
  });

  const reasonCodes: string[] = [];
  let decision: SafeVerdict["decision"] = "ALLOW";
  let riskScore = 0.25;

  const descriptions = [request.description, ...(request.schemaDescriptions ?? [])];
  if (descriptions.some((value) => MALICIOUS_TOOL_TEXT.test(value))) {
    decision = "BLOCK";
    reasonCodes.push("MALICIOUS_TOOL_MANIFEST");
    riskScore = 0.95;
  }

  if (context.policy.forbidTokenPassthrough && request.tokenPassthroughRequested) {
    decision = "BLOCK";
    reasonCodes.push("TOKEN_PASSTHROUGH_FORBIDDEN");
    riskScore = 0.95;
  }

  if (
    context.policy.enforceExactRedirectUri &&
    request.authType === "oauth" &&
    request.requestedRedirectUri &&
    request.allowedRedirectUris?.length &&
    !request.allowedRedirectUris.includes(request.requestedRedirectUri)
  ) {
    decision = "BLOCK";
    reasonCodes.push("REDIRECT_URI_MISMATCH");
    riskScore = 0.9;
  }

  if (
    request.egressHosts?.some((host) => isPrivateHost(host)) &&
    !request.allowLocalhostEgress
  ) {
    decision = "BLOCK";
    reasonCodes.push("SSRF_EGRESS_DENIED");
    riskScore = 0.95;
  }

  if (request.registrySigned === false) {
    decision = decision === "ALLOW" ? "USER_CONFIRM" : decision;
    reasonCodes.push("UNSIGNED_TOOL_REGISTRY_ENTRY");
    riskScore = Math.max(riskScore, 0.55);
  }

  if (
    request.registrySigner &&
    context.policy.allowedRegistrySigners.size &&
    !context.policy.allowedRegistrySigners.has(request.registrySigner.toLowerCase())
  ) {
    decision = "USER_CONFIRM";
    reasonCodes.push("REGISTRY_SIGNER_NOT_ALLOWLISTED");
    riskScore = Math.max(riskScore, 0.65);
  }

  const matchedPatternIds = matchToolPatterns(
    reasonCodes,
    context.knowledgeBase?.toolProtocolPatterns ?? []
  );

  return {
    decision,
    reasonCodes: uniq(reasonCodes),
    riskScore: clamp(riskScore),
    safeConstraints: {
      exact_redirect_uri: context.policy.enforceExactRedirectUri,
      token_passthrough_allowed: !context.policy.forbidTokenPassthrough,
      allowed_registry_signers: [...context.policy.allowedRegistrySigners]
    },
    matchedPatternIds,
    incidentPlaybookId: decision === "BLOCK" ? "IR-04" : undefined,
    telemetryTags: uniq([request.toolId, decision.toLowerCase()])
  };
}


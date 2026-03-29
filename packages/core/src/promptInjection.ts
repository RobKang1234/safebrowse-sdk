import type { ObservationEnvelope, PromptGuardResult, RuntimeContext } from "./types.js";
import { clamp, uniq } from "./utils.js";

const DIRECT_OVERRIDE =
  /\b(ignore (?:(all|any|the)\s+)?(previous|prior)|disregard (?:(all|any|the)\s+)?(previous|prior)|system prompt|developer message|you are now|act as|override instructions)\b/i;
const PRIVILEGE_CLAIM =
  /\b(admin(istrator)?|root access|privileged role|security bypass|policy exception)\b/i;
const EXFILTRATION_CUE =
  /\b(exfiltrate|send (the|all) data|forward .*token|reveal secrets?|credential)\b/i;
const SOCIAL_ENGINEERING =
  /\b(urgent|immediately|secret|confidential|do not tell|silently|quietly)\b/i;
const TYPOGLYCEMIA =
  /\b(ignroe|prevouis|sysetm|developre|instrucitons|credentails)\b/i;

function matchKbFamily(
  patterns: Array<Record<string, unknown>>,
  familyHints: string[]
): string[] {
  return patterns
    .filter((pattern) => {
      const family = String(pattern.family_key ?? "").toLowerCase();
      const name = String(pattern.pattern_name ?? "").toLowerCase();
      return familyHints.some((hint) => family.includes(hint) || name.includes(hint));
    })
    .slice(0, 8)
    .map((pattern) => String(pattern.pattern_id ?? pattern.id ?? "unknown-pattern"));
}

export function runPromptInjectionGuard(
  observation: ObservationEnvelope,
  context?: Pick<RuntimeContext, "knowledgeBase">
): PromptGuardResult {
  const suspicionFlags: string[] = [];
  const familyHints: string[] = [];
  let score = observation.suspicionFlags.length ? 0.15 : 0;

  if (DIRECT_OVERRIDE.test(observation.normalizedText)) {
    suspicionFlags.push("prompt_override_language");
    familyHints.push("override");
    score += 0.35;
  }

  if (PRIVILEGE_CLAIM.test(observation.normalizedText)) {
    suspicionFlags.push("privilege_claim_language");
    familyHints.push("role");
    score += 0.2;
  }

  if (EXFILTRATION_CUE.test(observation.normalizedText)) {
    suspicionFlags.push("exfiltration_cue");
    familyHints.push("unsafe");
    score += 0.25;
  }

  if (SOCIAL_ENGINEERING.test(observation.normalizedText)) {
    suspicionFlags.push("social_engineering_pressure");
    familyHints.push("social");
    score += 0.15;
  }

  if (TYPOGLYCEMIA.test(observation.normalizedText)) {
    suspicionFlags.push("obfuscated_typoglycemia");
    familyHints.push("obfus");
    score += 0.2;
  }

  if (
    observation.fragments.some((fragment) => fragment.visibilityClass !== "visible")
  ) {
    suspicionFlags.push("non_visible_instruction_channel");
    familyHints.push("hidden");
    score += 0.2;
  }

  const matchedPatternIds = matchKbFamily(
    context?.knowledgeBase?.promptInjectionPatterns ?? [],
    uniq(familyHints)
  );

  return {
    suspicionFlags: uniq(suspicionFlags),
    matchedPatternIds,
    riskScore: clamp(score)
  };
}

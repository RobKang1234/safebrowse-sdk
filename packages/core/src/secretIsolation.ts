import type { JsonValue } from "./types.js";

const SECRET_FIELD_NAME =
  /(auth(?:orization)?(?:_|-)?code|access(?:_|-)?token|refresh(?:_|-)?token|id(?:_|-)?token|session(?:_|-)?token|api(?:_|-)?key|secret|password|credential|bearer|cookie)/i;

const SECRET_VALUE_PATTERN =
  /\b(?:sk-[a-z0-9]{12,}|gh[pousr]_[A-Za-z0-9_]{20,}|eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9._-]{10,}|npm_[A-Za-z0-9]{20,}|tok_[A-Za-z0-9]{8,}|bearer\s+[A-Za-z0-9._-]{8,})\b/gi;

const CREDENTIALISH_TEXT =
  /\b(?:authorization code|access token|refresh token|session token|api key|password|credential|secret|bearer token)\b/i;

function isJsonObject(value: JsonValue): value is Record<string, JsonValue> {
  return Boolean(value && typeof value === "object" && !Array.isArray(value));
}

export function looksLikeSecretFieldName(fieldName: string): boolean {
  return SECRET_FIELD_NAME.test(fieldName);
}

export function findSecretsInText(input: string): string[] {
  const findings: string[] = [];
  if (CREDENTIALISH_TEXT.test(input)) {
    findings.push("credentialish_text");
  }
  if (SECRET_VALUE_PATTERN.test(input)) {
    findings.push("secret_value_pattern");
  }
  return [...new Set(findings)];
}

export function redactSecretsInText(input: string): {
  text: string;
  secretFindings: string[];
} {
  const secretFindings = findSecretsInText(input);
  if (!secretFindings.length) {
    return {
      text: input,
      secretFindings
    };
  }

  return {
    text: input.replace(SECRET_VALUE_PATTERN, "[REDACTED_SECRET]"),
    secretFindings
  };
}

export function redactJsonValue(value: JsonValue): {
  value: JsonValue;
  secretFindings: string[];
} {
  if (value === null || typeof value === "number" || typeof value === "boolean") {
    return {
      value,
      secretFindings: []
    };
  }

  if (typeof value === "string") {
    const redacted = redactSecretsInText(value);
    return {
      value: redacted.text,
      secretFindings: redacted.secretFindings
    };
  }

  if (Array.isArray(value)) {
    const findings: string[] = [];
    const sanitized = value.map((entry) => {
      const result = redactJsonValue(entry);
      findings.push(...result.secretFindings);
      return result.value;
    });
    return {
      value: sanitized,
      secretFindings: [...new Set(findings)]
    };
  }

  if (!isJsonObject(value)) {
    return {
      value,
      secretFindings: []
    };
  }

  const findings: string[] = [];
  const sanitized: Record<string, JsonValue> = {};

  for (const [key, entry] of Object.entries(value)) {
    if (looksLikeSecretFieldName(key)) {
      sanitized[key] = "[REDACTED_SECRET]";
      findings.push(`field:${key}`);
      continue;
    }

    const result = redactJsonValue(entry);
    findings.push(...result.secretFindings);
    sanitized[key] = result.value;
  }

  return {
    value: sanitized,
    secretFindings: [...new Set(findings)]
  };
}

export function assertNoSecretsInJson(value: JsonValue): string[] {
  return redactJsonValue(value).secretFindings;
}

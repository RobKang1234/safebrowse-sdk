import { createHash } from "node:crypto";

export function normalizeOrigin(input?: string): string {
  if (!input) {
    return "unknown";
  }

  try {
    const value = input.includes("://") ? input : `https://${input}`;
    const url = new URL(value);
    return url.origin.toLowerCase();
  } catch {
    return input.trim().toLowerCase() || "unknown";
  }
}

function siteKey(origin: string): string {
  try {
    const host = new URL(origin).hostname.toLowerCase();
    const parts = host.split(".").filter(Boolean);
    return parts.slice(-2).join(".");
  } catch {
    const parts = origin.toLowerCase().split(".").filter(Boolean);
    return parts.slice(-2).join(".");
  }
}

export function sameOriginRelation(
  sourceOrigin: string,
  targetOrigin: string
): "same-origin" | "same-site" | "cross-site" | "cross-channel" {
  if (sourceOrigin === "unknown" || targetOrigin === "unknown") {
    return "cross-channel";
  }
  if (sourceOrigin === targetOrigin) {
    return "same-origin";
  }
  if (siteKey(sourceOrigin) === siteKey(targetOrigin)) {
    return "same-site";
  }
  return "cross-site";
}

export function normalizeText(input: string): string {
  return input
    .normalize("NFKC")
    .replace(/[\u200B-\u200D\uFEFF]/g, "")
    .replace(/\s+/g, " ")
    .trim();
}

export function tokenize(input: string): string[] {
  return normalizeText(input)
    .toLowerCase()
    .split(/[^a-z0-9]+/i)
    .filter(Boolean);
}

export function overlapScore(left: string, right: string): number {
  const a = new Set(tokenize(left));
  const b = new Set(tokenize(right));
  if (!a.size || !b.size) {
    return 0;
  }

  let hits = 0;
  for (const token of a) {
    if (b.has(token)) {
      hits += 1;
    }
  }

  return hits / Math.max(a.size, b.size);
}

export function sha256Hex(input: string | Uint8Array): string {
  return createHash("sha256").update(input).digest("hex");
}

export function stableStringify(value: unknown): string {
  if (Array.isArray(value)) {
    return `[${value.map((entry) => stableStringify(entry)).join(",")}]`;
  }

  if (value && typeof value === "object") {
    const entries = Object.entries(value as Record<string, unknown>).sort(([a], [b]) =>
      a.localeCompare(b)
    );
    return `{${entries
      .map(([key, entry]) => `${JSON.stringify(key)}:${stableStringify(entry)}`)
      .join(",")}}`;
  }

  return JSON.stringify(value);
}

export function isPrivateHost(input: string): boolean {
  const host = input.toLowerCase();
  if (host === "localhost" || host.endsWith(".local")) {
    return true;
  }

  const ipv4 = host.match(/^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/);
  if (!ipv4) {
    return false;
  }

  const first = Number(ipv4[1]);
  const second = Number(ipv4[2]);
  return (
    first === 10 ||
    first === 127 ||
    (first === 172 && second >= 16 && second <= 31) ||
    (first === 192 && second === 168)
  );
}

export function clamp(value: number, min = 0, max = 1): number {
  return Math.min(max, Math.max(min, value));
}

export function uniq<T>(values: Iterable<T>): T[] {
  return [...new Set(values)];
}


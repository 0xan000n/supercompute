import type { CanonicalRequestV1, CanonicalMessage } from "./types";

/**
 * §21 — deterministic canonicalization.
 *
 * Rules: UTF-8, Unicode NFC, stable field order, no insignificant whitespace,
 * explicit defaults, integers only (reject NaN/Infinity/floats), reject
 * duplicate keys (impossible after re-construction below).
 *
 * We serialize with a JCS-style canonical JSON: object keys sorted
 * lexicographically, no whitespace, strings NFC-normalized.
 */

export class CanonicalizationError extends Error {}

function assertSafeInteger(n: unknown, field: string): number {
  if (typeof n !== "number" || !Number.isSafeInteger(n)) {
    throw new CanonicalizationError(
      `${field} must be a safe integer (no floats/NaN/Infinity), got: ${String(n)}`
    );
  }
  return n;
}

function nfc(s: unknown, field: string): string {
  if (typeof s !== "string") {
    throw new CanonicalizationError(`${field} must be a string`);
  }
  return s.normalize("NFC");
}

const ROLES = new Set(["system", "user", "assistant"]);

/** Rebuild the request with explicit defaults + validated fields, in stable order. */
export function toCanonicalRequest(input: {
  model: string;
  messages: Array<{ role: string; content: string }>;
  temperature?: number;
  temperature_millis?: number;
  max_tokens?: number;
}): CanonicalRequestV1 {
  const model = nfc(input.model, "model");
  if (model.length === 0) throw new CanonicalizationError("model is required");

  if (!Array.isArray(input.messages) || input.messages.length === 0) {
    throw new CanonicalizationError("messages must be a non-empty array");
  }
  const messages: CanonicalMessage[] = input.messages.map((m, i) => {
    if (!ROLES.has(m.role)) {
      throw new CanonicalizationError(`messages[${i}].role invalid: ${m.role}`);
    }
    return {
      role: m.role as CanonicalMessage["role"],
      content: nfc(m.content, `messages[${i}].content`),
    };
  });

  let temperature_millis: number;
  if (input.temperature_millis !== undefined) {
    temperature_millis = assertSafeInteger(input.temperature_millis, "temperature_millis");
  } else if (input.temperature !== undefined) {
    const t = input.temperature;
    if (typeof t !== "number" || !Number.isFinite(t) || t < 0 || t > 2) {
      throw new CanonicalizationError(`temperature out of range: ${String(t)}`);
    }
    temperature_millis = Math.round(t * 1000);
  } else {
    temperature_millis = 1000; // explicit default
  }
  if (temperature_millis < 0 || temperature_millis > 2000) {
    throw new CanonicalizationError("temperature_millis must be within [0, 2000]");
  }

  const max_tokens = assertSafeInteger(input.max_tokens ?? 1024, "max_tokens");
  if (max_tokens < 1 || max_tokens > 128000) {
    throw new CanonicalizationError("max_tokens must be within [1, 128000]");
  }

  return { model, messages, temperature_millis, max_tokens };
}

/** JCS-style canonical JSON: sorted keys, no whitespace, integers only. */
export function canonicalJson(value: unknown): string {
  if (value === null) return "null";
  const t = typeof value;
  if (t === "boolean") return value ? "true" : "false";
  if (t === "number") {
    if (!Number.isSafeInteger(value)) {
      throw new CanonicalizationError(`non-integer number in canonical form: ${String(value)}`);
    }
    return String(value);
  }
  if (t === "string") return JSON.stringify((value as string).normalize("NFC"));
  if (Array.isArray(value)) {
    return `[${value.map((v) => canonicalJson(v)).join(",")}]`;
  }
  if (t === "object") {
    const obj = value as Record<string, unknown>;
    const keys = Object.keys(obj).sort();
    const parts = keys
      .filter((k) => obj[k] !== undefined)
      .map((k) => `${JSON.stringify(k)}:${canonicalJson(obj[k])}`);
    return `{${parts.join(",")}}`;
  }
  throw new CanonicalizationError(`unsupported type in canonical form: ${t}`);
}

export function canonicalBytes(request: CanonicalRequestV1): Uint8Array {
  return new TextEncoder().encode(canonicalJson(request));
}

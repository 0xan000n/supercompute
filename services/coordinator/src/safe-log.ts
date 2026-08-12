/**
 * §57 — the single logging entry point for the coordinator.
 *
 * The coordinator is untrusted with respect to prompts and credentials, so the
 * defense here is not "remember not to log secrets" but "the logger refuses".
 * Three layers, because a key-name allowlist alone is not enough:
 *
 *   1. forbidden key names, matched after normalising case and separators;
 *   2. value patterns, so a secret logged under an unlisted key is still caught;
 *   3. a length cap, so a prompt echoed into an error message cannot ride out in
 *      a field named something innocuous like `message` or `detail`.
 *
 * The marker appearing in output is itself a bug signal worth investigating.
 */
const FORBIDDEN_KEYS = new Set([
  "messages",
  "prompt",
  "prompttext",
  "input",
  "output",
  "content",
  "response",
  "responsebody",
  "body",
  // The two header names real provider credentials actually travel under:
  // `authorization: Bearer …` (OpenAI-compatible) and `x-api-key` (Anthropic).
  // Normalisation collapses `X-Api-Key` and `xApiKey` onto the same entry.
  "authorization",
  "xapikey",
  "apikey",
  "key",
  "secret",
  "encryptedsecret",
  "ciphertext",
  "enc",
  "plaintext",
  "sharedsecret",
  "dek",
  "privatekey",
  "encryptedblob",
]);

const REDACTED = "[redacted-by-safeLog]";
const TRUNCATED = "[truncated-by-safeLog]";

/**
 * Values that look like credential material, regardless of the key they arrive
 * under. Deliberately conservative — a false positive costs a log line's detail,
 * a false negative costs a secret.
 */
const SECRET_VALUE_PATTERNS = [
  // Covers real key material as issued: `sk-ant-api03-…` (Anthropic) and
  // `sk-…` / `sk-proj-…` (OpenAI). The `\b` matters — without it the pattern
  // also fires on ordinary prose like "risk-assessment-framework", and a
  // redaction that eats useful log lines gets loosened by the next person.
  /\bsk-[A-Za-z0-9_-]{8,}/,
  /\bBearer\s+\S+/i,
  /\bmock-provider-key-\S+/,
  /\bsk_live_\S+/,
  /\bghp_[A-Za-z0-9]{20,}/,
];

/**
 * Long strings are the shape a prompt takes when it leaks. Identifiers, hashes,
 * status codes and error summaries are all comfortably shorter than this.
 */
const MAX_STRING_LENGTH = 200;

/** Lowercase and strip separators so casing and snake/camel cannot evade. */
const normalizeKey = (key: string) => key.toLowerCase().replace(/[^a-z0-9]/g, "");

function scrubString(value: string): string {
  if (SECRET_VALUE_PATTERNS.some((pattern) => pattern.test(value))) return REDACTED;
  if (value.length > MAX_STRING_LENGTH) {
    return `${value.slice(0, 64)}… ${TRUNCATED} (${value.length} chars)`;
  }
  return value;
}

export function redact(value: unknown, depth = 0): unknown {
  if (depth > 8) return "[depth-limit]";
  if (typeof value === "string") return scrubString(value);
  if (value === null || typeof value !== "object") return value;
  if (Array.isArray(value)) return value.map((v) => redact(v, depth + 1));

  const out: Record<string, unknown> = {};
  for (const [k, v] of Object.entries(value as Record<string, unknown>)) {
    out[k] = FORBIDDEN_KEYS.has(normalizeKey(k)) ? REDACTED : redact(v, depth + 1);
  }
  return out;
}

export type LogLevel = "info" | "warn" | "error";

export function safeLog(level: LogLevel, event: string, fields: Record<string, unknown> = {}): void {
  const line = JSON.stringify({
    at: new Date().toISOString(),
    level,
    event,
    ...(redact(fields) as Record<string, unknown>),
  });
  if (level === "error") console.error(line);
  else if (level === "warn") console.warn(line);
  else console.log(line);
}

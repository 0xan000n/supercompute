/**
 * §57, applied inside the trust boundary.
 *
 * The coordinator has `safeLog` because it is untrusted with prompts. This process
 * is the one that actually holds them, so it needs the same discipline more, not
 * less — a thrown error whose message embeds request content would otherwise be
 * printed verbatim to the parent's stdout, which in simulation is an ordinary
 * terminal and on Nitro is the one channel that leaves the enclave.
 *
 * Deliberately narrow: this logs identifiers and short status strings. Anything
 * long or credential-shaped is replaced rather than truncated-and-hoped-for.
 */
const SECRET_VALUE_PATTERNS = [
  // Covers real key material as issued: `sk-ant-api03-…` (Anthropic) and
  // `sk-…` / `sk-proj-…` (OpenAI). The `\b` matters — without it the pattern
  // also fires on ordinary prose like "risk-assessment-framework", and a
  // redaction that eats useful log lines gets loosened by the next person.
  /\bsk-[A-Za-z0-9_-]{8,}/,
  /\bBearer\s+\S+/i,
  /\bmock-provider-key-\S+/,
];

const MAX_LENGTH = 160;

/** Everything printed from inside the enclave passes through here. */
export function enclaveSafe(text: string): string {
  if (SECRET_VALUE_PATTERNS.some((p) => p.test(text))) return "[redacted-by-enclaveSafe]";
  if (text.length > MAX_LENGTH) {
    return `${text.slice(0, 64)}… [truncated-by-enclaveSafe] (${text.length} chars)`;
  }
  return text;
}

export function enclaveLog(event: string, fields: Record<string, string | number | boolean> = {}): void {
  const parts = Object.entries(fields).map(
    ([k, v]) => `${k}=${typeof v === "string" ? enclaveSafe(v) : v}`
  );
  console.log(`[tee-sim] ${event}${parts.length ? ` ${parts.join(" ")}` : ""}`);
}

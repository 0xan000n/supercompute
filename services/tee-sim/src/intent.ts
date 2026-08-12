/**
 * §5.1 — the sealed intent is the ONLY authority on a credential's
 * capability. This module is pure: parse + derive, no I/O, so the
 * tamper-resistance property is unit-testable in isolation.
 */
import {
  intentDigest,
  type CredentialCapability,
  type CredentialIntentV1,
} from "@ctn/protocol";
import type { MODEL_CATALOG } from "./catalog.js";

export class InvalidIntentError extends Error {
  readonly code = "CTN_INVALID_ENVELOPE";
}

const INTENT_KEYS = [
  "version", "credentialId", "secret", "provider",
  "allowedModels", "allowedPolicies", "contributorId", "intentNonce",
].sort();
const SUPPORTED_POLICIES = ["safety-v1"];
const MAX_MODELS = 8;
const MAX_ID_LENGTH = 64;

export function parseIntent(
  plaintext: Uint8Array,
  catalog: typeof MODEL_CATALOG
): CredentialIntentV1 {
  let parsed: unknown;
  try {
    parsed = JSON.parse(new TextDecoder().decode(plaintext));
  } catch {
    // Never echo the plaintext: it may be a raw key pasted without sealing.
    throw new InvalidIntentError("sealed intent is not valid JSON");
  }
  if (typeof parsed !== "object" || parsed === null || Array.isArray(parsed))
    throw new InvalidIntentError("sealed intent must be an object");
  // Exact schema: unknown fields are rejected, not ignored — an ignored field
  // is a field somebody will eventually trust without the enclave checking it.
  const keys = Object.keys(parsed).sort();
  if (JSON.stringify(keys) !== JSON.stringify(INTENT_KEYS))
    throw new InvalidIntentError("sealed intent has missing or unexpected fields");

  const i = parsed as CredentialIntentV1;
  if (i.version !== 1) throw new InvalidIntentError("unsupported intent version");
  if (typeof i.credentialId !== "string" || !/^cred_[0-9a-f]{12}$/.test(i.credentialId))
    throw new InvalidIntentError("credentialId must be cred_ + 12 hex chars");
  if (typeof i.secret !== "string" || i.secret.trim().length < 8 || /\s/.test(i.secret.trim()))
    throw new InvalidIntentError("credential does not look like an API key");
  // hasOwnProperty, not `in`: `in` reaches Object.prototype, so "constructor"
  // and friends would pass as providers and hand the model check a function.
  if (typeof i.provider !== "string" || !Object.prototype.hasOwnProperty.call(catalog, i.provider))
    throw new InvalidIntentError("provider is not implemented");
  const models = catalog[i.provider as keyof typeof catalog] as readonly string[];
  if (
    !Array.isArray(i.allowedModels) ||
    i.allowedModels.length === 0 ||
    i.allowedModels.length > MAX_MODELS ||
    !i.allowedModels.every((m) => typeof m === "string" && models.includes(m)) ||
    new Set(i.allowedModels).size !== i.allowedModels.length
  )
    throw new InvalidIntentError("allowedModels must be unique pinned snapshot ids from this provider's catalog");
  if (
    !Array.isArray(i.allowedPolicies) ||
    i.allowedPolicies.length === 0 ||
    !i.allowedPolicies.every((p) => SUPPORTED_POLICIES.includes(p)) ||
    new Set(i.allowedPolicies).size !== i.allowedPolicies.length
  )
    throw new InvalidIntentError("allowedPolicies must be supported policy labels");
  if (typeof i.contributorId !== "string" || i.contributorId.length === 0 || i.contributorId.length > MAX_ID_LENGTH)
    throw new InvalidIntentError("contributorId must be 1-64 chars");
  if (typeof i.intentNonce !== "string" || !/^[0-9a-f]{64}$/.test(i.intentNonce))
    throw new InvalidIntentError("intentNonce must be 32 bytes of hex");
  return { ...i, secret: i.secret.trim() };
}

export function deriveCapability(input: {
  intent: CredentialIntentV1;
  blobDigest: string;
  resolvePolicyId: (label: string) => string;
  now: number;
}): CredentialCapability {
  const { intent } = input;
  return {
    credentialId: intent.credentialId,
    provider: intent.provider,
    allowedModels: [...intent.allowedModels].sort(),
    // Contributors opt into an exact policy version, not a mutable label (§24).
    allowedPolicyIds: intent.allowedPolicies.map(input.resolvePolicyId),
    contributorId: intent.contributorId,
    createdAt: input.now,
    version: 1,
    blobDigest: input.blobDigest,
    intentDigest: intentDigest(intent),
  };
}

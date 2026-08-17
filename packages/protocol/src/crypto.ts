import { sha256, sha512 } from "@noble/hashes/sha2.js";
import * as ed from "@noble/ed25519";
import { canonicalJson } from "./canonical";
import type {
  CredentialIntentV1,
  PolicyDecisionReceiptV1,
  ProofArtifactV1,
  ProofArtifactWireV1,
} from "./types";

// Wire noble-ed25519 v3 to noble-hashes sha512 (enables sync sign/verify).
ed.hashes.sha512 = sha512;

export const utf8 = (s: string): Uint8Array => new TextEncoder().encode(s);

export function toHex(bytes: Uint8Array): string {
  return Array.from(bytes, (b) => b.toString(16).padStart(2, "0")).join("");
}

export function fromHex(hex: string): Uint8Array {
  const clean = hex.startsWith("0x") ? hex.slice(2) : hex;
  if (clean.length % 2 !== 0 || /[^0-9a-fA-F]/.test(clean)) {
    throw new Error("invalid hex");
  }
  const out = new Uint8Array(clean.length / 2);
  for (let i = 0; i < out.length; i++) {
    out[i] = parseInt(clean.slice(i * 2, i * 2 + 2), 16);
  }
  return out;
}

export function toB64(bytes: Uint8Array): string {
  if (typeof Buffer !== "undefined") return Buffer.from(bytes).toString("base64");
  let s = "";
  for (const b of bytes) s += String.fromCharCode(b);
  return btoa(s);
}

export function fromB64(b64: string): Uint8Array {
  if (typeof Buffer !== "undefined") return new Uint8Array(Buffer.from(b64, "base64"));
  const s = atob(b64);
  const out = new Uint8Array(s.length);
  for (let i = 0; i < s.length; i++) out[i] = s.charCodeAt(i);
  return out;
}

export function sha256Hex(data: Uint8Array | string): string {
  return toHex(sha256(typeof data === "string" ? utf8(data) : data));
}

/** Hash any JSON value via its canonical serialization. */
export function canonicalHash(value: unknown): string {
  return sha256Hex(canonicalJson(value));
}

const COMMITMENT_DOMAIN = "CTN_REQUEST_V1";

/** §21 — request_commitment = SHA256(domain || canonical_bytes || nonce). */
export function requestCommitment(canonical: Uint8Array, nonceHex: string): string {
  const nonce = fromHex(nonceHex);
  if (nonce.length !== 32) throw new Error("request nonce must be 32 bytes");
  const domain = utf8(COMMITMENT_DOMAIN);
  const buf = new Uint8Array(domain.length + canonical.length + nonce.length);
  buf.set(domain, 0);
  buf.set(canonical, domain.length);
  buf.set(nonce, domain.length + canonical.length);
  return "0x" + toHex(sha256(buf));
}

const INTENT_DOMAIN = "CTN_INTENT_V1";

/** Digest of the canonical intent MINUS the secret, domain-separated. */
export function intentDigest(intent: CredentialIntentV1): string {
  const { secret: _secret, ...publicIntent } = intent;
  const canonical = utf8(canonicalJson(publicIntent));
  const domain = utf8(INTENT_DOMAIN);
  const buf = new Uint8Array(domain.length + canonical.length);
  buf.set(domain, 0);
  buf.set(canonical, domain.length);
  return "0x" + toHex(sha256(buf));
}

// ---------------------------------------------------------------------------
// Phase 2b §4 — domain-separated digests for the proof artifact and its binding.
// Each is a raw-byte concatenation of a fixed domain label with the material,
// matching the request-commitment construction above. "0x"-prefixed lowercase
// hex, so a verifier (Task 5) reproduces the exact same string.
// ---------------------------------------------------------------------------

const ZK_RECEIPT_DOMAIN = "CTN_ZK_RECEIPT_V1";

/** artifactDigest = SHA256("CTN_ZK_RECEIPT_V1" ‖ receiptBytes). Over the RAW bincode bytes. */
export function zkArtifactDigest(receiptBytes: Uint8Array): string {
  const domain = utf8(ZK_RECEIPT_DOMAIN);
  const buf = new Uint8Array(domain.length + receiptBytes.length);
  buf.set(domain, 0);
  buf.set(receiptBytes, domain.length);
  return "0x" + toHex(sha256(buf));
}

const DECISION_RECEIPT_DOMAIN = "CTN_DECISION_RECEIPT_V1";

/** decisionReceiptDigest = SHA256("CTN_DECISION_RECEIPT_V1" ‖ canonical(PolicyDecisionReceiptV1)). */
export function decisionReceiptDigest(receipt: PolicyDecisionReceiptV1): string {
  const canonical = utf8(canonicalJson(receipt));
  const domain = utf8(DECISION_RECEIPT_DOMAIN);
  const buf = new Uint8Array(domain.length + canonical.length);
  buf.set(domain, 0);
  buf.set(canonical, domain.length);
  return "0x" + toHex(sha256(buf));
}

/** JSON/SQLite transport <-> in-enclave form for a ProofArtifactV1 (Uint8Array <-> base64). */
export function artifactToWire(artifact: ProofArtifactV1): ProofArtifactWireV1 {
  const { receiptBytes, ...rest } = artifact;
  return { ...rest, receiptB64: toB64(receiptBytes) };
}

export function artifactFromWire(wire: ProofArtifactWireV1): ProofArtifactV1 {
  const { receiptB64, ...rest } = wire;
  return { ...rest, receiptBytes: fromB64(receiptB64) };
}

// ---------------------------------------------------------------------------
// Ed25519 signing (enclave receipt key, prover key, platform key)
// ---------------------------------------------------------------------------

export interface SigningKeyPair {
  privateKey: Uint8Array;
  publicKey: Uint8Array;
}

export function generateSigningKeyPair(): SigningKeyPair {
  const { secretKey, publicKey } = ed.keygen();
  return { privateKey: secretKey, publicKey };
}

export function signDigestHex(digestHex: string, privateKey: Uint8Array): string {
  return toHex(ed.sign(fromHex(digestHex), privateKey));
}

export function verifyDigestHex(
  digestHex: string,
  signatureHex: string,
  publicKeyHex: string
): boolean {
  try {
    return ed.verify(fromHex(signatureHex), fromHex(digestHex), fromHex(publicKeyHex));
  } catch {
    return false;
  }
}

/** Sign canonical JSON of a value: signature over SHA256(canonical(value)). */
export function signCanonical(value: unknown, privateKey: Uint8Array): string {
  return signDigestHex(canonicalHash(value), privateKey);
}

export function verifyCanonical(
  value: unknown,
  signatureHex: string,
  publicKeyHex: string
): boolean {
  return verifyDigestHex(canonicalHash(value), signatureHex, publicKeyHex);
}

export function randomHex(bytes: number): string {
  const buf = new Uint8Array(bytes);
  globalThis.crypto.getRandomValues(buf);
  return toHex(buf);
}

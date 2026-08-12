import { sha256, sha512 } from "@noble/hashes/sha2.js";
import * as ed from "@noble/ed25519";
import { canonicalJson } from "./canonical";

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

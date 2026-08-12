/**
 * §9B — compatibility endpoint plumbing.
 *
 * READ THIS BEFORE USING THE COMPATIBILITY ENDPOINT.
 *
 * This module exists so unmodified OpenAI SDKs can talk to the network. To do
 * that, the coordinator has to hold the plaintext prompt in memory long enough
 * to encrypt it to the enclave, and hold the response key long enough to decrypt
 * the reply. That is a genuinely weaker privacy posture, and it is why the demo
 * defaults to the secure endpoint and why every response from this path carries
 * privacy_mode = compatibility.
 *
 * Nothing here persists or logs the plaintext, and the ephemeral response key is
 * discarded immediately after use — but "the operator cannot see your prompt" is
 * NOT a claim this endpoint can make. Only /v1/secure/chat/completions can.
 *
 * The spec's path to fixing this (§9) is terminating TLS inside the enclave via
 * an inbound TCP→vsock relay, at which point this module is deleted rather than
 * improved.
 */
import { randomUUID } from "node:crypto";
import {
  generateHpkeKeyPair,
  hpkeSeal,
  hpkeOpen,
  canonicalJson,
  randomHex,
  toCanonicalRequest,
  type SecureRequestEnvelope,
  type SecurePayload,
} from "@ctn/protocol";
import { teeClient } from "./tee-client.js";

/** Ephemeral response keys, keyed by requestId and deleted on first use. */
const responseKeys = new Map<string, string>();

export async function buildSecureEnvelope(body: {
  model?: string;
  messages?: Array<{ role: string; content: string }>;
  temperature?: number;
  max_tokens?: number;
}): Promise<SecureRequestEnvelope> {
  const attestation = await teeClient.attestation();
  const canonical = toCanonicalRequest({
    model: body.model!,
    messages: body.messages!,
    temperature: body.temperature,
    max_tokens: body.max_tokens,
  });

  const responseKeyPair = await generateHpkeKeyPair();
  const requestId = `req_${randomUUID().replace(/-/g, "")}`;
  responseKeys.set(requestId, responseKeyPair.privateKeyB64);

  const payload: SecurePayload = {
    request: canonical,
    requestNonce: randomHex(32),
    responsePublicKey: responseKeyPair.publicKeyB64,
  };

  const aad = {
    apiVersion: "v1" as const,
    requestedPolicy: "safety-v1" as const,
    model: canonical.model,
  };
  const sealed = await hpkeSeal(
    attestation.bundle.ingressPublicKey,
    new TextEncoder().encode(JSON.stringify(payload)),
    new TextEncoder().encode(canonicalJson(aad))
  );

  return {
    version: "ctn-1",
    requestId,
    enclaveKeyId: attestation.bundle.enclaveKeyId,
    enc: sealed.enc,
    ciphertext: sealed.ciphertext,
    aad,
  };
}

export async function openResponse(
  requestId: string,
  encrypted: { enc: string; ciphertext: string }
): Promise<{
  model: string;
  content: string;
  usage: { inputTokens: number; outputTokens: number };
}> {
  const privateKey = responseKeys.get(requestId);
  responseKeys.delete(requestId);
  if (!privateKey) throw new Error("no response key for request");
  const opened = await hpkeOpen(privateKey, encrypted);
  return JSON.parse(new TextDecoder().decode(opened)) as {
    model: string;
    content: string;
    usage: { inputTokens: number; outputTokens: number };
  };
}

/**
 * §10 — the secure client. Runs in the browser and in Node with identical code.
 *
 * The client is the ONLY party besides the enclave and the upstream provider
 * that ever holds the plaintext. It:
 *   1. fetches the enclave attestation and verifies key binding,
 *   2. canonicalizes the request,
 *   3. HPKE-seals it to the attested ingress key,
 *   4. sends only ciphertext,
 *   5. decrypts the response with its own ephemeral key.
 */
import {
  canonicalJson,
  generateHpkeKeyPair,
  hpkeOpen,
  hpkeSeal,
  randomHex,
  toCanonicalRequest,
  verifyCanonical,
  type AttestationBundle,
  type SecurePayload,
  type SecureRequestEnvelope,
  type SignedComputeReceipt,
} from "@ctn/protocol";

export interface AttestationEnvelope {
  bundle: AttestationBundle;
  verification: { valid: boolean; checks: Array<{ name: string; pass: boolean; detail?: string }> };
  policy: { policyId: string; guestImageId: string; name: string; version: string; normalizer: string };
  attestationDigest: string;
}

export interface CompletionResult {
  requestId: string;
  content: string;
  model: string;
  usage: { inputTokens: number; outputTokens: number };
  commitment: string;
  receipt: SignedComputeReceipt | null;
  receiptId: string | null;
  route: {
    provider: string;
    model: string;
    contributor_id: string;
    credential_id: string;
    attempt: number;
  } | null;
  timings: Record<string, number | undefined>;
  trustStatus: string;
}

export class PolicyDeniedError extends Error {
  constructor(
    readonly policyId: string,
    readonly requestId: string,
    readonly commitment?: string
  ) {
    super("Request was not eligible under Safety Policy v1.");
    this.name = "PolicyDeniedError";
  }
}

export class CtnApiError extends Error {
  constructor(
    readonly code: string,
    message: string,
    readonly requestId?: string
  ) {
    super(message);
    this.name = "CtnApiError";
  }
}

/**
 * Verifies the attestation the client is about to trust its plaintext to.
 *
 * The critical check is key binding: the ingress key we encrypt to must be the
 * key inside the attested document. Without that, an attacker who can serve the
 * attestation response could substitute their own key and read everything.
 */
export function verifyAttestationBundle(
  env: AttestationEnvelope,
  /** The nonce this caller asked for, if any. Checked for freshness when given. */
  expectedNonce?: string
): {
  keyBindingValid: boolean;
  documentSignatureValid: boolean;
  nonceFresh: boolean;
  hardwareBacked: boolean;
  valid: boolean;
  checks: Array<{ name: string; pass: boolean; detail?: string }>;
} {
  const { bundle } = env;
  const { platformSignature, ...unsigned } = bundle.document;

  // The nonce is part of the signed bytes, so it must come from the bundle. An
  // earlier version hardcoded null here, which meant every nonce-bearing
  // attestation failed verification — and the onboarding flow, which always
  // sends a nonce, could never complete.
  const documentSignatureValid = verifyCanonical(
    { ...unsigned, platformSignature: undefined, nonce: bundle.nonce ?? null },
    platformSignature,
    bundle.enclaveSigningPublicKey
  );
  const keyBindingValid =
    bundle.document.userData.ingressPublicKey === bundle.ingressPublicKey &&
    bundle.document.userData.signingPublicKey === bundle.enclaveSigningPublicKey;

  // A nonce only buys freshness if the caller actually checks it came back.
  const nonceFresh = expectedNonce === undefined || bundle.nonce === expectedNonce;

  const checks = [
    { name: "attestation document signature valid", pass: documentSignatureValid },
    { name: "attested keys equal presented keys", pass: keyBindingValid },
    ...(expectedNonce !== undefined
      ? [{ name: "attestation is fresh for this request's nonce", pass: nonceFresh }]
      : []),
    {
      name: "hardware root of trust",
      pass: bundle.teeMode === "nitro",
      detail:
        bundle.teeMode === "nitro"
          ? "AWS Nitro"
          : "SIMULATED — key binding verified, no hardware isolation",
    },
  ];

  return {
    keyBindingValid,
    documentSignatureValid,
    nonceFresh,
    hardwareBacked: bundle.teeMode === "nitro",
    // Cryptographic validity only. The hardware check is reported separately so
    // simulation can never be silently presented as hardware-backed.
    valid: documentSignatureValid && keyBindingValid && nonceFresh,
    checks,
  };
}

export class ComputeTrustClient {
  constructor(private readonly baseUrl: string = "http://127.0.0.1:4200") {}

  async attestation(nonce?: string): Promise<AttestationEnvelope> {
    const res = await fetch(
      `${this.baseUrl}/v1/attestation${nonce ? `?nonce=${encodeURIComponent(nonce)}` : ""}`
    );
    if (!res.ok) throw new CtnApiError("CTN_ENCLAVE_UNAVAILABLE", "attestation unavailable");
    return (await res.json()) as AttestationEnvelope;
  }

  async models(): Promise<{ data: Array<Record<string, unknown>> }> {
    const res = await fetch(`${this.baseUrl}/v1/models`);
    return (await res.json()) as { data: Array<Record<string, unknown>> };
  }

  /** Builds a sealed envelope. Exposed so callers can inspect exactly what is sent. */
  async sealRequest(
    attestation: AttestationEnvelope,
    input: {
      model: string;
      messages: Array<{ role: string; content: string }>;
      temperature?: number;
      max_tokens?: number;
    }
  ): Promise<{ envelope: SecureRequestEnvelope; responsePrivateKey: string; nonce: string }> {
    const canonical = toCanonicalRequest(input);
    const responseKeyPair = await generateHpkeKeyPair();
    const nonce = randomHex(32);

    const payload: SecurePayload = {
      request: canonical,
      requestNonce: nonce,
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
      envelope: {
        version: "ctn-1",
        requestId: `req_${randomHex(16)}`,
        enclaveKeyId: attestation.bundle.enclaveKeyId,
        enc: sealed.enc,
        ciphertext: sealed.ciphertext,
        aad,
      },
      responsePrivateKey: responseKeyPair.privateKeyB64,
      nonce,
    };
  }

  async completion(input: {
    model: string;
    messages: Array<{ role: string; content: string }>;
    temperature?: number;
    max_tokens?: number;
    attestation?: AttestationEnvelope;
  }): Promise<CompletionResult> {
    const attestation = input.attestation ?? (await this.attestation());
    if (!verifyAttestationBundle(attestation).valid) {
      throw new CtnApiError(
        "CTN_ATTESTATION_REQUIRED",
        "refusing to encrypt: enclave attestation failed verification"
      );
    }

    const { envelope, responsePrivateKey } = await this.sealRequest(attestation, input);

    const res = await fetch(`${this.baseUrl}/v1/secure/chat/completions`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ envelope }),
    });
    const json = (await res.json()) as Record<string, unknown>;

    if (!res.ok) {
      const error = json.error as { code: string; message: string; policy_id?: string } | undefined;
      if (error?.code === "CTN_POLICY_DENIED") {
        throw new PolicyDeniedError(
          error.policy_id ?? "",
          envelope.requestId,
          json.request_commitment as string | undefined
        );
      }
      throw new CtnApiError(error?.code ?? "CTN_INTERNAL", error?.message ?? "request failed", envelope.requestId);
    }

    const encrypted = json.encrypted_response as { enc: string; ciphertext: string };
    const opened = await hpkeOpen(responsePrivateKey, encrypted);
    const decoded = JSON.parse(new TextDecoder().decode(opened)) as {
      model: string;
      content: string;
      usage: { inputTokens: number; outputTokens: number };
    };

    const receipt = json.receipt as Record<string, unknown> | undefined;
    return {
      requestId: envelope.requestId,
      content: decoded.content,
      model: decoded.model,
      usage: decoded.usage,
      commitment: (receipt?.request_commitment as string) ?? "",
      receipt: (receipt?.signed_receipt as SignedComputeReceipt) ?? null,
      receiptId: (receipt?.receipt_id as string) ?? null,
      route: (json.route as CompletionResult["route"]) ?? null,
      timings: (json.timings as Record<string, number>) ?? {},
      trustStatus: (json.trust_status as string) ?? "UNKNOWN",
    };
  }

  /** §34 — run a policy test without revealing the prompt to the network. */
  async policyTest(prompt: string, model = "ctn/demo-model-a"): Promise<{
    testId: string;
    decision: "ALLOW" | "DENY";
    commitment: string;
    policyId: string;
    policyMs: number;
    proofStarted: boolean;
  }> {
    const attestation = await this.attestation();
    const { envelope } = await this.sealRequest(attestation, {
      model,
      messages: [{ role: "user", content: prompt }],
    });
    const res = await fetch(`${this.baseUrl}/v1/policy/test`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ envelope }),
    });
    const json = (await res.json()) as Record<string, unknown>;
    if (!res.ok) {
      const error = json.error as { code: string; message: string };
      throw new CtnApiError(error.code, error.message);
    }
    return json as never;
  }

  /** §12 — encrypt a contributed credential in the browser, to the attested key. */
  async contributeCredential(input: {
    contributorId: string;
    label: string;
    provider: string;
    apiKey: string;
    allowedModels: string[];
    weight?: number;
    operationalLimits?: { dailyUsd?: number; dailyRequests?: number };
    attestation?: AttestationEnvelope;
  }): Promise<Record<string, unknown>> {
    const attestation = input.attestation ?? (await this.attestation());
    if (!verifyAttestationBundle(attestation).valid) {
      throw new CtnApiError(
        "CTN_ATTESTATION_REQUIRED",
        "refusing to encrypt credential: enclave attestation failed verification"
      );
    }

    // The raw key is sealed here, in the contributor's own browser. Only
    // ciphertext is posted to the coordinator (§12).
    const sealed = await hpkeSeal(
      attestation.bundle.ingressPublicKey,
      new TextEncoder().encode(input.apiKey)
    );

    const res = await fetch(`${this.baseUrl}/v1/credentials`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({
        contributorId: input.contributorId,
        label: input.label,
        provider: input.provider,
        allowedModels: input.allowedModels,
        allowedPolicies: ["safety-v1"],
        weight: input.weight ?? 1,
        operationalLimits: input.operationalLimits,
        enclaveKeyId: attestation.bundle.enclaveKeyId,
        enc: sealed.enc,
        encryptedSecret: sealed.ciphertext,
      }),
    });
    const json = (await res.json()) as Record<string, unknown>;
    if (!res.ok) {
      const error = json.error as { code: string; message: string };
      throw new CtnApiError(error.code, error.message);
    }
    return json;
  }

  async receipt(requestId: string): Promise<Record<string, unknown>> {
    const res = await fetch(`${this.baseUrl}/v1/requests/${requestId}/receipt`);
    return (await res.json()) as Record<string, unknown>;
  }

  async proof(requestId: string): Promise<Record<string, unknown>> {
    const res = await fetch(`${this.baseUrl}/v1/requests/${requestId}/proof`);
    return (await res.json()) as Record<string, unknown>;
  }

  /** Polls until the proof settles — proving finishes after inference by design (§32). */
  async waitForProof(requestId: string, timeoutMs = 60_000): Promise<Record<string, unknown>> {
    const deadline = Date.now() + timeoutMs;
    for (;;) {
      const proof = await this.proof(requestId);
      const status = proof.proof_status as string;
      if (status && status !== "PROVING" && status !== "QUEUED") return proof;
      if (Date.now() > deadline) return proof;
      await new Promise((r) => setTimeout(r, 300));
    }
  }
}

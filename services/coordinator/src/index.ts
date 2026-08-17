/**
 * The public coordinator (§5). Untrusted with respect to plaintext prompts and
 * raw credentials: it authenticates callers, assigns request IDs, discovers
 * candidate capacity from visible metadata, relays ciphertext to the enclave,
 * records non-sensitive metadata, and serves the graph.
 *
 * Everything it stores about a request is an ID, a hash, a status or a timing.
 */
import Fastify from "fastify";
import cors from "@fastify/cors";
import { randomUUID } from "node:crypto";
import { loadPolicyPackage } from "@ctn/policy";
import type { SecureRequestEnvelope } from "@ctn/protocol";
import { db, migrate, nowIso, today } from "./db.js";
import { safeLog } from "./safe-log.js";
import { bus, emitEvent, graphSnapshot, startProjector } from "./events.js";
import { applyAttemptOutcome, discoverCandidates, recordAssumedUsage, recordUsage } from "./routing.js";
import {
  EnclaveRejectionError,
  EnclaveUnavailableError,
  teeClient,
  type ExecuteResult,
} from "./tee-client.js";

const PORT = Number(process.env.COORDINATOR_PORT ?? 4200);
const CTN_ENV = process.env.CTN_ENV ?? "local";
const pkg = loadPolicyPackage();

migrate();
startProjector();

const app = Fastify({ logger: false, bodyLimit: 4 * 1024 * 1024 });
await app.register(cors, { origin: true });

app.setErrorHandler((err: Error, request, reply) => {
  // safeLog, not the raw error object: request bodies here can contain envelopes.
  safeLog("error", "coordinator.unhandled_error", {
    method: request.method,
    url: request.url,
    message: err.message,
  });
  reply.code(500).send({ error: { code: "CTN_INTERNAL", message: err.message } });
});

/**
 * Presentation only — labels and tiers for ids the enclave's catalog publishes.
 * The catalog decides WHICH models exist; this decides what they are called in a
 * picker. An id missing from here still lists, under its own name.
 */
const MODEL_META: Record<string, { label: string; tier: string }> = {
  "ctn/demo-model-a": { label: "Demo Model A", tier: "standard" },
  "ctn/demo-model-b": { label: "Demo Model B", tier: "frontier" },
  "ctn/demo-model-fast": { label: "Demo Model Fast", tier: "fast" },
  "claude-haiku-4-5-20251001": { label: "Claude Haiku 4.5", tier: "fast" },
  "claude-sonnet-4-5-20250929": { label: "Claude Sonnet 4.5", tier: "frontier" },
  "gpt-4o-mini-2024-07-18": { label: "GPT-4o mini", tier: "fast" },
  "gpt-4o-2024-08-06": { label: "GPT-4o", tier: "frontier" },
};

app.get("/health", async () => ({ ok: true, service: "coordinator", env: CTN_ENV }));

// ---------------------------------------------------------------------------
// §8 — models. Never reveals which contributor keys exist.
// ---------------------------------------------------------------------------

app.get("/v1/models", async () => {
  const counts = db
    .prepare(
      `SELECT capability_json FROM credentials WHERE status = 'ACTIVE'`
    )
    .all() as unknown as Array<{ capability_json: string }>;

  const available = new Map<string, number>();
  for (const row of counts) {
    const capability = JSON.parse(row.capability_json) as { allowedModels: string[] };
    for (const model of capability.allowedModels) {
      available.set(model, (available.get(model) ?? 0) + 1);
    }
  }

  /**
   * The id list comes from the enclave's catalog, not a literal here. It used to
   * be three hardcoded demo ids, which meant a contributor could seal a
   * capability for `claude-haiku-4-5-20251001` and the playground would show it
   * with no contributor count at all — the two endpoints describing the same
   * network disagreed about what was on it.
   *
   * If the enclave is unreachable, fall back to the ids we can still see capacity
   * for rather than 503-ing: this endpoint's job is "what can I ask for", and a
   * partial honest answer beats none. The counts are computed locally either way.
   */
  let ids: string[];
  try {
    ids = (await teeClient.providers()).providers.flatMap((p) => p.models);
  } catch {
    ids = [...available.keys()].sort();
  }

  return {
    object: "list",
    data: ids.map((id) => ({
      id,
      object: "model",
      label: MODEL_META[id]?.label ?? id,
      tier: MODEL_META[id]?.tier ?? "standard",
      // A count, deliberately — not an enumeration of whose capacity it is.
      providers_available: available.get(id) ?? 0,
      trust_policy: "safety-v1",
    })),
  };
});

/**
 * §5.1 — the provider catalog, relayed from the enclave.
 *
 * This is what the contribute page offers and what the playground selects from.
 * It comes from the enclave's registry because the enclave is what enforces it:
 * a sealed intent naming a provider or a model that is not in this list is
 * refused at ingest, so publishing anything else here would only invite
 * contributors to mint capabilities that cannot be honoured.
 */
app.get("/v1/providers", async (_request, reply) => {
  try {
    return await teeClient.providers();
  } catch {
    return reply.code(503).send({
      error: { code: "CTN_ENCLAVE_UNAVAILABLE", message: "The confidential service is unavailable." },
    });
  }
});

// ---------------------------------------------------------------------------
// §11 — attestation, relayed from the enclave
// ---------------------------------------------------------------------------

app.get("/v1/attestation", async (request, reply) => {
  const nonce = (request.query as { nonce?: string }).nonce;
  try {
    return await teeClient.attestation(nonce);
  } catch (err) {
    return reply.code(503).send({
      error: { code: "CTN_ENCLAVE_UNAVAILABLE", message: "The confidential service is unavailable." },
    });
  }
});

app.get("/v1/build-manifest", async (request, reply) => {
  try {
    const manifest = await teeClient.buildManifest();
    return { ...manifest, env: CTN_ENV, coordinatorPolicyId: pkg.policyId };
  } catch {
    return reply.code(503).send({
      error: { code: "CTN_ENCLAVE_UNAVAILABLE", message: "The confidential service is unavailable." },
    });
  }
});

// ---------------------------------------------------------------------------
// §12, §13 — contributors and credential onboarding
// ---------------------------------------------------------------------------

app.post("/v1/contributors", async (request) => {
  const { displayName } = request.body as { displayName: string };
  const id = `contrib_${randomUUID().replace(/-/g, "").slice(0, 12)}`;
  db.prepare(
    `INSERT INTO contributors (id, display_name, status, created_at) VALUES (?, ?, 'ACTIVE', ?)`
  ).run(id, displayName, nowIso());
  emitEvent("contributor.created", id, { contributor_id: id, display_name: displayName });
  safeLog("info", "contributor.created", { contributor_id: id });
  return { id, displayName, status: "ACTIVE" };
});

app.get("/v1/contributors", async () => {
  const rows = db
    .prepare(
      `SELECT c.id, c.display_name, c.status, c.created_at,
              (SELECT COUNT(*) FROM credentials cr WHERE cr.contributor_id = c.id) AS credential_count
         FROM contributors c ORDER BY c.created_at`
    )
    .all() as unknown as Array<Record<string, unknown>>;
  return { data: rows };
});

app.post("/v1/credentials", async (request, reply) => {
  const body = request.body as {
    contributorId: string;
    label: string;
    weight?: number;
    operationalLimits?: { dailyUsd?: number; dailyRequests?: number };
    credentialId: string;
    enclaveKeyId: string;
    enc: string;
    encryptedSecret: string;
  };

  const contributor = db.prepare(`SELECT id FROM contributors WHERE id = ?`).get(body.contributorId);
  if (!contributor) {
    return reply.code(404).send({ error: { code: "CTN_INTERNAL", message: "unknown contributor" } });
  }

  // The id is the contributor's, not ours: it is sealed inside the intent, so
  // minting one here would only produce a mismatch the enclave then refuses.
  const credentialId = body.credentialId;
  if (!/^cred_[0-9a-f]{12}$/.test(credentialId)) {
    return reply.code(400).send({
      error: { code: "CTN_INVALID_ENVELOPE", message: "credentialId must be cred_ + 12 hex chars" },
    });
  }
  // The enclave enforces the real invariant (one capability per sealed intent);
  // this keeps coordinator state coherent rather than half-writing a duplicate.
  if (db.prepare(`SELECT id FROM credentials WHERE id = ?`).get(credentialId)) {
    return reply.code(409).send({
      error: { code: "CTN_INTENT_REPLAY", message: "this credential id has already been contributed" },
    });
  }

  // The coordinator forwards ciphertext it cannot read and receives back a
  // vault-encrypted blob plus an enclave-signed capability. At no point does a
  // raw credential exist in this process (§13, Rule 2).
  let ingested;
  try {
    ingested = await teeClient.ingestCredential({
      enclaveKeyId: body.enclaveKeyId,
      enc: body.enc,
      encryptedSecret: body.encryptedSecret,
      credentialId,
    });
  } catch (err) {
    if (err instanceof EnclaveRejectionError) {
      safeLog("warn", "credential.ingest_rejected", { credential_id: credentialId, code: err.code });
      // A consumed intent is a conflict, not a malformed envelope: collapsing
      // the enclave's 409 into a 400 would misdescribe why it was refused.
      return reply
        .code(err.httpStatus === 409 ? 409 : 400)
        .send({ error: { code: err.code, message: err.message } });
    }
    safeLog("error", "credential.ingest_failed", { credential_id: credentialId });
    return reply.code(503).send({
      error: { code: "CTN_ENCLAVE_UNAVAILABLE", message: "The confidential service is unavailable." },
    });
  }

  // The sealed intent is the authority on whose credential this is; the HTTP
  // body is only a hint. If they disagree, the relay altered something.
  if (ingested.capability.contributorId !== body.contributorId) {
    safeLog("warn", "credential.intent_mismatch", { credential_id: body.credentialId });
    return reply.code(400).send({
      error: { code: "CTN_INTENT_MISMATCH", message: "sealed intent names a different contributor" },
    });
  }

  db.prepare(
    `INSERT INTO credentials (
       id, contributor_id, provider, label, encrypted_blob, capability_json,
       capability_signature, key_fingerprint, status, weight, created_at, usage_day,
       operational_daily_usd_limit, operational_daily_request_limit
     ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, 'ACTIVE', ?, ?, ?, ?, ?)`
  ).run(
    credentialId,
    body.contributorId,
    ingested.capability.provider,
    body.label,
    ingested.encryptedBlob,
    JSON.stringify(ingested.capability),
    ingested.capabilitySignature,
    ingested.keyFingerprint,
    body.weight ?? 1,
    nowIso(),
    today(),
    body.operationalLimits?.dailyUsd ?? null,
    body.operationalLimits?.dailyRequests ?? null
  );

  emitEvent("credential.created", credentialId, {
    credential_id: credentialId,
    contributor_id: body.contributorId,
    provider: ingested.capability.provider,
    label: body.label,
    allowed_models: ingested.capability.allowedModels,
    policy_id: ingested.policyId,
    key_fingerprint: ingested.keyFingerprint,
  });
  safeLog("info", "credential.created", {
    credential_id: credentialId,
    contributor_id: body.contributorId,
    provider: ingested.capability.provider,
  });

  return {
    id: credentialId,
    status: "ACTIVE",
    capability: ingested.capability,
    capabilitySignature: ingested.capabilitySignature,
    keyFingerprint: ingested.keyFingerprint,
    rawCredential: "HIDDEN",
  };
});

app.get("/v1/credentials", async (request) => {
  const { contributorId } = request.query as { contributorId?: string };
  const rows = (
    contributorId
      ? db.prepare(`SELECT * FROM credentials WHERE contributor_id = ? ORDER BY created_at`).all(contributorId)
      : db.prepare(`SELECT * FROM credentials ORDER BY created_at`).all()
  ) as unknown as Array<Record<string, unknown>>;

  return {
    data: rows.map((r) => {
      const usage = db
        .prepare(
          `SELECT COUNT(*) AS requests, COALESCE(SUM(input_tokens + output_tokens), 0) AS tokens,
                  COALESCE(SUM(estimated_cost_usd), 0) AS cost
             FROM usage WHERE credential_id = ?`
        )
        .get(r.id as string) as unknown as { requests: number; tokens: number; cost: number };

      return {
        id: r.id,
        contributorId: r.contributor_id,
        label: r.label,
        provider: r.provider,
        status: r.status,
        weight: r.weight,
        // §50 — the raw credential is not returned, ever, to anyone.
        rawCredential: "HIDDEN",
        keyFingerprint: r.key_fingerprint,
        capability: JSON.parse(r.capability_json as string),
        capabilitySignature: r.capability_signature,
        createdAt: r.created_at,
        lastUsedAt: r.last_used_at,
        cooldownUntil: r.cooldown_until,
        failureCount: r.failure_count,
        operationalLimits: {
          dailyUsd: r.operational_daily_usd_limit,
          dailyRequests: r.operational_daily_request_limit,
          // §4 — always labeled for what it is.
          enforcement: "operationally enforced",
        },
        today: {
          requests: r.requests_today,
          estimatedCostUsd: Math.round((r.estimated_cost_today_usd as number) * 1e6) / 1e6,
        },
        total: {
          requests: usage.requests,
          tokens: usage.tokens,
          estimatedCostUsd: Math.round(usage.cost * 1e6) / 1e6,
        },
      };
    }),
  };
});

app.patch("/v1/credentials/:id", async (request, reply) => {
  const { id } = request.params as { id: string };
  const body = request.body as {
    status?: "ACTIVE" | "DISABLED";
    weight?: number;
    operationalLimits?: { dailyUsd?: number | null; dailyRequests?: number | null };
  };

  // §50 — the capability is derived once, inside the enclave, from the sealed
  // intent. Nothing downstream can widen it, so nothing downstream may edit it.
  if ((request.body as Record<string, unknown>).allowedModels !== undefined) {
    return reply.code(400).send({
      error: {
        code: "CTN_CAPABILITY_IMMUTABLE",
        message: "Capabilities are immutable. Revoke this credential and contribute a new one.",
      },
    });
  }

  const row = db.prepare(`SELECT * FROM credentials WHERE id = ?`).get(id) as
    | Record<string, unknown>
    | undefined;
  if (!row) return reply.code(404).send({ error: { code: "CTN_INTERNAL", message: "unknown credential" } });

  if (body.status !== undefined) {
    /**
     * The TypeScript annotation on `body` is a description of what callers are
     * supposed to send, not a check — this handler previously wrote whatever
     * string arrived straight into the status column. Two rules, both of which
     * something else in this system already claims to be true:
     *
     * 1. Only ACTIVE and DISABLED are settable. DELETED is reached through
     *    DELETE, and an unrecognised status would silently make a credential
     *    unroutable (routing tests `status !== 'ACTIVE'`) under a name nothing
     *    else understands.
     * 2. Revocation is terminal. The e2e smoke tests revoke a REAL provider key
     *    by DELETE and the docs say it is "never routable again"; without this,
     *    one PATCH {status:"ACTIVE"} put that key back in the pool.
     */
    if (body.status !== "ACTIVE" && body.status !== "DISABLED") {
      return reply.code(400).send({
        error: {
          code: "CTN_INVALID_STATUS",
          message: "status must be ACTIVE or DISABLED; use DELETE to revoke a credential",
        },
      });
    }
    if (row.status === "DELETED") {
      return reply.code(409).send({
        error: {
          code: "CTN_CREDENTIAL_DELETED",
          message: "This credential was revoked. Revocation is terminal — contribute a new credential.",
        },
      });
    }
    db.prepare(`UPDATE credentials SET status = ?, cooldown_until = NULL WHERE id = ?`).run(body.status, id);
  }
  if (body.weight !== undefined) {
    db.prepare(`UPDATE credentials SET weight = ? WHERE id = ?`).run(body.weight, id);
  }
  if (body.operationalLimits) {
    db.prepare(
      `UPDATE credentials SET operational_daily_usd_limit = ?, operational_daily_request_limit = ? WHERE id = ?`
    ).run(
      body.operationalLimits.dailyUsd ?? null,
      body.operationalLimits.dailyRequests ?? null,
      id
    );
  }

  const updated = db.prepare(`SELECT * FROM credentials WHERE id = ?`).get(id) as Record<string, unknown>;
  emitEvent("credential.updated", id, {
    credential_id: id,
    status: updated.status as string,
    label: updated.label as string,
    allowed_models: (JSON.parse(updated.capability_json as string) as { allowedModels: string[] })
      .allowedModels,
  });

  return {
    id,
    status: updated.status,
    capability: JSON.parse(updated.capability_json as string),
    capabilitySignature: updated.capability_signature,
  };
});

app.delete("/v1/credentials/:id", async (request) => {
  const { id } = request.params as { id: string };
  db.prepare(`UPDATE credentials SET status = 'DELETED' WHERE id = ?`).run(id);
  emitEvent("credential.updated", id, { credential_id: id, status: "DELETED" });
  return { id, status: "DELETED" };
});

// ---------------------------------------------------------------------------
// §9A — the secure inference endpoint. This is the canonical prototype path.
// ---------------------------------------------------------------------------

interface RequestRow {
  privacyMode: "secure" | "compatibility";
}

async function runSecureRequest(
  envelope: SecureRequestEnvelope,
  privacyMode: RequestRow["privacyMode"]
): Promise<{ code: number; body: unknown }> {
  const requestId = envelope.requestId;
  const model = envelope.aad.model;
  const startedAt = performance.now();

  db.prepare(
    `INSERT INTO requests (id, model, status, privacy_mode, proof_status, created_at, policy_id)
     VALUES (?, ?, 'RECEIVED', ?, 'NOT_REQUIRED', ?, NULL)`
  ).run(requestId, model, privacyMode, nowIso());

  emitEvent("request.received", requestId, {
    request_id: requestId,
    model,
    privacy_mode: privacyMode,
    requested_policy: envelope.aad.requestedPolicy,
  });
  safeLog("info", "request.received", { request_id: requestId, model, privacy_mode: privacyMode });

  // ---- Phase 2b §3: GATE FIRST, before any capacity decision ----
  // The guest executor is the authoritative gate for EVERY request. It runs
  // before candidate discovery so that ALLOW, DENY, and no-capacity requests are
  // all gated and all proved.
  let gate;
  try {
    gate = await teeClient.gate(envelope);
  } catch (err) {
    if (err instanceof EnclaveRejectionError && err.code === "PROVER_UNAVAILABLE") {
      // §4 — a 503-class SYSTEM failure, never a policy decision. No gate ran, so
      // no provider is called, NO PolicyDecisionReceiptV1 is manufactured, and the
      // TypeScript engine does NOT silently take over. Recorded as status FAILED
      // (not DENIED), so it stays out of denial metrics and the graph's denial
      // visuals.
      const totalMs = Math.round(performance.now() - startedAt);
      db.prepare(
        `UPDATE requests SET status = 'FAILED', error_code = 'CTN_PROVER_UNAVAILABLE', completed_at = ?, total_ms = ? WHERE id = ?`
      ).run(nowIso(), totalMs, requestId);
      emitEvent("request.failed", requestId, {
        request_id: requestId,
        error_code: "CTN_PROVER_UNAVAILABLE",
        system_failure: true,
        attempts: 0,
        total_ms: totalMs,
      });
      safeLog("error", "prover.unavailable", { request_id: requestId });
      return {
        code: 503,
        body: {
          error: {
            code: "CTN_PROVER_UNAVAILABLE",
            message: "The policy gate is unavailable. The request was not evaluated and no provider was called.",
            request_id: requestId,
          },
        },
      };
    }
    if (err instanceof EnclaveRejectionError) {
      // Bad envelope, replayed nonce, unknown key id, or a determinism-guard
      // failure (CTN_COMMITMENT_MISMATCH). Nothing was decrypted-and-acted-on.
      const totalMs = Math.round(performance.now() - startedAt);
      db.prepare(
        `UPDATE requests SET status = 'FAILED', error_code = ?, completed_at = ?, total_ms = ? WHERE id = ?`
      ).run(err.code, nowIso(), totalMs, requestId);
      emitEvent("request.failed", requestId, {
        request_id: requestId,
        error_code: err.code,
        attempts: 0,
        total_ms: totalMs,
      });
      safeLog("warn", "gate.rejected", { request_id: requestId, code: err.code, http_status: err.httpStatus });
      return {
        code: err.httpStatus >= 400 && err.httpStatus < 500 ? err.httpStatus : 400,
        body: { error: { code: err.code, message: err.message, request_id: requestId } },
      };
    }

    // The enclave itself is unreachable (distinct from the guest gate being down).
    db.prepare(
      `UPDATE requests SET status = 'FAILED', error_code = 'CTN_ENCLAVE_UNAVAILABLE', completed_at = ? WHERE id = ?`
    ).run(nowIso(), requestId);
    emitEvent("request.failed", requestId, {
      request_id: requestId,
      error_code: "CTN_ENCLAVE_UNAVAILABLE",
      attempts: 0,
      total_ms: Math.round(performance.now() - startedAt),
    });
    safeLog("error", "enclave.unavailable", { request_id: requestId });
    return {
      code: 503,
      body: {
        error: {
          code: "CTN_ENCLAVE_UNAVAILABLE",
          message: "The confidential service is unavailable.",
          request_id: requestId,
        },
      },
    };
  }

  // The gate returned a verdict. The request-path policy identity is the GUEST's
  // POLICY_ID_V2 (from the gate), NOT the TypeScript package's preview id.
  const guestPolicyId = gate.policyId;
  const gateWallMs = gate.gateWallMs ?? gate.timings?.gateWallMs ?? 0;
  db.prepare(`UPDATE requests SET policy_id = ?, request_commitment = ? WHERE id = ?`).run(
    guestPolicyId,
    gate.commitment,
    requestId
  );
  // §4 — persist the signed decision receipt for the verdict (ALLOW or DENY).
  const dr = gate.decisionReceipt;
  db.prepare(
    `INSERT OR REPLACE INTO decision_receipts
       (request_id, policy_id, decision, image_id, commitment, gate_wall_ms, receipt_json, signature, created_at)
     VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`
  ).run(
    requestId,
    dr.receipt.policyId,
    dr.receipt.decision,
    dr.receipt.imageId,
    dr.receipt.requestCommitment,
    dr.receipt.timing.gateWallMs,
    JSON.stringify(dr.receipt),
    dr.enclaveSignature,
    nowIso()
  );

  // The enclave attested itself as part of handling this request.
  const attestation = await teeClient.attestation().catch(() => null);
  if (attestation) {
    emitEvent("tee.verified", requestId, {
      request_id: requestId,
      build_id: attestation.bundle.enclaveBuildId,
      mode: attestation.bundle.teeMode,
      attestation_digest: attestation.attestationDigest,
    });
  }

  emitEvent("policy.started", requestId, { request_id: requestId, policy_id: guestPolicyId });

  // §4 — enqueue the proof of the verdict for EVERY gated request: ALLOW, DENY,
  // and (below) no-capacity. The enclave already started proving at the gate;
  // this records the coordinator-side job (status QUEUED — "waiting to prove,"
  // NOT "cryptography running") and watches it through the real five-state
  // machine to a terminal state.
  if (gate.proofStarted) {
    db.prepare(`UPDATE requests SET proof_status = 'QUEUED' WHERE id = ?`).run(requestId);
    // The proof is a REAL risc0 STARK now; its image is the guest image the gate
    // ran (`gate.imageId` == the decision receipt's), unifying identity across the
    // decision receipt, the proof journal, and the compute receipt.
    db.prepare(
      `INSERT INTO proofs (id, request_id, proof_system, guest_image_id, status, created_at)
       VALUES (?, ?, 'risc0', ?, 'QUEUED', ?)`
    ).run(`proof_${requestId}`, requestId, gate.imageId, nowIso());
    emitEvent("proof.queued", requestId, {
      request_id: requestId,
      policy_id: guestPolicyId,
      proof_system: "risc0",
      guest_image_id: gate.imageId,
    });
    watchProof(requestId);
  }

  // ---- DENY: done. No credential decrypted, no provider called — but proved. ----
  if (gate.decision === "DENY") {
    db.prepare(
      `UPDATE requests SET status = 'DENIED', policy_result = 'DENY',
              policy_ms = ?, trust_status = ?, error_code = 'CTN_POLICY_DENIED', completed_at = ?, total_ms = ?
        WHERE id = ?`
    ).run(
      gateWallMs,
      privacyMode === "secure" ? "SIMULATED" : "COMPATIBILITY",
      nowIso(),
      Math.round(performance.now() - startedAt),
      requestId
    );
    emitEvent("policy.denied", requestId, {
      request_id: requestId,
      commitment: gate.commitment,
      policy_id: guestPolicyId,
      policy_ms: gateWallMs,
    });
    safeLog("info", "policy.denied", { request_id: requestId, commitment: gate.commitment });
    return {
      code: 403,
      body: {
        error: {
          code: "CTN_POLICY_DENIED",
          message: "Request was not eligible under Safety Policy v1.",
          request_id: requestId,
          policy_id: guestPolicyId,
        },
        request_commitment: gate.commitment,
      },
    };
  }

  // ---- ALLOW: discover candidates, keyed on the GUEST policyId ----
  emitEvent("policy.allowed", requestId, {
    request_id: requestId,
    commitment: gate.commitment,
    policy_id: guestPolicyId,
    policy_ms: gateWallMs,
  });

  const discovery = discoverCandidates(model, guestPolicyId);
  if (discovery.candidates.length === 0) {
    // The request was still gated and is still being proved (above). No capacity.
    const totalMs = Math.round(performance.now() - startedAt);
    db.prepare(
      `UPDATE requests SET status = 'FAILED', policy_result = 'ALLOW', policy_ms = ?, error_code = 'CTN_NO_CAPACITY', completed_at = ?, total_ms = ? WHERE id = ?`
    ).run(gateWallMs, nowIso(), totalMs, requestId);
    emitEvent("request.failed", requestId, {
      request_id: requestId,
      commitment: gate.commitment,
      error_code: "CTN_NO_CAPACITY",
      attempts: 0,
      total_ms: totalMs,
    });
    return {
      code: 503,
      body: {
        error: {
          code: "CTN_NO_CAPACITY",
          message: "No eligible contributed capacity is available for this model and policy.",
          request_id: requestId,
          excluded: discovery.excluded.map((e) => e.reason),
        },
      },
    };
  }

  // ---- Dispatch (ALLOW only). The enclave consumes the parked gate outcome. ----
  let result: ExecuteResult;
  try {
    result = await teeClient.execute(envelope, discovery.candidates, gate.commitment);
  } catch (err) {
    if (err instanceof EnclaveRejectionError) {
      const totalMs = Math.round(performance.now() - startedAt);
      db.prepare(
        `UPDATE requests SET status = 'FAILED', error_code = ?, completed_at = ?, total_ms = ? WHERE id = ?`
      ).run(err.code, nowIso(), totalMs, requestId);
      emitEvent("request.failed", requestId, {
        request_id: requestId,
        commitment: gate.commitment,
        error_code: err.code,
        attempts: 0,
        total_ms: totalMs,
      });
      safeLog("warn", "dispatch.rejected", { request_id: requestId, code: err.code });
      return {
        code: err.httpStatus >= 400 && err.httpStatus < 500 ? err.httpStatus : 400,
        body: { error: { code: err.code, message: err.message, request_id: requestId } },
      };
    }
    db.prepare(
      `UPDATE requests SET status = 'FAILED', error_code = 'CTN_ENCLAVE_UNAVAILABLE', completed_at = ? WHERE id = ?`
    ).run(nowIso(), requestId);
    emitEvent("request.failed", requestId, {
      request_id: requestId,
      commitment: gate.commitment,
      error_code: "CTN_ENCLAVE_UNAVAILABLE",
      attempts: 0,
      total_ms: Math.round(performance.now() - startedAt),
    });
    safeLog("error", "enclave.unavailable", { request_id: requestId });
    return {
      code: 503,
      body: {
        error: {
          code: "CTN_ENCLAVE_UNAVAILABLE",
          message: "The confidential service is unavailable.",
          request_id: requestId,
        },
      },
    };
  }

  // Defence in depth: dispatch should return COMPLETE or FAILED (the gate already
  // handled DENY). Anything else is malformed.
  if (result?.status !== "COMPLETE" && result?.status !== "FAILED") {
    db.prepare(
      `UPDATE requests SET status = 'FAILED', error_code = 'CTN_INTERNAL', completed_at = ? WHERE id = ?`
    ).run(nowIso(), requestId);
    emitEvent("request.failed", requestId, {
      request_id: requestId,
      commitment: gate.commitment,
      error_code: "CTN_INTERNAL",
      attempts: 0,
      total_ms: Math.round(performance.now() - startedAt),
    });
    safeLog("error", "enclave.malformed_result", { request_id: requestId });
    return {
      code: 502,
      body: {
        error: {
          code: "CTN_INTERNAL",
          message: "The confidential service returned an unrecognized result.",
          request_id: requestId,
        },
      },
    };
  }

  // Rule 6 — persist every attempt the enclave reports, successes and failures.
  for (const attempt of result.attempts) {
    const outcome = applyAttemptOutcome(attempt.credentialId, attempt.status, attempt.classification);
    db.prepare(
      `INSERT INTO provider_attempts (id, request_id, credential_id, contributor_id, attempt_number, status, http_status, classification, latency_ms, created_at, upstream_outcome_unknown, assumed_spend_micro_usd)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`
    ).run(
      `att_${requestId}_${attempt.attemptNumber}`,
      requestId,
      attempt.credentialId,
      attempt.contributorId,
      attempt.attemptNumber,
      attempt.status,
      attempt.httpStatus,
      attempt.classification ?? null,
      attempt.latencyMs,
      nowIso(),
      attempt.upstreamOutcomeUnknown ? 1 : 0,
      attempt.assumedSpendMicroUsd ?? null
    );

    /**
     * §5.1 — the enclave dispatched and never learned the outcome. Nothing
     * downstream will ever tell us what this cost, and `recordUsage` only runs
     * for a success, so without this the request is free: no spend, no request
     * slot, and a wedged provider becomes an unmetered way to drain a
     * contributor's cap. Book the enclave's conservative upper bound instead.
     *
     * The flag alone is the trigger, not the flag AND a number: an unknown
     * outcome that arrived without a bound still consumed a request slot, and
     * skipping it because the dollar figure is missing is exactly the
     * under-counting this guard exists to prevent.
     */
    if (attempt.upstreamOutcomeUnknown) {
      /**
       * Accounting is allowed to fail; it is not allowed to decide the request's
       * outcome. `recordAssumedUsage` throws on a primary-key collision (the same
       * requestId booked twice — the check that makes double-booking impossible),
       * and an escaping throw here would abandon the FAILED path mid-loop: the
       * row stays at RECEIVED, no `request.failed` is emitted, and the caller
       * gets a generic 500 instead of the classification the enclave worked out.
       * Log it and carry on — the request's own failure is the news.
       */
      try {
        recordAssumedUsage({
          requestId,
          credentialId: attempt.credentialId,
          contributorId: attempt.contributorId,
          assumedSpendMicroUsd: attempt.assumedSpendMicroUsd ?? 0,
        });
        safeLog("warn", "provider.assumed_spend", {
          request_id: requestId,
          credential_id: attempt.credentialId,
          classification: attempt.classification,
          assumed_spend_micro_usd: attempt.assumedSpendMicroUsd,
        });
      } catch (err) {
        safeLog("error", "provider.assumed_spend_failed", {
          request_id: requestId,
          credential_id: attempt.credentialId,
          classification: attempt.classification,
          assumed_spend_micro_usd: attempt.assumedSpendMicroUsd,
          error: err instanceof Error ? err.message : String(err),
        });
      }
    }

    if (attempt.status === "FAILED") {
      emitEvent("provider.failed", requestId, {
        request_id: requestId,
        credential_id: attempt.credentialId,
        contributor_id: attempt.contributorId,
        attempt_number: attempt.attemptNumber,
        http_status: attempt.httpStatus,
        classification: attempt.classification ?? "unknown",
        latency_ms: attempt.latencyMs,
        action: outcome.action,
      });
      safeLog("warn", "provider.failed", {
        request_id: requestId,
        credential_id: attempt.credentialId,
        classification: attempt.classification,
        action: outcome.action,
      });
    }
  }

  if (result.status === "FAILED" || !result.selected || !result.receipt) {
    const errorCode = result.error?.code ?? "CTN_PROVIDER_ERROR";
    const totalMs = Math.round(performance.now() - startedAt);
    db.prepare(
      `UPDATE requests SET status = 'FAILED', request_commitment = ?, policy_result = 'ALLOW',
              policy_ms = ?, error_code = ?, completed_at = ?, total_ms = ? WHERE id = ?`
    ).run(result.commitment, result.policyMs, errorCode, nowIso(), totalMs, requestId);
    /**
     * The DB row is now FAILED, and until this event existed the graph was not
     * told. `policy.allowed` was the last projection to touch the node, so a
     * failed request rendered AUTHORIZED forever — in-flight in the UI, dead in
     * the database. The event carries the code and the attempt count only: the
     * enclave's `message` is caller-facing prose and has no business in a
     * projection that anyone can read.
     */
    emitEvent("request.failed", requestId, {
      request_id: requestId,
      commitment: result.commitment,
      error_code: errorCode,
      attempts: result.attempts.length,
      total_ms: totalMs,
    });
    return {
      code: 502,
      body: {
        error: {
          code: errorCode,
          message: result.error?.message ?? "The request could not be completed.",
          request_id: requestId,
        },
        attempts: result.attempts.length,
      },
    };
  }

  const selected = result.selected;
  emitEvent("route.selected", requestId, {
    request_id: requestId,
    commitment: result.commitment,
    credential_id: selected.credentialId,
    contributor_id: selected.contributorId,
    provider: selected.provider,
    model: selected.model,
  });
  emitEvent("provider.started", requestId, {
    request_id: requestId,
    commitment: result.commitment,
    provider: selected.provider,
    model: selected.model,
  });

  const totalMs = Math.round(performance.now() - startedAt);
  const usage = result.usage ?? {};

  recordUsage({
    requestId,
    credentialId: selected.credentialId,
    contributorId: selected.contributorId,
    inputTokens: usage.inputTokens ?? 0,
    outputTokens: usage.outputTokens ?? 0,
    // Receipts carry integer micro-USD; the operational ledger stores dollars.
    estimatedCostUsd: (usage.estimatedCostMicroUsd ?? 0) / 1_000_000,
  });

  db.prepare(
    `UPDATE requests SET status = 'COMPLETE', request_commitment = ?, policy_result = 'ALLOW',
            selected_credential_id = ?, provider = ?, model = ?, policy_ms = ?, provider_ms = ?,
            total_ms = ?, input_tokens = ?, output_tokens = ?, trust_status = ?, completed_at = ?
      WHERE id = ?`
  ).run(
    result.commitment,
    selected.credentialId,
    selected.provider,
    selected.model,
    result.policyMs,
    result.timings.providerTotalMs ?? null,
    totalMs,
    usage.inputTokens ?? 0,
    usage.outputTokens ?? 0,
    // Trust status stays PROOF_PENDING until the proof actually verifies (§60).
    privacyMode === "secure" ? "CONFIDENTIAL_PROOF_PENDING" : "COMPATIBILITY",
    nowIso(),
    requestId
  );

  emitEvent("provider.completed", requestId, {
    request_id: requestId,
    commitment: result.commitment,
    credential_id: selected.credentialId,
    contributor_id: selected.contributorId,
    provider: selected.provider,
    attempt_number: selected.attempt,
    http_status: 200,
    latency_ms: result.timings.providerTotalMs ?? 0,
    input_tokens: usage.inputTokens ?? 0,
    output_tokens: usage.outputTokens ?? 0,
    total_ms: totalMs,
  });

  const receiptId = `rcpt_${requestId.replace(/^req_/, "")}`;
  db.prepare(
    `INSERT INTO compute_receipts (id, request_id, receipt_json, signature, created_at) VALUES (?, ?, ?, ?, ?)`
  ).run(receiptId, requestId, JSON.stringify(result.receipt.receipt), result.receipt.enclaveSignature, nowIso());

  emitEvent("receipt.created", requestId, {
    request_id: requestId,
    receipt_id: receiptId,
    commitment: result.commitment,
  });
  safeLog("info", "request.complete", {
    request_id: requestId,
    credential_id: selected.credentialId,
    total_ms: totalMs,
  });

  return {
    code: 200,
    body: {
      request_id: requestId,
      // §31 — relayed without decryption; only the client can open this.
      encrypted_response: result.encryptedResponse,
      receipt: {
        receipt_id: receiptId,
        request_commitment: result.commitment,
        policy: "safety-v1",
        policy_id: result.policyId,
        proof_status: "QUEUED",
        signed_receipt: result.receipt,
      },
      route: {
        provider: selected.provider,
        model: selected.model,
        contributor_id: selected.contributorId,
        credential_id: selected.credentialId,
        attempt: selected.attempt,
      },
      usage,
      timings: { ...result.timings, coordinatorTotalMs: totalMs },
      trust_status: "CONFIDENTIAL_PROOF_PENDING",
    },
  };
}

app.post("/v1/secure/chat/completions", async (request, reply) => {
  const envelope = (request.body as { envelope?: SecureRequestEnvelope }).envelope;
  if (!envelope?.requestId || !envelope.ciphertext || !envelope.aad?.model) {
    return reply
      .code(400)
      .send({ error: { code: "CTN_INVALID_ENVELOPE", message: "envelope, ciphertext and aad.model are required" } });
  }
  if (db.prepare(`SELECT id FROM requests WHERE id = ?`).get(envelope.requestId)) {
    return reply
      .code(409)
      .send({ error: { code: "CTN_INVALID_ENVELOPE", message: "requestId already used", request_id: envelope.requestId } });
  }
  const { code, body } = await runSecureRequest(envelope, "secure");
  return reply.code(code).send(body);
});

/**
 * §9B — compatibility endpoint. Accepts plain OpenAI-style JSON.
 *
 * This endpoint is honest about being weaker: TLS terminates at the coordinator,
 * so the coordinator DOES see the prompt in memory here. It is provided for SDK
 * compatibility and is never the demo default. It performs the encryption the
 * client would otherwise have done, immediately, and does not persist or log the
 * plaintext — but "operator-blind" is not a claim it can make.
 */
app.post("/v1/chat/completions", async (request, reply) => {
  const body = request.body as {
    model?: string;
    messages?: Array<{ role: string; content: string }>;
    temperature?: number;
    max_tokens?: number;
  };
  if (!body?.model || !Array.isArray(body.messages)) {
    return reply
      .code(400)
      .send({ error: { code: "CTN_INVALID_ENVELOPE", message: "model and messages are required" } });
  }

  const { buildSecureEnvelope } = await import("./compat.js");
  let envelope: SecureRequestEnvelope;
  try {
    envelope = await buildSecureEnvelope(body);
  } catch (err) {
    if (err instanceof EnclaveUnavailableError) {
      return reply.code(503).send({
        error: { code: "CTN_ENCLAVE_UNAVAILABLE", message: "The confidential service is unavailable." },
      });
    }
    return reply.code(400).send({
      error: { code: "CTN_INVALID_ENVELOPE", message: err instanceof Error ? err.message : "bad request" },
    });
  }

  const { code, body: result } = await runSecureRequest(envelope, "compatibility");
  if (code !== 200) return reply.code(code).send(result);

  // Return an OpenAI-shaped response so existing SDKs work unchanged.
  const { openResponse } = await import("./compat.js");
  const decoded = await openResponse(
    envelope.requestId,
    (result as { encrypted_response: { enc: string; ciphertext: string } }).encrypted_response
  );
  const r = result as Record<string, unknown>;
  return reply.code(200).send({
    id: `chatcmpl-${envelope.requestId}`,
    object: "chat.completion",
    created: Math.floor(Date.now() / 1000),
    model: decoded.model,
    choices: [{ index: 0, message: { role: "assistant", content: decoded.content }, finish_reason: "stop" }],
    usage: {
      prompt_tokens: decoded.usage.inputTokens,
      completion_tokens: decoded.usage.outputTokens,
      total_tokens: decoded.usage.inputTokens + decoded.usage.outputTokens,
    },
    ctn: {
      request_id: envelope.requestId,
      privacy_mode: "compatibility",
      privacy_note:
        "TLS terminated at the coordinator, so this endpoint does not provide operator-blind prompt confidentiality. Use /v1/secure/chat/completions for that.",
      receipt: r.receipt,
      route: r.route,
      trust_status: "COMPATIBILITY",
    },
  });
});

// ---------------------------------------------------------------------------
// §34 — policy test harness
// ---------------------------------------------------------------------------

app.post("/v1/policy/test", async (request, reply) => {
  const envelope = (request.body as { envelope?: SecureRequestEnvelope }).envelope;
  if (!envelope?.ciphertext) {
    return reply.code(400).send({ error: { code: "CTN_INVALID_ENVELOPE", message: "envelope is required" } });
  }
  try {
    return await teeClient.policyTest(envelope);
  } catch (err) {
    if (err instanceof EnclaveRejectionError) {
      return reply.code(400).send({ error: { code: err.code, message: err.message } });
    }
    return reply.code(503).send({
      error: { code: "CTN_ENCLAVE_UNAVAILABLE", message: "The confidential service is unavailable." },
    });
  }
});

// Task 4 — there is deliberately no policy-test proof endpoint. The Policy Lab
// is a PREVIEW that gates nothing and mints no proof (proving there would produce
// an identity-inconsistent binding: the preview receipt carries the non-authoritative
// pkg id, while the shared prover stamps the pinned guest POLICY_ID_V2). The
// authoritative, verified STARK is produced only on the request path and polled
// via `/v1/requests/:id/proof`.

app.get("/v1/policy", async () => ({
  policyId: pkg.policyId,
  guestImageId: pkg.guestImageId,
  name: pkg.manifest.name,
  version: pkg.manifest.version,
  engine: pkg.manifest.engine,
  normalizer: pkg.rules.normalizer,
  categories: Object.entries(pkg.rules.categories).map(([id, c]) => ({
    id,
    name: c.name,
    threshold: c.threshold,
  })),
  // §23 — the exact scoring system is not presented as production moderation.
  disclaimer:
    "Safety Policy v1 is a small deterministic integer-scoring engine chosen because it is auditable and provable. It is not a production moderation model and can produce false positives and false negatives.",
}));

// ---------------------------------------------------------------------------
// §29, §32 — proof and receipt retrieval
// ---------------------------------------------------------------------------

/**
 * Phase 2b §6 — poll the enclave through the REAL five-state machine
 * (QUEUED → PROVING → GENERATED → VERIFIED/FAILED) and record the artifact (§32).
 *
 * NO flat wall-clock deadline. Phase 2a proofs run 113–135 s BEFORE any queue
 * wait, so the old 120 s deadline failed normal proofs. Termination is
 * STATE-based: keep polling while the daemon reports QUEUED/PROVING/GENERATED;
 * end only on a daemon FAILED, a PROVER_UNAVAILABLE, or a generous absolute
 * ceiling (15 min, well above the measured max + plausible queue wait). QUEUED
 * time never counts against a proving deadline because there is no proving
 * deadline — only the absolute ceiling.
 */
const PROOF_ABSOLUTE_CEILING_MS = 15 * 60 * 1000;

function watchProof(requestId: string): void {
  const ceiling = Date.now() + PROOF_ABSOLUTE_CEILING_MS;
  // Track the last projected status so we emit an event only on a real transition.
  let lastStatus: string | null = "QUEUED";

  const markFailed = (error: string, proofMs: number | null): void => {
    db.prepare(`UPDATE requests SET proof_status = 'FAILED', proof_ms = ? WHERE id = ?`).run(proofMs, requestId);
    db.prepare(
      `UPDATE proofs SET status = 'FAILED', error = ?, proof_ms = ?, completed_at = ? WHERE request_id = ?`
    ).run(error, proofMs, nowIso(), requestId);
    db.prepare(
      `UPDATE requests SET trust_status = 'CONFIDENTIAL_PROOF_FAILED' WHERE id = ? AND privacy_mode = 'secure'`
    ).run(requestId);
    emitEvent("proof.failed", requestId, { request_id: requestId, error, proof_ms: proofMs ?? 0 });
    safeLog("warn", "proof.failed", { request_id: requestId, error });
  };

  const poll = async (): Promise<void> => {
    if (Date.now() > ceiling) {
      markFailed("proving exceeded the 15-minute absolute ceiling", null);
      return;
    }
    let res;
    try {
      res = await teeClient.proof(requestId);
    } catch (err) {
      // A transient relay/daemon hiccup is NOT a proof failure — keep polling. A
      // genuine PROVER_UNAVAILABLE surfaces as an EnclaveRejectionError code.
      if (err instanceof EnclaveRejectionError && err.code === "PROVER_UNAVAILABLE") {
        markFailed("PROVER_UNAVAILABLE during proving", null);
        return;
      }
      setTimeout(() => void poll(), 500);
      return;
    }

    // Mid-flight states: record the transition and keep polling. QUEUED renders as
    // "waiting to prove"; GENERATED means a receipt exists but is NOT yet verified.
    // Both the request row (the summary) AND the proofs row (what the /proof polling
    // endpoint reads) are kept in step, so a poller sees the real five-state walk.
    if (res.status === "QUEUED" || res.status === "PROVING" || res.status === "GENERATED") {
      db.prepare(`UPDATE requests SET proof_status = ? WHERE id = ?`).run(res.status, requestId);
      db.prepare(`UPDATE proofs SET status = ?, receipt_digest = COALESCE(?, receipt_digest) WHERE request_id = ?`).run(
        res.status,
        res.artifactDigest ?? null,
        requestId
      );
      if (res.status !== lastStatus) {
        lastStatus = res.status;
        if (res.status === "PROVING") {
          emitEvent("proof.started", requestId, {
            request_id: requestId,
            proof_system: "risc0",
            guest_image_id: res.imageId ?? "",
          });
        } else if (res.status === "GENERATED") {
          emitEvent("proof.generated", requestId, {
            request_id: requestId,
            proof_system: "risc0",
            guest_image_id: res.imageId ?? "",
            artifact_digest: res.artifactDigest ?? "",
          });
        }
      }
      setTimeout(() => void poll(), 400);
      return;
    }

    if (res.status === "FAILED") {
      // §59 — inference stays COMPLETE; the proof failure is recorded, not hidden.
      markFailed(res.error ?? "unknown", res.proofMs ?? null);
      return;
    }

    // VERIFIED — the reference verifier passed server-side. `proofVerified` is the
    // enclave's own subprocess verdict; the coordinator does not re-decide it.
    const verified = res.status === "VERIFIED" && res.proofVerified === true;
    db.prepare(`UPDATE requests SET proof_status = ?, proof_ms = ? WHERE id = ?`).run(
      verified ? "VERIFIED" : "GENERATED",
      res.proofMs ?? null,
      requestId
    );
    db.prepare(
      `UPDATE proofs SET status = ?, verified = ?, receipt_blob = ?, receipt_digest = ?, binding_json = ?,
              proof_ms = ?, completed_at = ? WHERE request_id = ?`
    ).run(
      verified ? "VERIFIED" : "GENERATED",
      verified ? 1 : 0,
      res.artifact ? JSON.stringify(res.artifact) : null,
      res.artifactDigest ?? null,
      res.binding ? JSON.stringify(res.binding) : null,
      res.proofMs ?? null,
      nowIso(),
      requestId
    );
    if (verified) {
      db.prepare(
        `UPDATE requests SET trust_status = 'CONFIDENTIAL_VERIFIED'
          WHERE id = ? AND privacy_mode = 'secure' AND status = 'COMPLETE'`
      ).run(requestId);
    }
    emitEvent("proof.completed", requestId, {
      request_id: requestId,
      proof_system: "risc0",
      guest_image_id: res.imageId ?? "",
      artifact_digest: res.artifactDigest ?? "",
      decision_receipt_digest: res.decisionReceiptDigest ?? "",
      proof_ms: res.proofMs ?? 0,
      verified,
    });
    safeLog("info", "proof.completed", { request_id: requestId, verified, proof_ms: res.proofMs });
  };
  setTimeout(() => void poll(), 250);
}

app.get("/v1/requests/:requestId/proof", async (request, reply) => {
  const { requestId } = request.params as { requestId: string };
  const row = db.prepare(`SELECT * FROM proofs WHERE request_id = ?`).get(requestId) as
    | Record<string, unknown>
    | undefined;
  const req = db.prepare(`SELECT * FROM requests WHERE id = ?`).get(requestId) as
    | Record<string, unknown>
    | undefined;
  if (!req) return reply.code(404).send({ error: { code: "CTN_INTERNAL", message: "unknown request" } });
  if (!row) return { request_id: requestId, proof_status: "NOT_REQUIRED" };

  // The stored blob is a real ProofArtifactWireV1 once GENERATED. Independent
  // verification RE-RUNS the reference verifier in the enclave (not an ed25519
  // seal check) — the digest a viewer sees is only trustworthy if this passes.
  const artifact = row.receipt_blob
    ? (JSON.parse(row.receipt_blob as string) as import("@ctn/protocol").ProofArtifactWireV1)
    : null;
  let verification: unknown = null;
  if (artifact) {
    verification = await teeClient
      .verify({ artifact })
      .then((r) => r.proof)
      .catch(() => null);
  }

  return {
    request_id: requestId,
    request_commitment: req.request_commitment,
    policy_id: req.policy_id,
    decision: req.policy_result ?? artifact?.decodedJournal.decision ?? null,
    proof_system: row.proof_system,
    guest_image_id: row.guest_image_id,
    proof_status: row.status,
    proof_verified: row.verified === 1,
    proof_ms: row.proof_ms,
    error: row.error,
    artifact_digest: row.receipt_digest,
    decoded_journal: artifact?.decodedJournal ?? null,
    artifact,
    binding: row.binding_json ? JSON.parse(row.binding_json as string) : null,
    verification,
  };
});

app.get("/v1/requests/:requestId/receipt", async (request, reply) => {
  const { requestId } = request.params as { requestId: string };
  const req = db.prepare(`SELECT * FROM requests WHERE id = ?`).get(requestId) as
    | Record<string, unknown>
    | undefined;
  if (!req) return reply.code(404).send({ error: { code: "CTN_INTERNAL", message: "unknown request" } });

  const receiptRow = db.prepare(`SELECT * FROM compute_receipts WHERE request_id = ?`).get(requestId) as
    | Record<string, unknown>
    | undefined;
  const proofRow = db.prepare(`SELECT * FROM proofs WHERE request_id = ?`).get(requestId) as
    | Record<string, unknown>
    | undefined;

  const signedReceipt = receiptRow
    ? {
        receipt: JSON.parse(receiptRow.receipt_json as string),
        enclaveSignature: receiptRow.signature as string,
      }
    : null;
  const artifact = proofRow?.receipt_blob
    ? (JSON.parse(proofRow.receipt_blob as string) as import("@ctn/protocol").ProofArtifactWireV1)
    : undefined;
  const binding = proofRow?.binding_json ? JSON.parse(proofRow.binding_json as string) : undefined;

  let verification: unknown = null;
  if (signedReceipt) {
    verification = await teeClient.verify({ receipt: signedReceipt, artifact, binding }).catch(() => null);
  }

  return {
    request_id: requestId,
    receipt_id: receiptRow?.id ?? null,
    proof_status: req.proof_status,
    trust_status: req.trust_status,
    signed_receipt: signedReceipt,
    proof_artifact: artifact,
    proof_binding: binding,
    verification,
  };
});

app.get("/v1/requests/:requestId", async (request, reply) => {
  const { requestId } = request.params as { requestId: string };
  const req = db.prepare(`SELECT * FROM requests WHERE id = ?`).get(requestId) as
    | Record<string, unknown>
    | undefined;
  if (!req) return reply.code(404).send({ error: { code: "CTN_INTERNAL", message: "unknown request" } });

  const attempts = db
    .prepare(`SELECT * FROM provider_attempts WHERE request_id = ? ORDER BY attempt_number`)
    .all(requestId) as unknown as Array<Record<string, unknown>>;
  const proofRow = db.prepare(`SELECT * FROM proofs WHERE request_id = ?`).get(requestId) as
    | Record<string, unknown>
    | undefined;
  const decisionRow = db.prepare(`SELECT * FROM decision_receipts WHERE request_id = ?`).get(requestId) as
    | Record<string, unknown>
    | undefined;
  const contributor = req.selected_credential_id
    ? (db
        .prepare(
          `SELECT c.id, c.display_name FROM contributors c
             JOIN credentials cr ON cr.contributor_id = c.id WHERE cr.id = ?`
        )
        .get(req.selected_credential_id as string) as { id: string; display_name: string } | undefined)
    : undefined;

  return {
    request: {
      id: req.id,
      commitment: req.request_commitment,
      // Prompt and response are never available here — by construction.
      prompt: "PRIVATE",
      response: "PRIVATE",
      status: req.status,
      privacyMode: req.privacy_mode,
      trustStatus: req.trust_status,
      proofStatus: req.proof_status,
      policyId: req.policy_id,
      policyResult: req.policy_result,
      provider: req.provider,
      model: req.model,
      credentialId: req.selected_credential_id,
      contributor: contributor ? { id: contributor.id, displayName: contributor.display_name } : null,
      usage: { inputTokens: req.input_tokens, outputTokens: req.output_tokens },
      timings: {
        policyMs: req.policy_ms,
        proofMs: req.proof_ms,
        providerMs: req.provider_ms,
        totalMs: req.total_ms,
      },
      errorCode: req.error_code,
      createdAt: req.created_at,
      completedAt: req.completed_at,
    },
    attempts,
    proof: proofRow
      ? {
          status: proofRow.status,
          verified: proofRow.verified === 1,
          proofSystem: proofRow.proof_system,
          guestImageId: proofRow.guest_image_id,
          proofMs: proofRow.proof_ms,
          artifactDigest: proofRow.receipt_digest,
          decisionReceiptDigest: proofRow.binding_json
            ? (JSON.parse(proofRow.binding_json as string) as import("@ctn/protocol").SignedProofBindingV2).binding
                .decisionReceiptDigest
            : null,
          error: proofRow.error,
        }
      : null,
    // Phase 2b §4 — the signed gate result for this request (ALLOW or DENY). A
    // PROVER_UNAVAILABLE system failure has none, by construction.
    policyDecisionReceipt: decisionRow
      ? {
          receipt: JSON.parse(decisionRow.receipt_json as string),
          enclaveSignature: decisionRow.signature as string,
        }
      : null,
  };
});

app.get("/v1/requests", async (request) => {
  const limit = Math.min(Number((request.query as { limit?: string }).limit ?? 50), 200);
  const rows = db
    .prepare(
      `SELECT id, request_commitment, status, privacy_mode, trust_status, proof_status, model, provider,
              selected_credential_id, policy_result, policy_ms, proof_ms, provider_ms, total_ms,
              input_tokens, output_tokens, error_code, created_at
         FROM requests ORDER BY created_at DESC LIMIT ?`
    )
    .all(limit) as unknown as Array<Record<string, unknown>>;
  return { data: rows };
});

// ---------------------------------------------------------------------------
// §46, §47 — graph snapshot + live SSE
// ---------------------------------------------------------------------------

app.get("/v1/graph", async () => graphSnapshot());

app.get("/v1/graph/events", async (request, reply) => {
  // Take the socket over from Fastify: this response is an open-ended stream, so
  // Fastify must not try to serialize or terminate a reply for it.
  //
  // Hijacking also skips the reply lifecycle, which is where @fastify/cors would
  // normally attach its headers — so CORS has to be written explicitly here or
  // the browser opens the stream and then silently discards every event.
  reply.hijack();
  reply.raw.writeHead(200, {
    "content-type": "text/event-stream",
    "cache-control": "no-cache, no-transform",
    connection: "keep-alive",
    "x-accel-buffering": "no",
    "access-control-allow-origin": request.headers.origin ?? "*",
    vary: "Origin",
  });
  reply.raw.write(`retry: 1000\n\n`);

  const send = (payload: { kind: string; node?: unknown; link?: unknown }) => {
    reply.raw.write(`event: ${payload.kind}\ndata: ${JSON.stringify(payload)}\n\n`);
  };
  const onGraph = (payload: { kind: string }) => send(payload as never);
  bus.on("graph", onGraph);

  const heartbeat = setInterval(() => reply.raw.write(`: ping\n\n`), 15_000);
  request.raw.on("close", () => {
    clearInterval(heartbeat);
    bus.off("graph", onGraph);
  });
});

// ---------------------------------------------------------------------------
// §65 — performance telemetry
// ---------------------------------------------------------------------------

function percentile(values: number[], p: number): number | null {
  if (values.length === 0) return null;
  const sorted = [...values].sort((a, b) => a - b);
  const idx = Math.min(sorted.length - 1, Math.floor((p / 100) * sorted.length));
  return sorted[idx];
}

app.get("/v1/stats", async () => {
  const rows = db
    .prepare(
      `SELECT policy_ms, proof_ms, provider_ms, total_ms, status, proof_status, privacy_mode
         FROM requests WHERE status IN ('COMPLETE', 'DENIED', 'FAILED')`
    )
    .all() as unknown as Array<Record<string, number | string | null>>;

  const num = (key: string) =>
    rows.map((r) => r[key]).filter((v): v is number => typeof v === "number" && v > 0);

  const policy = num("policy_ms");
  // Proof latency is reported ONLY over proofs that actually VERIFIED. A FAILED
  // proof still writes proof_ms (including a 1–5 ms queue-drop 503), so counting
  // those would make "Proving takes X at p50" on the trust page a fabricated
  // number — e.g. 35 s synthesized from 0 verified / 86 failed. This is the
  // honesty page; the figure must describe real proving, not failures.
  const proof = rows
    .filter((r) => r.proof_status === "VERIFIED")
    .map((r) => r.proof_ms)
    .filter((v): v is number => typeof v === "number" && v > 0);
  const provider = num("provider_ms");
  const total = num("total_ms");

  const contributors = db
    .prepare(
      `SELECT c.id, c.display_name,
              COUNT(u.id) AS requests,
              COALESCE(SUM(u.input_tokens + u.output_tokens), 0) AS tokens,
              COALESCE(SUM(u.estimated_cost_usd), 0) AS cost
         FROM contributors c LEFT JOIN usage u ON u.contributor_id = c.id
        GROUP BY c.id ORDER BY requests DESC`
    )
    .all() as unknown as Array<Record<string, unknown>>;

  return {
    counts: {
      requests: rows.length,
      complete: rows.filter((r) => r.status === "COMPLETE").length,
      denied: rows.filter((r) => r.status === "DENIED").length,
      failed: rows.filter((r) => r.status === "FAILED").length,
      proofsVerified: rows.filter((r) => r.proof_status === "VERIFIED").length,
      proofsFailed: rows.filter((r) => r.proof_status === "FAILED").length,
      contributors: (db.prepare(`SELECT COUNT(*) AS n FROM contributors`).get() as { n: number }).n,
      credentials: (db.prepare(`SELECT COUNT(*) AS n FROM credentials WHERE status = 'ACTIVE'`).get() as {
        n: number;
      }).n,
    },
    latency: {
      policy: { p50: percentile(policy, 50), p95: percentile(policy, 95) },
      proof: { p50: percentile(proof, 50), p95: percentile(proof, 95) },
      provider: { p50: percentile(provider, 50), p95: percentile(provider, 95) },
      overall: { p50: percentile(total, 50), p95: percentile(total, 95) },
    },
    /**
     * §66 — the research question, measured rather than guessed.
     *
     * `perceivedAddedLatency` is computed PER REQUEST (total minus that same
     * request's provider time) and then aggregated, because taking p50 of two
     * separate distributions and subtracting them is not a per-request figure.
     */
    parallelism: (() => {
      const perRequest = rows
        .filter(
          (r) => typeof r.total_ms === "number" && typeof r.provider_ms === "number" && r.status === "COMPLETE"
        )
        .map((r) => (r.total_ms as number) - (r.provider_ms as number));
      const serialized = rows
        .filter((r) => typeof r.proof_ms === "number" && typeof r.provider_ms === "number")
        .map((r) => (r.proof_ms as number) + (r.provider_ms as number));
      return {
        proofP50Ms: percentile(proof, 50),
        providerP50Ms: percentile(provider, 50),
        perceivedTotalP50Ms: percentile(total, 50),
        perceivedAddedLatencyP50Ms: percentile(perRequest, 50),
        perceivedAddedLatencyP95Ms: percentile(perRequest, 95),
        serializedWouldBeP50Ms: percentile(serialized, 50),
        samples: perRequest.length,
        note: "Proving runs concurrently with the provider call, so proof latency does not accumulate into the response the caller waits for.",
      };
    })(),
    contributors,
    usage: db.prepare(`SELECT COALESCE(SUM(estimated_cost_usd),0) AS cost, COALESCE(SUM(input_tokens+output_tokens),0) AS tokens FROM usage`).get(),
  };
});

app
  .listen({ port: PORT, host: "127.0.0.1" })
  .then(() => {
    safeLog("info", "coordinator.listening", { port: PORT, env: CTN_ENV, policy_id: pkg.policyId });
    console.log(`[coordinator] listening on http://127.0.0.1:${PORT} (env=${CTN_ENV})`);
  })
  .catch((err) => {
    console.error(err);
    process.exit(1);
  });

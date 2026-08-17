/**
 * §41, §42, §47 — outbox events, graph projection, and live SSE fan-out.
 *
 * Events carry IDs and hashes only. The projector reads the outbox and MERGEs
 * nodes/links, so a graph failure can never fail inference (Rule 9): the
 * inference path writes an outbox row and returns.
 */
import { EventEmitter } from "node:events";
import { db, nowIso } from "./db.js";
import { safeLog } from "./safe-log.js";
import type { CtnEventType, GraphNode, GraphLink } from "@ctn/protocol";

export const bus = new EventEmitter();
bus.setMaxListeners(200);

/**
 * Fields that must never appear in an event payload, at any depth.
 *
 * Compared after `normalizeKey`, so `encrypted_blob`, `encryptedBlob` and
 * `Encrypted-Blob` all collapse to the same entry and only one spelling has to be
 * listed.
 */
const BANNED_EVENT_FIELDS = [
  "messages",
  "message",
  "prompt",
  "prompttext",
  "content",
  "input",
  "output",
  "response",
  "responsebody",
  "secret",
  "apikey",
  "key",
  "authorization",
  "ciphertext",
  "encryptedblob",
  "encryptedsecret",
  "plaintext",
];

/** Lowercase and strip separators, so casing and snake/camel spelling cannot evade. */
const normalizeKey = (key: string) => key.toLowerCase().replace(/[^a-z0-9]/g, "");

/**
 * Walks the whole payload, not just its top level. A top-level-only check stops
 * protecting the moment anyone adds a nested `meta` or `detail` object, which is
 * exactly the shape a prompt would arrive in.
 */
function assertNoForbiddenFields(
  eventType: CtnEventType,
  value: unknown,
  path = "",
  depth = 0
): void {
  if (depth > 8 || value === null || typeof value !== "object") return;
  if (Array.isArray(value)) {
    value.forEach((item, i) => assertNoForbiddenFields(eventType, item, `${path}[${i}]`, depth + 1));
    return;
  }
  for (const [key, child] of Object.entries(value as Record<string, unknown>)) {
    const here = path ? `${path}.${key}` : key;
    if (BANNED_EVENT_FIELDS.includes(normalizeKey(key))) {
      // Fail loudly rather than silently leaking into the graph.
      throw new Error(`event ${eventType} attempted to carry forbidden field "${here}"`);
    }
    assertNoForbiddenFields(eventType, child, here, depth + 1);
  }
}

export function emitEvent(
  eventType: CtnEventType,
  aggregateId: string,
  payload: Record<string, unknown>
): void {
  assertNoForbiddenFields(eventType, payload);
  const created = nowIso();
  db.prepare(
    `INSERT INTO outbox_events (event_type, aggregate_id, payload_json, created_at) VALUES (?, ?, ?, ?)`
  ).run(eventType, aggregateId, JSON.stringify({ ...payload, event: eventType, timestamp: created }), created);
  bus.emit("outbox");
}

// ---------------------------------------------------------------------------
// Graph projection
// ---------------------------------------------------------------------------

function upsertNode(node: Omit<GraphNode, "createdAt"> & { createdAt?: string }): void {
  const now = nowIso();
  const existing = db.prepare(`SELECT id, meta_json FROM graph_nodes WHERE id = ?`).get(node.id) as
    | { id: string; meta_json: string }
    | undefined;

  if (existing) {
    const mergedMeta = { ...(JSON.parse(existing.meta_json) as object), ...(node.meta ?? {}) };
    db.prepare(
      `UPDATE graph_nodes SET label = ?, status = COALESCE(?, status), meta_json = ?, updated_at = ? WHERE id = ?`
    ).run(node.label, node.status ?? null, JSON.stringify(mergedMeta), now, node.id);
    const full = readNode(node.id);
    if (full) bus.emit("graph", { kind: "node.updated", node: full });
    return;
  }

  db.prepare(
    `INSERT INTO graph_nodes (id, type, label, status, meta_json, created_at, updated_at)
     VALUES (?, ?, ?, ?, ?, ?, ?)`
  ).run(
    node.id,
    node.type,
    node.label,
    node.status ?? null,
    JSON.stringify(node.meta ?? {}),
    node.createdAt ?? now,
    now
  );
  const full = readNode(node.id);
  if (full) bus.emit("graph", { kind: "node.created", node: full });
}

function upsertLink(source: string, target: string, type: string): void {
  const id = `${source}|${type}|${target}`;
  const existing = db.prepare(`SELECT id FROM graph_links WHERE id = ?`).get(id);
  if (existing) return;
  const now = nowIso();
  db.prepare(
    `INSERT INTO graph_links (id, source, target, type, created_at) VALUES (?, ?, ?, ?, ?)`
  ).run(id, source, target, type, now);
  bus.emit("graph", {
    kind: "link.created",
    link: { id, source, target, type, createdAt: now } satisfies GraphLink,
  });
}

function readNode(id: string): GraphNode | null {
  const row = db.prepare(`SELECT * FROM graph_nodes WHERE id = ?`).get(id) as
    | {
        id: string;
        type: string;
        label: string;
        status: string | null;
        meta_json: string;
        created_at: string;
      }
    | undefined;
  if (!row) return null;
  return {
    id: row.id,
    type: row.type as GraphNode["type"],
    label: row.label,
    status: row.status ?? undefined,
    meta: JSON.parse(row.meta_json) as GraphNode["meta"],
    createdAt: row.created_at,
  };
}

const shortId = (id: string) => id.slice(-6);
/** Node labels compete for lane width, so show the model name without its namespace. */
const modelLabel = (model: string) => model.replace(/^ctn\//, "");
const shortHash = (h: string) => (h?.startsWith("0x") ? h.slice(2, 8) : (h ?? "").slice(0, 6));

/**
 * §43/§44 node and relationship model. Equivalent to the spec's Cypher MERGE
 * statements; the parameterized-values discipline (§45) is preserved by using
 * bound SQL parameters everywhere above.
 */
function project(eventType: CtnEventType, payload: Record<string, unknown>): void {
  const s = (k: string) => payload[k] as string | undefined;
  const n = (k: string) => payload[k] as number | undefined;

  switch (eventType) {
    case "contributor.created":
      upsertNode({
        id: `contrib:${s("contributor_id")}`,
        type: "Contributor",
        label: s("display_name") ?? "Contributor",
        status: "ACTIVE",
      });
      break;

    case "credential.created": {
      const credId = s("credential_id")!;
      upsertNode({
        id: `cred:${credId}`,
        type: "Credential",
        label: s("label") ?? `Credential ${shortId(credId)}`,
        status: "ACTIVE",
        meta: {
          provider: s("provider") ?? "",
          allowedModels: (payload.allowed_models as string[])?.join(", ") ?? "",
          policyId: s("policy_id") ?? "",
          keyFingerprint: s("key_fingerprint") ?? "",
          rawCredential: "INACCESSIBLE — held only inside the enclave vault",
        },
      });
      upsertNode({ id: `provider:${s("provider")}`, type: "Provider", label: s("provider")!.toUpperCase() });
      upsertLink(`contrib:${s("contributor_id")}`, `cred:${credId}`, "CONTRIBUTED");
      upsertLink(`cred:${credId}`, `provider:${s("provider")}`, "CONNECTS_TO");
      for (const model of (payload.allowed_models as string[]) ?? []) {
        upsertNode({ id: `model:${model}`, type: "Model", label: modelLabel(model) });
        upsertLink(`provider:${s("provider")}`, `model:${model}`, "SERVES");
      }
      break;
    }

    case "credential.updated":
      upsertNode({
        id: `cred:${s("credential_id")}`,
        type: "Credential",
        label: s("label") ?? `Credential ${shortId(s("credential_id")!)}`,
        status: s("status"),
        meta: { allowedModels: (payload.allowed_models as string[])?.join(", ") ?? "" },
      });
      break;

    case "request.received":
      upsertNode({
        id: `req:${s("request_id")}`,
        type: "Request",
        label: `Request ${shortHash(s("commitment") ?? s("request_id")!)}`,
        status: "RECEIVED",
        meta: {
          privacyMode: s("privacy_mode") ?? "",
          model: s("model") ?? "",
          prompt: "PRIVATE — encrypted to the enclave ingress key",
        },
      });
      if (s("model")) {
        upsertNode({ id: `model:${s("model")}`, type: "Model", label: modelLabel(s("model")!) });
        upsertLink(`req:${s("request_id")}`, `model:${s("model")}`, "REQUESTED_MODEL");
      }
      break;

    case "tee.verified":
      upsertNode({
        id: `tee:${s("build_id")}`,
        type: "TEEWorker",
        label: `TEE ${(s("build_id") ?? "").slice(0, 6)}`,
        status: s("mode") === "nitro" ? "NITRO_VERIFIED" : "SIMULATED",
        meta: {
          buildId: s("build_id") ?? "",
          attestationDigest: s("attestation_digest") ?? "",
          mode: s("mode") ?? "",
          verified: true,
        },
      });
      upsertLink(`req:${s("request_id")}`, `tee:${s("build_id")}`, "EXECUTED_IN");
      break;

    case "policy.started":
      upsertNode({
        id: `policy:${s("policy_id")}`,
        type: "Policy",
        label: "Safety v1",
        status: "ACTIVE",
        meta: { policyId: s("policy_id") ?? "", version: "1.0.0" },
      });
      upsertLink(`req:${s("request_id")}`, `policy:${s("policy_id")}`, "EVALUATED_UNDER");
      break;

    case "policy.allowed":
      upsertNode({
        id: `req:${s("request_id")}`,
        type: "Request",
        label: `Request ${shortHash(s("commitment")!)}`,
        status: "AUTHORIZED",
        meta: { commitment: s("commitment") ?? "", policyResult: "ALLOW", policyMs: n("policy_ms") ?? 0 },
      });
      break;

    case "policy.denied":
      upsertNode({
        id: `req:${s("request_id")}`,
        type: "Request",
        label: `Request ${shortHash(s("commitment")!)}`,
        status: "DENIED",
        meta: { commitment: s("commitment") ?? "", policyResult: "DENY", policyMs: n("policy_ms") ?? 0 },
      });
      break;

    /**
     * The request's terminal state when it did not succeed. This has to overwrite
     * whatever `policy.allowed` or `route.selected` last wrote, because those are
     * mid-flight statuses and the graph would otherwise keep showing a dead
     * request as still running.
     */
    case "request.failed":
      upsertNode({
        id: `req:${s("request_id")}`,
        type: "Request",
        label: `Request ${shortHash(s("commitment") ?? s("request_id")!)}`,
        status: "FAILED",
        meta: {
          errorCode: s("error_code") ?? "",
          attempts: n("attempts") ?? 0,
          totalLatencyMs: n("total_ms") ?? 0,
        },
      });
      break;

    /**
     * Phase 2b — the real five-state machine. `proof.queued` renders as "waiting
     * to prove" (NOT cryptography running); `proof.started` is PROVING;
     * `proof.generated` is GENERATED (a receipt exists but is NOT yet verified);
     * `proof.completed` is VERIFIED (the reference verifier passed — the payload
     * says so, never hardcoded); `proof.failed` is FAILED.
     */
    case "proof.queued":
      upsertNode({
        id: `proof:${s("request_id")}`,
        type: "Proof",
        label: "Policy Proof",
        status: "QUEUED",
        meta: { proofSystem: s("proof_system") ?? "", policyId: s("policy_id") ?? "" },
      });
      upsertLink(`req:${s("request_id")}`, `proof:${s("request_id")}`, "HAS_PROOF");
      break;

    case "proof.started":
      upsertNode({
        id: `proof:${s("request_id")}`,
        type: "Proof",
        label: "Policy Proof",
        status: "PROVING",
        meta: { proofSystem: s("proof_system") ?? "", policyId: s("policy_id") ?? "" },
      });
      upsertLink(`req:${s("request_id")}`, `proof:${s("request_id")}`, "HAS_PROOF");
      break;

    case "proof.generated":
      upsertNode({
        id: `proof:${s("request_id")}`,
        type: "Proof",
        label: "Policy Proof",
        // Decoded but NOT verified — the server-side verifier has not yet passed.
        status: "GENERATED",
        meta: {
          proofSystem: s("proof_system") ?? "",
          verified: false,
          guestImageId: s("guest_image_id") ?? "",
          artifactDigest: s("artifact_digest") ?? "",
        },
      });
      break;

    case "proof.completed":
      upsertNode({
        id: `proof:${s("request_id")}`,
        type: "Proof",
        label: "Policy Proof",
        // VERIFIED carries the verified payload — no longer hardcoded. A proof that
        // did not verify never emits proof.completed; it emits proof.failed.
        status: (payload.verified as boolean) ? "VERIFIED" : "GENERATED",
        meta: {
          proofSystem: s("proof_system") ?? "",
          verified: (payload.verified as boolean) ?? false,
          durationMs: n("proof_ms") ?? 0,
          guestImageId: s("guest_image_id") ?? "",
          artifactDigest: s("artifact_digest") ?? "",
          decisionReceiptDigest: s("decision_receipt_digest") ?? "",
        },
      });
      break;

    case "proof.failed":
      upsertNode({
        id: `proof:${s("request_id")}`,
        type: "Proof",
        label: "Policy Proof",
        status: "FAILED",
        meta: { verified: false, error: s("error") ?? "", durationMs: n("proof_ms") ?? 0 },
      });
      break;

    case "route.selected":
      upsertLink(`req:${s("request_id")}`, `cred:${s("credential_id")}`, "ROUTED_THROUGH");
      upsertLink(`cred:${s("credential_id")}`, `provider:${s("provider")}`, "CONNECTS_TO");
      upsertNode({
        id: `req:${s("request_id")}`,
        type: "Request",
        label: `Request ${shortHash(s("commitment") ?? s("request_id")!)}`,
        status: "ROUTING",
        meta: { contributorId: s("contributor_id") ?? "", credentialId: s("credential_id") ?? "" },
      });
      break;

    case "provider.started":
      upsertNode({
        id: `req:${s("request_id")}`,
        type: "Request",
        label: `Request ${shortHash(s("commitment") ?? s("request_id")!)}`,
        status: "PROVIDER_RUNNING",
      });
      upsertLink(`req:${s("request_id")}`, `provider:${s("provider")}`, "CALLED");
      break;

    case "provider.failed": {
      const attemptId = `attempt:${s("request_id")}:${n("attempt_number")}`;
      upsertNode({
        id: attemptId,
        type: "ProviderAttempt",
        label: `Attempt ${n("attempt_number")} · ${s("classification") ?? "failed"}`,
        status: "FAILED",
        meta: {
          httpStatus: n("http_status") ?? 0,
          classification: s("classification") ?? "",
          latencyMs: n("latency_ms") ?? 0,
          action: s("action") ?? "",
        },
      });
      upsertLink(`req:${s("request_id")}`, attemptId, "HAS_ATTEMPT");
      upsertLink(attemptId, `cred:${s("credential_id")}`, "USED");
      break;
    }

    case "provider.completed": {
      const attemptId = `attempt:${s("request_id")}:${n("attempt_number")}`;
      upsertNode({
        id: attemptId,
        type: "ProviderAttempt",
        label: `Attempt ${n("attempt_number")} · ok`,
        status: "SUCCESS",
        meta: { httpStatus: n("http_status") ?? 200, latencyMs: n("latency_ms") ?? 0 },
      });
      upsertLink(`req:${s("request_id")}`, attemptId, "HAS_ATTEMPT");
      upsertLink(attemptId, `cred:${s("credential_id")}`, "USED");

      upsertNode({
        id: `resp:${s("request_id")}`,
        type: "Response",
        label: "Response",
        status: "COMPLETE",
        meta: {
          inputTokens: n("input_tokens") ?? 0,
          outputTokens: n("output_tokens") ?? 0,
          providerMs: n("latency_ms") ?? 0,
          body: "PRIVATE — sealed to the client's ephemeral key",
        },
      });
      upsertLink(`req:${s("request_id")}`, `resp:${s("request_id")}`, "PRODUCED");
      upsertNode({
        id: `req:${s("request_id")}`,
        type: "Request",
        label: `Request ${shortHash(s("commitment") ?? s("request_id")!)}`,
        status: "COMPLETE",
        meta: { totalLatencyMs: n("total_ms") ?? 0 },
      });
      break;
    }

    case "receipt.created":
      upsertNode({
        id: `receipt:${s("request_id")}`,
        type: "ComputeReceipt",
        label: "Compute Receipt",
        status: "SIGNED",
        meta: {
          receiptId: s("receipt_id") ?? "",
          commitment: s("commitment") ?? "",
          signatureVerified: true,
        },
      });
      upsertLink(`req:${s("request_id")}`, `receipt:${s("request_id")}`, "HAS_RECEIPT");
      break;
  }
}

/** §42 — drain the outbox into the graph. Safe to call repeatedly. */
export function drainOutbox(limit = 500): number {
  const rows = db
    .prepare(
      `SELECT id, event_type, payload_json FROM outbox_events WHERE processed_at IS NULL ORDER BY id LIMIT ?`
    )
    .all(limit) as unknown as Array<{ id: number; event_type: string; payload_json: string }>;

  let processed = 0;
  for (const row of rows) {
    try {
      project(row.event_type as CtnEventType, JSON.parse(row.payload_json) as Record<string, unknown>);
    } catch (err) {
      // Rule 9 — a projection error must never break the inference path. Mark it
      // processed with a warning so the loop cannot wedge on a poison event.
      safeLog("warn", "graph.projection_failed", {
        outbox_id: row.id,
        event_type: row.event_type,
        error: err instanceof Error ? err.message : String(err),
      });
    }
    db.prepare(`UPDATE outbox_events SET processed_at = ? WHERE id = ?`).run(nowIso(), row.id);
    processed += 1;
  }
  return processed;
}

export function startProjector(intervalMs = 120): () => void {
  let running = false;
  const tick = () => {
    if (running) return;
    running = true;
    try {
      drainOutbox();
    } finally {
      running = false;
    }
  };
  const timer = setInterval(tick, intervalMs);
  bus.on("outbox", tick);
  tick();
  return () => clearInterval(timer);
}

export function graphSnapshot(): { nodes: GraphNode[]; links: GraphLink[] } {
  const nodes = (
    db.prepare(`SELECT * FROM graph_nodes ORDER BY created_at`).all() as unknown as Array<{
      id: string;
      type: string;
      label: string;
      status: string | null;
      meta_json: string;
      created_at: string;
    }>
  ).map((r) => ({
    id: r.id,
    type: r.type as GraphNode["type"],
    label: r.label,
    status: r.status ?? undefined,
    meta: JSON.parse(r.meta_json) as GraphNode["meta"],
    createdAt: r.created_at,
  }));
  const links = db
    .prepare(`SELECT id, source, target, type, created_at as createdAt FROM graph_links ORDER BY created_at`)
    .all() as unknown as GraphLink[];
  return { nodes, links };
}

/**
 * §16, §17 — candidate discovery and weighted round robin.
 *
 * This is the UNTRUSTED half of routing. Everything decided here is a hint: the
 * enclave re-verifies provider, model, policy and the capability signature before
 * any credential is decrypted (§16). The reason this code is allowed to exist at
 * all is that it only ever narrows the candidate set and orders it.
 */
import { db, nowIso, today } from "./db.js";
import type { CredentialCapability } from "@ctn/protocol";

export interface CredentialRow {
  id: string;
  contributor_id: string;
  provider: string;
  label: string;
  encrypted_blob: string;
  capability_json: string;
  capability_signature: string;
  status: string;
  weight: number;
  last_used_at: string | null;
  requests_today: number;
  estimated_cost_today_usd: number;
  usage_day: string | null;
  failure_count: number;
  cooldown_until: string | null;
  operational_daily_usd_limit: number | null;
  operational_daily_request_limit: number | null;
}

export interface Candidate {
  credentialId: string;
  contributorId: string;
  provider: string;
  status: string;
  encryptedBlob: string;
  capability: CredentialCapability;
  capabilitySignature: string;
}

export type ExclusionReason =
  | "disabled"
  | "cooldown"
  | "model_not_allowed"
  | "policy_not_allowed"
  | "daily_request_limit"
  | "daily_usd_limit";

export interface DiscoveryResult {
  candidates: Candidate[];
  excluded: Array<{ credentialId: string; contributorId: string; reason: ExclusionReason }>;
}

/** Reset per-day counters lazily so the demo behaves correctly across midnight. */
function rollUsageDay(row: CredentialRow): CredentialRow {
  const d = today();
  if (row.usage_day === d) return row;
  db.prepare(
    `UPDATE credentials SET requests_today = 0, estimated_cost_today_usd = 0, usage_day = ? WHERE id = ?`
  ).run(d, row.id);
  return { ...row, requests_today: 0, estimated_cost_today_usd: 0, usage_day: d };
}

/**
 * Weighted round robin (§17): least-recently-used first, then higher weight
 * first. Deliberately not price-optimized — the spec says do not overbuild.
 */
function routingOrder(a: CredentialRow, b: CredentialRow): number {
  const at = a.last_used_at ? Date.parse(a.last_used_at) : 0;
  const bt = b.last_used_at ? Date.parse(b.last_used_at) : 0;
  if (at !== bt) return at - bt;
  if (a.weight !== b.weight) return b.weight - a.weight;
  return a.id.localeCompare(b.id);
}

export function discoverCandidates(model: string, policyId: string): DiscoveryResult {
  const rows = (db.prepare(`SELECT * FROM credentials`).all() as unknown as CredentialRow[]).map(
    rollUsageDay
  );

  const excluded: DiscoveryResult["excluded"] = [];
  const eligible: CredentialRow[] = [];
  const now = Date.now();

  for (const row of rows) {
    const exclude = (reason: ExclusionReason) =>
      excluded.push({ credentialId: row.id, contributorId: row.contributor_id, reason });

    if (row.status !== "ACTIVE") {
      exclude("disabled");
      continue;
    }
    if (row.cooldown_until && Date.parse(row.cooldown_until) > now) {
      exclude("cooldown");
      continue;
    }

    const capability = JSON.parse(row.capability_json) as CredentialCapability;
    if (!capability.allowedModels.includes(model)) {
      exclude("model_not_allowed");
      continue;
    }
    if (!capability.allowedPolicyIds.includes(policyId)) {
      exclude("policy_not_allowed");
      continue;
    }
    // §4 — operationally enforced, NOT cryptographically enforced. A malicious
    // host could roll these counters back; that is out of scope for v0.1 and
    // labeled as such everywhere it is surfaced.
    if (
      row.operational_daily_request_limit !== null &&
      row.requests_today >= row.operational_daily_request_limit
    ) {
      exclude("daily_request_limit");
      continue;
    }
    if (
      row.operational_daily_usd_limit !== null &&
      row.estimated_cost_today_usd >= row.operational_daily_usd_limit
    ) {
      exclude("daily_usd_limit");
      continue;
    }
    eligible.push(row);
  }

  eligible.sort(routingOrder);

  // Weight expansion: a weight-2 credential appears twice as often in the
  // fallback order than a weight-1 credential at the same recency.
  const ordered: CredentialRow[] = [];
  const maxWeight = Math.max(1, ...eligible.map((r) => r.weight));
  for (let pass = 0; pass < maxWeight; pass++) {
    for (const row of eligible) {
      if (row.weight > pass) ordered.push(row);
    }
  }

  const seen = new Set<string>();
  const candidates: Candidate[] = [];
  for (const row of ordered) {
    if (seen.has(row.id)) continue;
    seen.add(row.id);
    candidates.push({
      credentialId: row.id,
      contributorId: row.contributor_id,
      provider: row.provider,
      status: row.status,
      encryptedBlob: row.encrypted_blob,
      capability: JSON.parse(row.capability_json) as CredentialCapability,
      capabilitySignature: row.capability_signature,
    });
  }

  return { candidates, excluded };
}

const COOLDOWN_MS = Number(process.env.CTN_COOLDOWN_MS ?? 60_000);

/** §18 — apply the failure policy the enclave's attempt classification implies. */
export function applyAttemptOutcome(
  credentialId: string,
  status: "SUCCESS" | "FAILED",
  classification?: string
): { action: "none" | "disabled" | "cooldown" } {
  if (status === "SUCCESS") {
    db.prepare(
      `UPDATE credentials SET last_used_at = ?, failure_count = 0, cooldown_until = NULL WHERE id = ?`
    ).run(nowIso(), credentialId);
    return { action: "none" };
  }

  if (classification === "auth_failed") {
    // A credential the provider rejects is useless and possibly revoked: disable
    // it rather than retrying it on every subsequent request.
    db.prepare(
      `UPDATE credentials SET status = 'DISABLED', failure_count = failure_count + 1, last_used_at = ? WHERE id = ?`
    ).run(nowIso(), credentialId);
    return { action: "disabled" };
  }
  if (classification === "rate_limited") {
    db.prepare(
      `UPDATE credentials SET cooldown_until = ?, failure_count = failure_count + 1, last_used_at = ? WHERE id = ?`
    ).run(new Date(Date.now() + COOLDOWN_MS).toISOString(), nowIso(), credentialId);
    return { action: "cooldown" };
  }
  db.prepare(
    `UPDATE credentials SET failure_count = failure_count + 1, last_used_at = ? WHERE id = ?`
  ).run(nowIso(), credentialId);
  return { action: "none" };
}

export function recordUsage(args: {
  requestId: string;
  credentialId: string;
  contributorId: string;
  inputTokens: number;
  outputTokens: number;
  estimatedCostUsd: number;
}): void {
  db.prepare(
    `INSERT INTO usage (id, request_id, credential_id, contributor_id, input_tokens, output_tokens, estimated_cost_usd, created_at)
     VALUES (?, ?, ?, ?, ?, ?, ?, ?)`
  ).run(
    `use_${args.requestId}`,
    args.requestId,
    args.credentialId,
    args.contributorId,
    args.inputTokens,
    args.outputTokens,
    args.estimatedCostUsd,
    nowIso()
  );
  db.prepare(
    `UPDATE credentials
        SET requests_today = requests_today + 1,
            estimated_cost_today_usd = estimated_cost_today_usd + ?,
            usage_day = ?
      WHERE id = ?`
  ).run(args.estimatedCostUsd, today(), args.credentialId);
}

/**
 * §5.1 — book the conservative upper bound for a dispatch whose outcome we never
 * learned (timeout, mid-flight transport failure, a 200 we could not parse).
 *
 * The provider may have run the completion and billed for it. Recording nothing
 * would make a wedged provider the cheapest capacity on the network: every such
 * request would be free of both cost and request-slot, and a credential could be
 * drained past its cap without a single counter moving. So an unknown outcome
 * consumes exactly what a known one does — a request slot plus a cost estimate —
 * with tokens recorded as 0 because no token count was ever reported.
 *
 * Both writes go in one transaction. Half of this pair is worse than neither:
 * a ledger row without the counter bump silently under-enforces the cap, and a
 * counter bump without the ledger row makes the dashboard's totals unexplainable.
 * (node:sqlite has no `db.transaction()` wrapper, hence the explicit BEGIN.)
 */
export function recordAssumedUsage(args: {
  requestId: string;
  credentialId: string;
  contributorId: string;
  assumedSpendMicroUsd: number;
}): void {
  const estimatedCostUsd = args.assumedSpendMicroUsd / 1_000_000;
  db.exec("BEGIN IMMEDIATE");
  try {
    db.prepare(
      `INSERT INTO usage (id, request_id, credential_id, contributor_id, input_tokens, output_tokens, estimated_cost_usd, created_at)
       VALUES (?, ?, ?, ?, 0, 0, ?, ?)`
    ).run(
      `use_${args.requestId}`,
      args.requestId,
      args.credentialId,
      args.contributorId,
      estimatedCostUsd,
      nowIso()
    );
    db.prepare(
      `UPDATE credentials
          SET requests_today = requests_today + 1,
              estimated_cost_today_usd = estimated_cost_today_usd + ?,
              usage_day = ?
        WHERE id = ?`
    ).run(estimatedCostUsd, today(), args.credentialId);
    db.exec("COMMIT");
  } catch (err) {
    db.exec("ROLLBACK");
    throw err;
  }
}

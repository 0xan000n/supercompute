# Phase 2b — Wiring the Prover In: Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Connect the Phase 2a prover to the live demo so every request is gated by the zkVM executor and backed by a real, server-side-verified STARK proof a viewer can watch reach `VERIFIED`.

**Architecture:** Restructure the coordinator/tee-sim request path around five distinct states — gate result, provider result, proof job, verified artifact, infrastructure failure. The guest gates every request (ALLOW, DENY, no-capacity) before capacity discovery; every gated request enqueues a proof; tee-sim verifies each receipt via the reference `prover/verify` subprocess before VERIFIED; a real five-state projection carries QUEUED→PROVING→GENERATED→VERIFIED to the browser with timeouts that tolerate multi-minute proving.

**Tech Stack:** TypeScript (Node 22, `node:sqlite`), the `:4500` Rust daemon + `prover/verify` binary from Phase 2a, Next.js (`apps/web`), `@ctn/protocol`.

**Spec:** `docs/superpowers/specs/2026-08-16-phase2b-wiring-design.md` (revised post-review) and parent `docs/superpowers/specs/2026-08-11-supercompute-real-design.md` §5.5/§5.6/§7.

## Global Constraints

- The guest verdict is authoritative for **every** request; the TS engine (`packages/policy`) gates nothing — Policy-Lab preview only.
- **Every gated request enqueues a proof — ALLOW and DENY, including no-capacity.** Gate happens BEFORE candidate discovery, so `CTN_NO_CAPACITY` requests are still gated and proved.
- **Decoding a receipt is not verifying it.** Before GENERATED→VERIFIED or `proofVerified: true`, tee-sim runs the reference `prover/verify` subprocess against pinned `prover/release.json` and rejects: devMode; imageId/policyId/rulesDigest/risc0Version/receiptCodec mismatch; a journal differing from the gate journal in any of the five fields; malformed/trailing bytes.
- **`PROVER_UNAVAILABLE` is a 503-class system-failure record, never a `PolicyDecisionReceiptV1`** (whose decision is only ALLOW/DENY) and never a silent TS fall-through.
- Request-path `policyId` is the guest `POLICY_ID_V2` (from `/health`). Demo data is **reseeded** under it (capabilities' `allowedPolicies` contain `POLICY_ID_V2`, discovery keys on it). Phase 1 receipts stay identifiable as legacy.
- No proof has a flat wall-clock deadline that fails a legitimately-proving job. Poll while the daemon reports QUEUED/PROVING/GENERATED; end only on daemon FAILED, PROVER_UNAVAILABLE, or a generous absolute ceiling (15 min). QUEUED time never counts as proving time. (Replaces the current 120 s coordinator + 90 s playground deadlines.)
- The public journal / any browser-visible proof artifact is EXACTLY `{protocolVersion, requestCommitment, policyId, decision, proofNonce}` — no prompt-derived bytes.
- Canonical request wire shape: `{"max_tokens":N,"messages":[{"content":…,"role":…}],"model":…,"temperature_millis":N}`, JCS key order, raw UTF-8. The daemon computes the commitment itself.
- Honesty invariant: the enclave stays labelled simulated at equal weight. No fake ETA bar; QUEUED is not "cryptography running."
- Begin after the Phase 2a branch merges to `main`.

Exact schemas (parent §5.5), used verbatim below:

```typescript
interface PolicyDecisionReceiptV1 { requestId: string; requestCommitment: string; policyId: string; decision: "ALLOW"|"DENY"; imageId: string; timing: { gateWallMs: number } }
interface ComputeOutcomeReceiptV2 { requestId: string; route: unknown; usage: unknown; pricingTableDigest: string; timing: unknown; upstreamHashes: unknown; outcome: "success"|"failed"|"UPSTREAM_OUTCOME_UNKNOWN" }
interface ProofArtifactV1 { proofSystem: "risc0"; risc0Version: string; receiptCodec: "bincode-v1"; receiptBytes: Uint8Array; imageId: string; journalVersion: number; decodedJournal: { protocolVersion: 1; requestCommitment: string; policyId: string; decision: "ALLOW"|"DENY"; proofNonce: string } }
// artifactDigest = SHA256("CTN_ZK_RECEIPT_V1" ‖ receiptBytes)
interface ProofBindingV2 { decisionReceiptDigest: string; artifactDigest: string; imageId: string; policyId: string; decision: "ALLOW"|"DENY"; proofVerified: boolean }
```

---

### Task 1: `ProverClient` — typed client for the `:4500` daemon

**Files:** Create `services/tee-sim/src/prover-client.ts`; Test `services/tee-sim/src/prover-client.test.ts`. Reference `prover/README.md` wire contract and `services/coordinator/src/tee-client.ts`'s fetch-with-timeout pattern.

**Interfaces — Produces (Tasks 2/3 consume):**

```typescript
export interface ExecuteResult { journal: { protocolVersion: 1; requestCommitment: string; policyId: string; decision: "ALLOW"|"DENY"; proofNonce: string }; privateScores: Record<string, number> | null; execWallMs: number }
export interface JobStatus { status: "QUEUED"|"PROVING"|"GENERATED"|"FAILED"; receiptB64?: string; proveWallMs?: number; error?: string; devMode: boolean }
export interface ProverHealth { imageIdHex: string; policyId: string; rulesDigest: string; risc0Version: string; devMode: boolean }
export class ProverUnavailableError extends Error { readonly code = "PROVER_UNAVAILABLE" }
export class ProverClient {
  constructor(baseUrl: string, opts?: { timeoutMs?: number });
  health(): Promise<ProverHealth>;
  execute(input: { canonicalRequestBytes: string; requestNonceHex: string; proofNonce: string; emitScores: boolean }): Promise<ExecuteResult>;
  prove(input: { canonicalRequestBytes: string; requestNonceHex: string; proofNonce: string }): Promise<{ jobId: string }>;
  pollJob(jobId: string): Promise<JobStatus>;
}
```

- [ ] **Step 1: Failing tests** against a `node:http` stub: execute() posts camelCase `{protocolVersion, canonicalRequestBytesB64, requestNonceHex, proofNonce, emitScores}` and returns the journal + execWallMs; connection-refused/timeout on ANY method throws `ProverUnavailableError`; base64 applied exactly once; pollJob returns JobStatus verbatim incl. devMode; a 500 rejects with exactly one request (no retry).
- [ ] **Step 2:** Run, verify fail.
- [ ] **Step 3:** Implement — `fetch` + `AbortController` timeout, map network errors to `ProverUnavailableError`, no retry, error messages never include request bytes.
- [ ] **Step 4:** Run, verify pass.
- [ ] **Step 5:** `git add services/tee-sim/src/prover-client.* && git commit -m "tee-sim: typed ProverClient for the :4500 daemon"`

---

### Task 2: Gate-path restructuring — guest gates every request, decision receipt for all, DENY & no-capacity proved, `PROVER_UNAVAILABLE`, policy-identity reseed

**Files:** Modify `services/tee-sim/src/index.ts` (gate the request via the guest, sign `PolicyDecisionReceiptV1`, `proofStarted` for ALLOW **and** DENY), `services/tee-sim/src/authorize.ts` (verdict + commitment from the guest journal; assert commitment equality, fail closed), `services/coordinator/src/index.ts` (call the gate BEFORE `discoverCandidates`; key discovery on the guest `policyId`; add `PROVER_UNAVAILABLE` system-failure record distinct from FAILED/DENY; enqueue proof for DENY & no-capacity), `packages/protocol` (`PolicyDecisionReceiptV1`), the seed script `scripts/seed-demo.ts` (mint capabilities under `POLICY_ID_V2`). Test: extend `scripts/test-e2e.mts`.

**Interfaces — Consumes:** `ProverClient.execute`/`.health` (Task 1). **Produces:** a signed `PolicyDecisionReceiptV1` for every request; discovery keyed on the guest `policyId`.

- [ ] **Step 1: Failing e2e tests:**
  - `no-capacity ALLOW`: a benign prompt for a model with no eligible credential is gated ALLOW (decision receipt exists, policyId == `/health.policyId`), a proof is enqueued, and the request returns `CTN_NO_CAPACITY`.
  - `no-capacity DENY` and `DENY (with capacity)`: gated DENY, no provider called, a proof IS enqueued (`proofStarted` true for DENY).
  - `PROVER_UNAVAILABLE`: daemon down → a system-failure record (its own code), no dispatch, no `PolicyDecisionReceiptV1` manufactured, absent from denial metrics; TS engine did NOT gate.
  - `commitment guard`: a guest ExecuteResult whose commitment ≠ the enclave's recomputation is rejected (fail closed).
  - `reseed`: after `pnpm seed`, discovery finds candidates under the guest `policyId`.
- [ ] **Step 2:** Run, verify fail.
- [ ] **Step 3:** Implement the reorder: gate → sign decision receipt → enqueue proof → branch (DENY done; ALLOW → discovery keyed on guest policyId → dispatch or NO_CAPACITY). Remove the TS `evaluate` gate from the request path. Reseed capabilities under `POLICY_ID_V2`. `PROVER_UNAVAILABLE` is a system-failure row, never a decision.
- [ ] **Step 4:** Run, verify pass (daemon up in harness for gate cases; the down case is explicit).
- [ ] **Step 5:** `git add services scripts/seed-demo.ts scripts/test-e2e.mts packages/protocol && git commit -m "path: guest gates every request before capacity; decision receipt for all; DENY & no-capacity proved; PROVER_UNAVAILABLE system failure; reseed under POLICY_ID_V2"`

---

### Task 3: Real proofs + server-side verification + receipt split + five-state projection + timeout fix

**Files:** Modify `services/tee-sim/src/prover.ts` (replace the simulated sleep with `/prove` + poll; on GENERATED, **verify via the `prover/verify` subprocess** before VERIFIED; build `ProofArtifactV1` + `ProofBindingV2`), `packages/protocol` (`ComputeOutcomeReceiptV2` versioning, `ProofArtifactV1`, `ProofBindingV2`, the domain-separated digests), `services/coordinator/src/events.ts` (add `proof.queued`/`proof.generated`; make `proof.completed` carry its verified payload instead of hardcoding VERIFIED; poll through GENERATED to a terminal state), `services/coordinator/src/index.ts` (`watchProof` — remove the 120 s deadline; state-based termination with a 15 min ceiling), `apps/web/src/app/playground/page.tsx` (remove the 90 s poll cap; poll to a terminal state). Test: `services/tee-sim/src/prover.test.ts`, extend `scripts/test-e2e.mts`.

**Interfaces — Consumes:** `ProverClient.prove`/`.pollJob` (Task 1); the reference `prover/verify` binary. **Produces:** the three receipts + `ProofBindingV2` (schemas in Global Constraints); events `proof.queued|started|generated|completed|failed`.

- [ ] **Step 1: Failing tests:**
  - `Prover.run()` calls prove, polls to GENERATED, spawns `prover/verify` against the pinned manifest, and only then transitions VERIFIED with `proofVerified: true` and a non-empty `artifactDigest`/`decisionReceiptDigest`.
  - a receipt that fails verification (tampered/wrong-image/dev-mode fixture, or a journal ≠ the gate journal) → proof `FAILED`, never VERIFIED.
  - the projection emits QUEUED→PROVING→GENERATED→VERIFIED; a fake slow daemon that proves at 130 s still reaches VERIFIED (no 120 s/90 s failure).
  - a real ALLOW request: decision receipt reads `proof: "pending"` immediately; binding with a real `artifactDigest` after the job completes (gated slow test, one real proof).
- [ ] **Step 2:** Run, verify fail.
- [ ] **Step 3:** Implement — poll loop (honest interval), subprocess verification (spawn `prover/verify`; strict-decode; reject the §4 list), receipt split, the five events, the timeout/ceiling changes in both coordinator and playground. Drop `SIMULATED_PROVING_MS`/`simulatedCostMs`; update its UI consumer.
- [ ] **Step 4:** Run, verify pass.
- [ ] **Step 5:** `git add services packages/protocol apps/web/src/app/playground scripts/test-e2e.mts && git commit -m "proofs: real STARKs verified via prover/verify subprocess; receipt split; five-state projection; timeouts tolerate multi-minute proving"`

---

### Task 4: policyId reconciliation (preview labelling)

**Files:** Modify the Policy-Lab component (grep `apps/web/src` for `policyId` render) to label `pkg.policyId` as "preview identity — authoritative id is the guest image's." Test: assert the request-path receipts carry `/health.policyId` and the preview carries `pkg.policyId` (they differ).

*(The request-path switch to `POLICY_ID_V2` and the reseed already landed in Task 2; this task is only the preview-side labelling, kept separate so a reviewer can gate the UI copy independently.)*

- [ ] **Step 1:** Failing test — decision receipt `policyId === proverHealth.policyId`; Policy-Lab renders the "preview identity" label.
- [ ] **Step 2:** Run, verify fail.
- [ ] **Step 3:** Implement the label.
- [ ] **Step 4:** Run, verify pass.
- [ ] **Step 5:** `git add apps/web && git commit -m "policyId: label the Policy-Lab preview id as non-authoritative"`

---

### Task 5: Verifier + expanded differential + browser go/no-go spike

**Files:** Create `packages/verify/` (TS verifier for the coordinator + browser); Modify `scripts/verify-receipt.ts`; Test `packages/verify` + differential.
**Step 0 SPIKE (timeboxed ~15 min, go/no-go):** is full receipt **seal** verification feasible in-browser (wasm risc0 verify)? GO → bundle the pinned manifest, verify raw receipt bytes locally, the browser action may be "Verify offline." NO-GO → the browser checks structure + journal key-set + policyId/rulesDigest + proofNonce shape locally and delegates seal verification to the coordinator; the action is "Inspect proof" / "Verify via coordinator," shows which checks ran where, and points to `prover-verify`. Record the outcome + honesty implication in `packages/verify/README.md`. Never call a delegated flow "offline."

**Interfaces — Produces:** `verifyReceipt(receiptBytes, manifest, expect?) => { ok: boolean; checks: Array<{ name; ok; detail }> }`.

- [ ] **Step 1: Failing tests** — parse each committed fixture journal, assert the exact five-field key set; `verifyReceipt` ok for allow-real/allow-succinct/adv-004, fails at the right named check for wrong-image/dev-mode; AND fails for **hand-built malformed, appended, truncated, and invalid-journal** receipts. Differential: the verifier's verdict matches `prover-verify`'s exit code across ALL of these, not just the five good fixtures.
- [ ] **Step 2:** Run, verify fail.
- [ ] **Step 3:** Implement per the spike outcome.
- [ ] **Step 4:** Run, verify pass (incl. differential agreement on the expanded set).
- [ ] **Step 5:** `git add packages/verify scripts/verify-receipt.ts && git commit -m "verify: TS verifier + expanded differential (malformed/appended/truncated/wrong-image/dev-mode/invalid-journal); browser go/no-go recorded"`

---

### Task 6: Frontend proof beat (playground)

**Files:** Modify the playground page + request-card (grep the current proof-status consumer); Create a `ProofBeat` component; wire it to the five-state projection. Test: component tests for the states.

- [ ] **Step 1: Failing component tests** — the card renders: verdict chip on completion (gate; the ~57 ms figure shown as internal cost, not browser latency); a `QUEUED` "waiting to prove" state distinct from `PROVING`; `PROVING` with an elapsed timer + real ImageID and NO ETA bar; `VERIFIED ✓` only after the terminal verified event; a distinct `PROVER_UNAVAILABLE` system-failure state; DENY shown stopping yet still proving; the proof action (name per Task 5 spike) runs the verifier and shows checks.
- [ ] **Step 2:** Run, verify fail.
- [ ] **Step 3:** Implement `ProofBeat` off the projection; honest visuals; all five states first-class.
- [ ] **Step 4:** Run, verify pass; `pnpm --filter web build` clean.
- [ ] **Step 5:** `git add apps/web && git commit -m "web: playground proof beat — gate → queued → proving → VERIFIED, honest states, proof action"`

---

### Task 7: Trust-page rewrite + skew label + honesty pass

**Files:** Modify `apps/web/src/app/trust/page.tsx`, the Policy-Lab skew label, `README.md` trust table, `VALIDATION.md`. Test: trust page renders proof "established (local, verified, simulated enclave)" AND enclave "simulated"; no request-path surface emits `simulated-reexec`; boundary row names `tee-sim + prover/host`.

- [ ] **Step 1:** Failing tests as above.
- [ ] **Step 2:** Run, verify fail.
- [ ] **Step 3:** Implement — rewrite the two-column; add the `prover/host` boundary row; label the preview-vs-gate Unicode skew (guest authoritative); update README/VALIDATION statements now false. Every still-simulated label stays at equal weight.
- [ ] **Step 4:** Run, verify pass; web build clean; `pnpm test` + `pnpm test:e2e` green.
- [ ] **Step 5:** `git add apps/web README.md VALIDATION.md && git commit -m "trust: proof is real and verified; enclave still simulated; prover/host in the boundary"`

---

## Self-Review

**Spec coverage:** §3 restructuring → Tasks 1–2; §4 receipts+verification → Task 3; §5 identity migration → Task 2 (reseed) + Task 4 (label); §6 lifecycle+timeouts → Task 3; §7 frontend → Task 6; §7 trust page + §8 verifier go/no-go → Tasks 5/7; §10 testing → distributed. §9 deferrals are out of scope. Covered.

**Placeholder scan:** the one unknown (in-browser seal verification) is a go/no-go spike in Task 5 with both branches specified and an honesty rule each. File paths that Phase-2a churn may move are given as path + grep-target.

**Type consistency:** the four receipt/artifact interfaces are defined once in Global Constraints and consumed unchanged in Tasks 2/3; `ExecuteResult`/`JobStatus`/`ProverHealth`/`ProverUnavailableError` (Task 1) consumed in 2/3; `verifyReceipt` (Task 5) consumed in 6; the journal five-field shape identical everywhere. `PROVER_UNAVAILABLE` is a system-failure record everywhere, never a decision.

## Execution Handoff

After the Phase 2a merge. Subagent-driven (Opus), same discipline as 2a; ledger at `.superpowers/sdd/2026-08-16-phase2b-wiring/progress.md`.

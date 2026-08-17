# Phase 2b — Wiring the Prover In: Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Connect the Phase 2a RISC Zero prover to the live demo so real requests are gated by the zkVM executor and backed by real STARK proofs a viewer can watch reach `VERIFIED` and check themselves.

**Architecture:** `services/tee-sim` gains a typed `ProverClient` for the `:4500` daemon. The executor becomes the authoritative gate on the request path (~57 ms); if the daemon is unreachable a request fails visibly with `PROVER_UNAVAILABLE`. The existing `Prover` state machine's simulated sleep is replaced by real `/prove` + poll, and the existing `proof_status` projection carries `PROVING → VERIFIED` to the browser unchanged. Receipts split by lifecycle; a TS verifier lets the coordinator and browser check a receipt; the playground shows the proof beat and the trust page tells the truth.

**Tech Stack:** TypeScript (Node 22, `node:sqlite`), the `:4500` Rust daemon from Phase 2a, Next.js (`apps/web`), `@ctn/protocol` canonical/crypto, RISC Zero receipts (bincode).

**Spec:** `docs/superpowers/specs/2026-08-16-phase2b-wiring-design.md` (and its parent `docs/superpowers/specs/2026-08-11-supercompute-real-design.md` §5.2, §5.5, §7).

## Global Constraints

- Guest verdict is authoritative on the request path; the TS engine (`packages/policy`) gates NOTHING after this plan — it powers the Policy-Lab preview only. Copy this rule into every gate-touching task.
- No inference retries; single dispatch survives from Phase 1. The `ProverClient` does NOT retry `/prove` or `/execute`.
- `PROVER_UNAVAILABLE` is a visible request state, never a silent fall-through to the TS engine and never a fake success.
- The public journal / any browser-visible proof artifact is EXACTLY `{protocolVersion, requestCommitment, policyId, decision, proofNonce}` — no prompt-derived bytes, ever.
- `policyId` on the request path is the guest's `POLICY_ID_V2` (`SHA256(canonical_manifest ‖ rules_bytes)`, path-independent, unchanged by the 2a ImageID fix). The TS `pkg.policyId` is preview-only and labelled as such.
- Honesty invariant: the enclave stays labelled simulated at equal weight. New labels (proof-is-real, prover/host in the boundary, preview-vs-gate skew) are additions, never softenings.
- The canonical request wire shape is `{"max_tokens":N,"messages":[{"content":…,"role":…}],"model":…,"temperature_millis":N}`, JCS key order, raw UTF-8 (no `\u` escapes). The daemon computes the commitment itself; never trust a host-supplied commitment.
- Every proving/timing number written to a doc states machine, image, run count, variance. No fake ETA in the UI.
- Begin only after the Phase 2a branch merges to `main`.

---

### Task 1: `ProverClient` — a typed client for the `:4500` daemon

**Files:**
- Create: `services/tee-sim/src/prover-client.ts`
- Test: `services/tee-sim/src/prover-client.test.ts`
- Reference: `prover/README.md` wire-contract section (the `/execute`, `/prove`, `/jobs/:id`, `/health` shapes and the required `emitScores` field); `services/coordinator/src/tee-client.ts` for the existing fetch-with-timeout pattern to mirror.

**Interfaces:**
- Produces (Tasks 2/3 consume verbatim):

```typescript
export interface ExecuteResult {
  journal: { protocolVersion: 1; requestCommitment: string; policyId: string; decision: "ALLOW" | "DENY"; proofNonce: string };
  privateScores: Record<string, number> | null;
  execWallMs: number;
}
export interface JobStatus {
  status: "QUEUED" | "PROVING" | "GENERATED" | "FAILED";
  receiptB64?: string;
  proveWallMs?: number;
  error?: string;
  devMode: boolean;
}
export interface ProverHealth { imageIdHex: string; policyId: string; rulesDigest: string; risc0Version: string; devMode: boolean }
export class ProverUnavailableError extends Error { readonly code = "PROVER_UNAVAILABLE" }

export class ProverClient {
  constructor(baseUrl: string, opts?: { timeoutMs?: number });
  health(): Promise<ProverHealth>;                                  // throws ProverUnavailableError on unreachable/timeout
  execute(input: { canonicalRequestBytes: string; requestNonceHex: string; proofNonce: string; emitScores: boolean }): Promise<ExecuteResult>;
  prove(input: { canonicalRequestBytes: string; requestNonceHex: string; proofNonce: string }): Promise<{ jobId: string }>;
  pollJob(jobId: string): Promise<JobStatus>;
}
```

- [ ] **Step 1: Write failing tests** against a stub HTTP server (use `node:http` on an ephemeral port in the test, as `scripts/test-e2e.mts` patterns do):

```typescript
// prover-client.test.ts — key assertions:
// 1. execute() posts camelCase body {protocolVersion, canonicalRequestBytesB64, requestNonceHex, proofNonce, emitScores}
//    and returns the parsed journal + execWallMs.
// 2. A connection refused / timeout from any method throws ProverUnavailableError (code PROVER_UNAVAILABLE), NOT a generic Error.
// 3. The client base64-encodes canonicalRequestBytes into canonicalRequestBytesB64 exactly once.
// 4. pollJob returns the daemon's JobStatus verbatim incl. devMode.
// 5. No retry: a 500 from /execute rejects, and the stub records exactly ONE request.
```

- [ ] **Step 2: Run tests, verify they fail** — `pnpm --filter @ctn/tee-sim test` (or the package's test script; grep `services/tee-sim/package.json`). Expected: FAIL, ProverClient undefined.
- [ ] **Step 3: Implement `ProverClient`** — `fetch` with an `AbortController` timeout (default 3000 ms for execute/health, longer for pollJob), base64 via `Buffer.from(bytes).toString("base64")`, map `ECONNREFUSED`/`AbortError`/network errors to `ProverUnavailableError`, no retry loop. Error messages must NOT include any request bytes.
- [ ] **Step 4: Run tests, verify pass.**
- [ ] **Step 5: Commit** — `git add services/tee-sim/src/prover-client.ts services/tee-sim/src/prover-client.test.ts && git commit -m "tee-sim: typed ProverClient for the :4500 daemon"`

---

### Task 2: Guest-authoritative gate + `PROVER_UNAVAILABLE`

**Files:**
- Modify: `services/tee-sim/src/index.ts` (the request-ingestion / policy-gate path — grep for where `evaluate(`/`evaluateRequest(` is called on the request path today)
- Modify: `services/tee-sim/src/authorize.ts` (the `AuthorizedRequest` factory — the gate verdict now comes from the guest)
- Modify: `services/coordinator/src/index.ts` (add `PROVER_UNAVAILABLE` as a request outcome + error code) and `services/coordinator/src/tee-client.ts` (propagate it)
- Test: extend `scripts/test-e2e.mts`

**Interfaces:**
- Consumes: `ProverClient.execute` / `.health` (Task 1).
- Produces: the enclave now sets the request decision from `ExecuteResult.journal.decision`. `AuthorizedRequest` still constructs only on ALLOW; its `requestCommitment` MUST equal the guest journal's `requestCommitment` (the guest computed it — assert equality, fail closed on mismatch).

- [ ] **Step 1: Failing e2e tests** in `scripts/test-e2e.mts`:

```
// 80: a benign prompt gates ALLOW via the GUEST (assert the enclave used the guest verdict:
//     the decision receipt's policyId == the daemon /health policyId, not pkg.policyId).
// 81: a blocked-phrase prompt gates DENY via the guest — no credential decrypted, no provider called.
// 82: with the daemon NOT started (or pointed at a dead port), a request fails with
//     PROVER_UNAVAILABLE, no dispatch happened, and the TS engine did NOT silently gate it.
// 83: the enclave rejects a guest ExecuteResult whose requestCommitment != the enclave's own
//     recomputation (fail-closed determinism guard).
```

- [ ] **Step 2: Run, verify fail** (daemon wiring not present).
- [ ] **Step 3: Implement** — on the request path, call `proverClient.execute(...)` with the canonical bytes; use its decision as authoritative; on `ProverUnavailableError` return a `PROVER_UNAVAILABLE` error through the coordinator (new error code + request state) without dispatching; assert commitment equality. Remove the TS `evaluate` gate from the request path (leave it exported for Policy Lab). The daemon URL comes from env (`CTN_PROVER_URL` default `http://127.0.0.1:4500`).
- [ ] **Step 4: Run tests, verify pass** (start the daemon in the test harness setup, or gate cases 80/81/83 behind daemon-up and make 82 the daemon-down case explicitly).
- [ ] **Step 5: Commit** — `git add services/tee-sim services/coordinator scripts/test-e2e.mts && git commit -m "tee-sim: guest executor is the authoritative gate; PROVER_UNAVAILABLE on daemon-down"`

---

### Task 3: Real proofs in `Prover.run()` + receipt split

**Files:**
- Modify: `services/tee-sim/src/prover.ts` (replace the simulated sleep with real `/prove` + poll)
- Create: `packages/protocol/src/receipts.ts` (the three receipt types) — or extend the existing receipt module (grep `packages/protocol/src` for the current `ComputeReceipt`/`ProofBinding` definitions and version them in place)
- Modify: `services/coordinator/src/index.ts` (persist the split; `proof_status` transitions unchanged)
- Test: `services/tee-sim/src/prover.test.ts`, extend `scripts/test-e2e.mts`

**Interfaces:**
- Consumes: `ProverClient.prove` / `.pollJob` (Task 1).
- Produces:

```typescript
export interface PolicyDecisionReceiptV1 { version: 1; requestCommitment: string; policyId: string; decision: "ALLOW"|"DENY"; gateWallMs: number; proof: "pending" | ProofBindingV2 }
export interface ComputeOutcomeReceiptV2 { version: 2; /* Phase-1 receipt fields: tokens, pricingTableDigest, estimatedCostMicroUsd, outcome */ }
export interface ProofBindingV2 { requestCommitment: string; policyId: string; guestImageId: string; zkReceiptDigest: string; decision: "ALLOW"|"DENY"; proofVerified: boolean }
```

- [ ] **Step 1: Failing tests** — `prover.test.ts`: `Prover.run()` calls `prove` then polls to `GENERATED`, decodes the receipt, transitions `PROVING → GENERATED → VERIFIED`, and the `ProofBindingV2` carries a non-empty `zkReceiptDigest` and the daemon's `guestImageId`. e2e: a full ALLOW request produces a decision receipt reading `proof: "pending"` immediately and a binding with a real digest after the job completes (gated slow test, one real proof).
- [ ] **Step 2: Run, verify fail.**
- [ ] **Step 3: Implement** — replace `SIMULATED_PROVING_MS`/`setTimeout` with `prove` + a poll loop (bounded, honest interval); keep the TS re-execution determinism guard (it already exists — now compare guest vs enclave and fail the proof on disagreement); build `ProofBindingV2` from the daemon receipt digest; split the persisted receipt. Keep `simulatedCostMs` semantics gone — proving is now measured; rename the field or drop it and update the UI consumer (grep for `simulatedCostMs`/`SIMULATED_PROVING_MS`).
- [ ] **Step 4: Run tests, verify pass.**
- [ ] **Step 5: Commit** — `git add services/tee-sim/src/prover.ts packages/protocol services/coordinator services/tee-sim/src/prover.test.ts scripts/test-e2e.mts && git commit -m "tee-sim: real STARK proofs via the daemon; decision/outcome/binding receipt split"`

---

### Task 4: policyId reconciliation

**Files:**
- Modify: the request-path receipt/journal construction (Tasks 2/3 sites) to stamp `POLICY_ID_V2` (from `/health`)
- Modify: `apps/web` Policy-Lab component (grep `apps/web/src` for where `policyId` renders) to label the preview id as "preview identity"
- Test: unit assertion that a decision receipt's `policyId` equals `/health.policyId`, not `pkg.policyId`

- [ ] **Step 1: Failing test** — assert request-path `policyId === proverHealth.policyId` and that the two differ (guarding against an accidental collapse).
- [ ] **Step 2: Run, verify fail.**
- [ ] **Step 3: Implement** — source the request-path `policyId` from the daemon; leave `pkg.policyId` only in the Policy-Lab preview with a visible "preview identity — authoritative id is the guest image's" label.
- [ ] **Step 4: Run, verify pass.**
- [ ] **Step 5: Commit** — `git add services apps/web && git commit -m "policyId: guest POLICY_ID_V2 is canonical on the request path; TS id is preview-only, labelled"`

---

### Task 5: TypeScript verifier + differential agreement

**Files:**
- Create: `packages/verify/` (or `packages/protocol/src/verify.ts`) — the TS port of `prover-verify`'s checks
- Modify: `scripts/verify-receipt.ts` (route through the TS verifier)
- Test: `packages/verify` unit tests + a differential case asserting agreement with `prover-verify` on the five committed fixtures
- **Step 0 SPIKE (fold into this task, ~15 min, timeboxed):** determine whether full receipt *seal* verification is feasible in TypeScript/wasm in the browser. If yes, the TS verifier checks everything. If no, the TS verifier checks structure + journal key-set + policyId/rulesDigest + proofNonce shape, and delegates seal verification to the coordinator (which shells to `prover-verify` or a wasm module server-side). Record the decision + its honesty implication in `packages/verify/README.md`. Do NOT claim in-browser seal verification if it is delegated.

**Interfaces:**
- Produces:

```typescript
export interface VerifyReport { ok: boolean; checks: Array<{ name: string; ok: boolean; detail: string }> }
export function verifyReceipt(receiptBytes: Uint8Array, manifest: { imageIdHex: string; policyId: string; rulesDigest: string }, expect?: { commitment?: string; decision?: "ALLOW"|"DENY"; proofNonce?: string }): VerifyReport;
```

- [ ] **Step 1: Failing tests** — parse each committed fixture's journal, assert the exact five-field key set; assert `verifyReceipt` returns `ok:true` for `allow-real`/`allow-succinct`/`adv-004` and `ok:false` at the right named check for `wrong-image`/`dev-mode`; a hostile fat-proofNonce journal fails `journal-proof-nonce`. Differential: for each fixture, the TS `checks[]` verdict matches `prover-verify`'s exit code.
- [ ] **Step 2: Run, verify fail.**
- [ ] **Step 3: Implement** per the spike outcome.
- [ ] **Step 4: Run, verify pass** (incl. the differential agreement).
- [ ] **Step 5: Commit** — `git add packages/verify scripts/verify-receipt.ts && git commit -m "verify: TS receipt verifier agreeing with prover-verify on the committed fixtures"`

---

### Task 6: Frontend proof beat (playground)

**Files:**
- Modify: `apps/web/src/app` playground page + request-card component (grep for the current playground request rendering and the `proof_status` consumer)
- Create: a `ProofBeat` component — the `PROVING` visual + `VERIFIED ✓` + Verify-offline expander
- Modify: the coordinator projection/event consumer if a new field is needed for the browser (reuse existing `proof_status` events; add `imageIdHex` and `proveWallMs` to what the browser receives if not already present)
- Test: component tests for the three render states (ALLOW→proving→verified, DENY, PROVER_UNAVAILABLE)

- [ ] **Step 1: Failing component tests** — the card renders: a verdict chip on gate; a `PROVING…` state with an elapsed timer and the real ImageID (NO percentage/ETA bar); a `VERIFIED ✓` state after the projection reports it; a distinct `PROVER_UNAVAILABLE` state; the Verify-offline expander runs `verifyReceipt` (Task 5) and shows checks going green.
- [ ] **Step 2: Run, verify fail.**
- [ ] **Step 3: Implement** — `ProofBeat` driven by the existing proof-status projection (poll or the existing timer); the proving visual is an honest pulsing/elapsed state, not a fake ETA; Verify-offline calls the TS verifier and renders the check list; DENY and PROVER_UNAVAILABLE are first-class states.
- [ ] **Step 4: Run, verify pass; `pnpm --filter web build` clean.**
- [ ] **Step 5: Commit** — `git add apps/web services/coordinator && git commit -m "web: playground proof beat — gate → proving → VERIFIED, verify-offline"`

---

### Task 7: Trust-page rewrite + skew label + honesty pass

**Files:**
- Modify: `apps/web/src/app/trust/page.tsx` (the two-column truth table + trust-boundary row)
- Modify: `apps/web` Policy-Lab (the preview-vs-gate Unicode skew label)
- Modify: `README.md` trust table (add `prover/host` to the boundary), `VALIDATION.md` (the "simulated-reexec" statements that are now false on the request path)
- Test: assertions that the trust page renders "ZK proof: established (local, simulated enclave)" and still renders "enclave: simulated"; a grep-style check in CI or a test that no request-path surface still emits `simulated-reexec`

- [ ] **Step 1: Failing tests** — trust page shows the proof as established AND the enclave as simulated (both, at equal weight); `proofSystem` on the request path is no longer `simulated-reexec`; the boundary row names `tee-sim + prover/host`.
- [ ] **Step 2: Run, verify fail.**
- [ ] **Step 3: Implement** — rewrite the trust two-column; add the `prover/host` boundary row; label the preview-vs-gate skew in Policy Lab (guest authoritative, can disagree with the preview on Unicode-17-only codepoints); update README/VALIDATION statements that are now false. Keep every still-simulated label at equal weight.
- [ ] **Step 4: Run, verify pass; web build clean; `pnpm test` + `pnpm test:e2e` green.**
- [ ] **Step 5: Commit** — `git add apps/web README.md VALIDATION.md && git commit -m "trust: the proof is real and labelled; enclave still simulated; prover/host in the boundary"`

---

## Self-Review

**Spec coverage:** §3 wiring → Tasks 1–2; §4 receipt split → Task 3; §5 policyId → Task 4; §6 TS verifier → Task 5; §7 frontend beat → Task 6; §7 trust page + §8 honesty → Task 7; §10 testing → distributed across tasks + the e2e additions. §9 deferrals are explicitly out of scope (2c). Covered.

**Placeholder scan:** the one genuine unknown (in-browser seal verification) is a timeboxed spike inside Task 5 with both outcomes specified and an honesty rule for each — not a placeholder. File paths that the 2a fixer or Phase-1 churn may have moved are given as path + grep-target rather than fixed line numbers, deliberately.

**Type consistency:** `ExecuteResult`/`JobStatus`/`ProverHealth`/`ProverUnavailableError` (Task 1) are consumed unchanged in Tasks 2–3; `POLICY_ID_V2` sourced from `/health.policyId` consistently in Tasks 2/3/4; `verifyReceipt`/`VerifyReport` (Task 5) consumed in Task 6; the journal five-field shape is identical everywhere it appears.

## Execution Handoff

Execution begins after the Phase 2a branch merges to `main`. Subagent-driven (Opus), same discipline as 2a: fresh implementer per task, independent reviewer, fix loops, ledger at `.superpowers/sdd/2026-08-16-phase2b-wiring/progress.md`.

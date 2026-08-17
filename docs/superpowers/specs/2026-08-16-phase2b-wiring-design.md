# Phase 2b — Wiring the Prover In ("the proof goes live")

**Date:** 2026-08-16 (revised same day after a changes-requested review)
**Status:** Revised — addressing a 10-finding integration review; pending re-approval
**Predecessor:** Phase 2a (standalone prover, branch `phase2a-standalone-prover`)
**Parent spec:** `docs/superpowers/specs/2026-08-11-supercompute-real-design.md` (§5.5 receipts, §5.6 queue, §7 non-goals)
**Input:** the `PHASE 2B CARRY-FORWARD` block (A–G) at the tail of `.superpowers/sdd/2026-08-12-phase2a-standalone-prover/progress.md`

## 0. What the review corrected (read this first)

The first draft assumed 2b only swaps `Prover` internals and the rest of the
request path already exposes what the demo needs. That is false against the
current code, and the correction is the organizing idea of this revision:

**Model five distinct states, each with its own signed artifact and its own
event, rather than assuming the monolithic completion path exposes them:**

1. **Gate result** — the guest ALLOW/DENY decision (`PolicyDecisionReceiptV1`).
2. **Provider result** — the upstream outcome (`ComputeOutcomeReceiptV2`, ALLOW path only).
3. **Proof job** — QUEUED → PROVING → GENERATED, a real STARK.
4. **Verified artifact** — GENERATED **verified against the pinned manifest** → VERIFIED (`ProofArtifactV1` + `ProofBindingV2`).
5. **Infrastructure failure** — `PROVER_UNAVAILABLE`, a system failure, **never a policy decision**.

Every concrete correction below follows from separating these five.

## 1. Goal

Connect the Phase 2a prover to the live demo: the executor becomes the
authoritative gate for **every** request (ALLOW, DENY, and no-capacity alike),
real STARK proofs are generated and **cryptographically verified** for every
gated request, and the playground shows a proof reach `VERIFIED` that a viewer
can check. After 2b, "every proof artifact the demo shows is `simulated-reexec`"
is no longer true, and the trust page says so accurately.

**Demo-complete slice.** In scope: the request-path restructuring, real proofs,
server-side verification, the receipt split, the five-state projection,
timeouts compatible with multi-minute proving, the policy-identity migration,
the frontend proof beat, and the trust-page rewrite. **Deferred to 2c:** queue
*persistence*, backpressure/priority classes, per-request work caps, worker-panic
recovery, the `:4500` privacy-canary sweep. Deck mode stays Phase 4. The
honesty invariant carries over: the enclave stays labelled simulated at equal
weight.

## 2. Settled decisions

| Question | Decision |
|---|---|
| Scope | Demo-complete slice (§1). Correctness of the single-request lifecycle is in 2b; scale/robustness is 2c. |
| Gate authority | Guest authoritative for **every** request; TS engine gates nothing (Policy-Lab preview only). |
| Proof coverage | **Every gated request enqueues a proof — ALLOW and DENY** (parent §5.6). No-capacity requests are still gated and still proved. |
| Verification | tee-sim runs the **reference `prover/verify` path** (subprocess) against the pinned manifest before VERIFIED. Decoding is not verification. |
| Proof transport | Extend the projection, but with a **real five-state machine** (QUEUED/PROVING/GENERATED/VERIFIED/FAILED) — the current one does not have it (§7). |
| Gate-result UX | **Softened, honest:** the gate result appears when the completion response arrives (sub-second). The ~57 ms figure is the internal executor cost, shown as such, not a browser-visible latency. (A two-stage streamed gate is a possible later enhancement, out of the slice.) |
| Policy identity | Request-path identity becomes the guest's `POLICY_ID_V2`. Because existing capabilities and candidate discovery key on the old `pkg.policyId`, **demo data is reseeded** under the new identity; Phase 1 receipts are retained as legacy (§5). |

## 3. Request-path restructuring (this is not "just Prover internals")

Today the coordinator returns `CTN_NO_CAPACITY` **before** calling tee-sim
(`services/coordinator/src/index.ts:476`), DENY runs with `proofStarted: false`
(`services/tee-sim/src/index.ts:355`), and candidate discovery keys on
`pkg.policyId`. So today the guest would gate neither a no-capacity request nor
inform discovery. 2b reorders the path:

1. **Gate first.** On request receipt, tee-sim calls the guest `/execute` and
   signs a `PolicyDecisionReceiptV1` for **every** request, before any capacity
   decision. `ProverClient` unreachable → `PROVER_UNAVAILABLE` system failure
   (§4), no dispatch, no fake decision.
2. **Enqueue the proof** of that decision immediately (ALLOW and DENY both),
   `/prove` off the path.
3. **Then branch on the decision and capacity.** DENY → done (no provider).
   ALLOW → candidate discovery (now keyed on the guest `policyId`); empty →
   `CTN_NO_CAPACITY`, but the request was still gated and is still being proved.
   Non-empty → dispatch → `ComputeOutcomeReceiptV2`.
4. **Proof completes asynchronously** and is verified (§4) → `ProofBindingV2`.

`services/tee-sim/src/prover.ts`'s state machine and the coordinator's proof
persistence are reused, but the coordinator request handler, `discoverCandidates`
keying, the DENY branch, and the no-capacity branch all change. The design does
**not** claim the seam is untouched.

The daemon receives the plaintext witness, so the simulated confidential
boundary becomes **`tee-sim` + `prover/host` together** (parent §4); the trust
page and README trust table gain a `prover/host` row.

## 4. Receipts, the proof artifact, and verification (parent §5.5, copied exactly)

The first draft under-copied the parent schemas and contradicted itself. Exact
shapes:

```typescript
// Signed at decision time for EVERY request. This is what proofs bind to.
interface PolicyDecisionReceiptV1 {
  requestId: string;
  requestCommitment: string;   // equals the guest journal's commitment (assert, fail closed)
  policyId: string;            // guest POLICY_ID_V2
  decision: "ALLOW" | "DENY";
  imageId: string;             // the guest image the gate ran
  timing: { gateWallMs: number };
}
// Signed after the provider call (ALLOW path only).
interface ComputeOutcomeReceiptV2 {
  requestId: string;
  route: unknown; usage: unknown; pricingTableDigest: string;
  timing: unknown; upstreamHashes: unknown;
  outcome: "success" | "failed" | "UPSTREAM_OUTCOME_UNKNOWN";
}
// The immutable proof artifact. Digest is domain-separated.
interface ProofArtifactV1 {
  proofSystem: "risc0"; risc0Version: string; receiptCodec: "bincode-v1";
  receiptBytes: Uint8Array; imageId: string; journalVersion: number;
  decodedJournal: { protocolVersion: 1; requestCommitment: string; policyId: string; decision: "ALLOW"|"DENY"; proofNonce: string };
}
// artifactDigest = SHA256("CTN_ZK_RECEIPT_V1" ‖ receiptBytes)
// Binds the artifact to the DECISION receipt (not the outcome receipt).
interface ProofBindingV2 {
  decisionReceiptDigest: string;   // SHA256("CTN_DECISION_RECEIPT_V1" ‖ canonical(PolicyDecisionReceiptV1))
  artifactDigest: string;          // the domain-separated ProofArtifactV1 digest
  imageId: string; policyId: string; decision: "ALLOW"|"DENY";
  proofVerified: boolean;          // only ever true after §4-verification passes
}
```

The decision receipt's proof pointer reads `"pending"` until the binding
exists; the verifier treats `"pending"` as expected, not failure (parent §2.2).

**Verification is required in build phase 2, not the browser spike.** Before
transitioning GENERATED → VERIFIED or setting `proofVerified: true`, tee-sim
spawns the reference `prover/verify` path (subprocess, no FFI) against the
pinned `prover/release.json` with strict decoding, and **rejects**:

- `devMode: true`;
- imageId / policyId / rulesDigest / risc0Version / receiptCodec that mismatch the manifest;
- a decoded journal that differs from the **gate** journal in any of the five fields;
- malformed or trailing receipt bytes.

Any rejection → the proof is `FAILED` with a fixed reason (visible absence,
never a fake VERIFIED).

**`PROVER_UNAVAILABLE` is a system failure (503-class), never a policy
decision** (parent §5.5). It is recorded as a request/system-failure record —
NOT a `PolicyDecisionReceiptV1` (whose `decision` is only ALLOW/DENY). The
request fails closed (no gate → no provider), and the failure is kept out of
denial metrics and the graph's denial visuals.

## 5. Policy-identity migration (P1 — existing capabilities break otherwise)

Candidate discovery uses `pkg.policyId` and immutable capabilities carry that
old allowed-policy id. Switching authorization to `POLICY_ID_V2` makes existing
credentials ineligible, and the coordinator cannot rewrite signed capabilities.
Rule for this local demo:

- **Reseed demo data** under the guest policy identity: the seed script mints
  capabilities whose `allowedPolicies` contain `POLICY_ID_V2`, and
  `discoverCandidates` keys on the guest `policyId`. `pnpm reset && pnpm seed`
  is part of the 2b runbook.
- **Phase 1 receipts are retained as legacy** — identifiable by their old
  `policyId`, never reinterpreted under the new identity.
- The Policy-Lab preview keeps `pkg.policyId` labelled "preview identity."

## 6. Proof lifecycle transport & timeouts (P0/P1 — the current path fails these)

The current projection is not a five-state machine: there is no `proof.generated`
event, `proof.completed` hardcodes `VERIFIED` ignoring its payload
(`services/coordinator/src/events.ts:312`), the coordinator stops polling at
GENERATED (may never see verified), the coordinator fails a proof after **120 s**
(`index.ts:1042`), and the playground stops polling after **90 s**
(`playground/page.tsx:181`). Phase 2a measured proofs at 113–135 s **before**
queue wait. So a normal proof times out today. 2b:

- **Explicit events/states:** `proof.queued` (QUEUED), `proof.started` (PROVING),
  `proof.generated` (GENERATED), `proof.completed` (VERIFIED, carrying the
  verified payload), `proof.failed` (FAILED). QUEUED renders as "waiting to
  prove," **not** "cryptography running." The coordinator polls until a terminal
  state (VERIFIED or FAILED), through GENERATED.
- **Timeouts compatible with QUEUED + multi-minute proving:** remove the flat
  120 s / 90 s wall-clocks. Bound by **job state**, not elapsed wall-time: keep
  polling while the daemon reports QUEUED/PROVING/GENERATED; only a daemon
  `FAILED`, a `PROVER_UNAVAILABLE`, or a generous absolute ceiling (e.g. 15 min,
  well above the measured max + plausible queue wait) ends it. QUEUED time never
  counts against a proving deadline.
- Make `proof.completed` carry and project its `verified`/digest payload rather
  than hardcoding it.

## 7. Frontend proof beat (the wow — playground)

On the request card, honest to §6's states:

1. **Gate.** The verdict chip (ALLOW/DENY) appears when the completion response
   arrives (sub-second). The ~57 ms executor cost is shown as an internal
   figure, not claimed as the browser-visible time. DENY shows the request
   stopping with no downstream path — and still gets a proof (below).
2. **Answer** decrypts in the browser (ALLOW).
3. **Queued → Proving.** QUEUED renders as "waiting to prove"; PROVING is an
   honest pulsing "generating zero-knowledge proof" state with an **elapsed
   timer and the real ImageID** — no fake ETA/percentage bar (proving time is
   variable; VALIDATION §2c).
4. **Verified (~2 min).** The chip flips to `VERIFIED ✓` only after server-side
   verification (§4) — the projection's terminal event. A **proof action button**
   (name decided by the §8 go/no-go) reveals the checks and the journal's five
   fields (nothing else).
5. **`PROVER_UNAVAILABLE`** renders as its own system-failure state, distinct
   from a policy DENY and from a provider failure.

The trust page rewrites its two columns: the ZK proof moves to "established —
local, verified against the pinned manifest, simulated enclave"; the enclave
stays "simulated"; `prover/host` joins the boundary row. The preview-vs-gate
Unicode skew is labelled in Policy Lab (guest authoritative).

## 8. TS verifier — a go/no-go spike, honest naming (P1)

Server-side verification (§4) is the load-bearing one and does not depend on the
browser. The browser verifier is separate and its honesty depends on a spike:

- **If full in-browser verification is feasible** (wasm risc0 verify): bundle the
  pinned release manifest with the app, verify the **raw receipt bytes** locally,
  and the action may be called **"Verify offline."**
- **If not:** the action is renamed **"Inspect proof"** / **"Verify via
  coordinator,"** it shows explicitly which checks ran locally vs. server-side,
  and points independent users to `prover-verify`. It is not called "offline."

The verifier differential must include **malformed, appended, truncated,
wrong-image, dev-mode, and invalid-journal** receipts — not only the five
committed good fixtures.

## 9. Deferred to Phase 2c (recorded)

Queue persistence and resume-after-restart; backpressure + live/seeded priority
classes (parent §5.6); per-request work caps and request timeouts (2a review
I2); worker-panic recovery/`catch_unwind` (C2); `:4500` privacy-canary sweep
(§4/C7); `MAX_QUEUED` vs spec-default reconciliation. 2b assumes a single local
operator and one proof at a time.

## 10. Testing

- **Gate coverage:** no-capacity ALLOW (gated, proved, `CTN_NO_CAPACITY`
  returned), no-capacity DENY, DENY → proof → VERIFIED, ALLOW → VERIFIED.
- **Verification:** a tampered/wrong-image/dev-mode receipt is rejected
  server-side and the proof goes FAILED, never VERIFIED; a journal that differs
  from the gate journal fails.
- **`PROVER_UNAVAILABLE`:** daemon down → system-failure record, no dispatch, no
  fake decision, absent from denial metrics.
- **Lifecycle:** a proof transits QUEUED → PROVING → GENERATED → VERIFIED with
  the right events; QUEUED never renders as "proving"; no flat timeout fails a
  legitimately-proving job (a fake slow daemon past 120 s still reaches VERIFIED).
- **Identity migration:** after reseed, discovery finds candidates under the
  guest policyId; a Phase-1 legacy receipt is still identifiable.
- **Verifier differential:** TS/coordinator verifier agrees with `prover-verify`
  across the good fixtures AND the malformed/appended/truncated/wrong-image/
  dev-mode/invalid-journal set.
- **Web:** the five card states render; component-level, not a 2-minute e2e.
- Same subagent-driven SDD discipline as 2a.

## 11. Build phases (cumulative)

1. **Gate-path restructuring** — guest gate before capacity, decision receipt
   for every request, DENY/no-capacity gated, `PROVER_UNAVAILABLE` system
   failure, policy-identity reseed. Demo: every request is guest-gated; proofs
   still simulated.
2. **Real proofs + server-side verification + receipt split** — `/prove`,
   `ProofArtifactV1`, subprocess verification before VERIFIED, the three
   receipts, `ProofBindingV2`, the five-state projection + timeout fix. Demo:
   real, verified proofs land in the graph for ALLOW and DENY.
3. **Verifier + differential** — server-side verifier hardened, the go/no-go
   browser spike, the expanded differential.
4. **Frontend proof beat + trust page** — the playground states, the proof
   action, trust-page rewrite, skew label. Demo: the wow.

Begins after the Phase 2a branch merges to `main`.

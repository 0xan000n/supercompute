# Phase 2b — Wiring the Prover In ("the proof goes live")

**Date:** 2026-08-16
**Status:** Design approved in chat; pending spec review, then implementation plan
**Predecessor:** Phase 2a (standalone prover, branch `phase2a-standalone-prover`)
**Parent spec:** `docs/superpowers/specs/2026-08-11-supercompute-real-design.md`
**Input:** the `PHASE 2B CARRY-FORWARD` block (sections A–G) at the tail of
`.superpowers/sdd/2026-08-12-phase2a-standalone-prover/progress.md`

## 1. Goal

Phase 2a built a real RISC Zero prover that **nothing calls**. Phase 2b connects
it: the demo's policy gate becomes the zkVM executor, real STARK proofs are
generated for real requests, and the playground shows a proof go from
`PROVING` to `VERIFIED` that a viewer can check themselves. After 2b, the
sentence "every proof artifact the demo shows is `simulated-reexec`" is no
longer true, and the trust page says so accurately.

This is the **demo-complete slice** (decision, §2). Production hardening —
queue persistence, backpressure, request timeouts, the unbounded-work cap, the
worker-panic recovery, the `:4500` privacy-canary sweep — is explicitly
**deferred to Phase 2c** and enumerated in §7. 2b makes the proof real and
visible; 2c makes it robust under load and abuse.

The honesty invariant from v0.1/2a carries over unchanged: the enclave is still
simulated and stays labelled at equal weight; the proof becoming real does not
license softening any other label.

## 2. Settled decisions (design review, 2026-08-16)

| Question | Decision |
|---|---|
| Scope | **Demo-complete slice.** Wire the prover in, split receipts, reconcile policyId, add a TS verifier, rewrite the trust page, and build the frontend proof beat. Defer persistence/backpressure/hardening to Phase 2c. |
| Gate authority | **Guest authoritative + `PROVER_UNAVAILABLE` fallback.** `tee-sim` calls `/execute` (~57 ms) as the real gate on every request. If the daemon is unreachable, the request fails visibly with `PROVER_UNAVAILABLE` (spec §7) — never a silent fall-through to the TS engine. The daemon being up is now a hard demo dependency; that is acceptable and goes in the runbook. |
| Proof-status transport | **Extend the existing outbox→graph projection.** The demo already drives its live graph from an outbox drained on a timer, and the coordinator already tracks `proof_status` with `PROVING → GENERATED → VERIFIED` events. 2b feeds real daemon status through that same machinery. No new transport. |
| Demo surface | **Playground inline + trust page.** The proof beat lives on the playground request card; the full-screen guided deck stays Phase 4. |

## 3. Architecture & the seam

The abstraction already exists. `services/tee-sim/src/prover.ts` has a
`ProofState` machine (`PROVING → GENERATED → VERIFIED → FAILED`) and a
`Prover.run()` that today re-executes the policy in TypeScript, sleeps
`CTN_SIMULATED_PROVING_MS` (~2.4 s), builds the public journal, and signs a
binding. The coordinator (`services/coordinator/src/index.ts`,
`events.ts`) already persists `proof_status` and emits proof-status events the
web graph consumes.

2b changes the **internals** of that seam, not its shape:

- **New `ProverClient`** (`services/tee-sim/src/prover-client.ts`): a typed
  client for the `:4500` daemon — `execute`, `prove`, `pollJob`, `health` —
  with a hard timeout, no retries (single dispatch discipline carries over),
  and structured errors that never echo request bytes (the daemon already
  guarantees this; the client must not undo it in its own error messages).
- **Gate call** on the request path: before dispatch, `tee-sim` calls
  `POST /execute` with the canonical request bytes and gets the authoritative
  ALLOW/DENY. The TS engine (`packages/policy`) is demoted to Policy-Lab
  preview; it no longer gates anything. Health of the daemon is checked at
  request time; unreachable → `PROVER_UNAVAILABLE`.
- **Prove call** off the path: `Prover.run()` replaces its simulated sleep with
  `POST /prove` → poll `/jobs/:id` to `GENERATED` → decode the real receipt.
  The `ProofState` transitions and the events they emit are unchanged, so the
  browser's `PROVING → VERIFIED` beat lights up from real data with no
  transport work.

Everything the daemon receives (canonical request bytes = the plaintext
witness) keeps it inside the simulated confidential boundary, which becomes
**`tee-sim` + `prover/host` together** (parent spec §4). The trust page and the
README trust table gain a `prover/host` row (carry-forward, whole-branch note 1).

## 4. Receipt split (§5.5, carry-forward A)

Today one receipt carries a mutable `proof_status`. Split by lifecycle:

- **`PolicyDecisionReceiptV1`** — signed at gate time, immediately: protocol
  version, request commitment, `policyId` (the guest's `POLICY_ID_V2`, now
  canonical — §5), decision, gate timing. Available the instant the gate
  returns.
- **`ComputeOutcomeReceiptV2`** — the provider result: token counts, pricing
  digest, estimated cost, outcome (including `UPSTREAM_OUTCOME_UNKNOWN`). This
  is the Phase-1 receipt, versioned.
- **`ProofBindingV2`** — signed when the STARK settles: binds
  `{requestCommitment, policyId, guestImageId, zkReceiptDigest, decision,
  proofVerified}`. Until it exists, the decision receipt's proof field reads
  `"pending"` and the verifier treats `"pending"` as *expected*, not failure —
  the exact pattern VALIDATION §2.2 established for the simulated binding.

`PROVER_UNAVAILABLE` is a decision-receipt state, not a compute-outcome failure:
the request never dispatched, so there is no outcome to book.

## 5. policyId reconciliation (carry-forward A2)

The guest's `POLICY_ID_V2 = SHA256(canonical_manifest ‖ rules_bytes)` and the TS
`pkg.policyId` (which folds in a simulated `guestImageId`) differ by design. 2b
makes **the guest's the canonical request-path identity**: the decision receipt,
the journal, and the trust page all use `POLICY_ID_V2`. The Policy-Lab preview
keeps `pkg.policyId` but labels it "preview identity — the authoritative policy
id is the guest image's." No signed Phase-1 artifact silently changes meaning;
the change is additive and labelled.

## 6. TS verifier (carry-forward B)

A TypeScript port of `prover-verify`'s checks (`packages/protocol` or a new
`packages/verify`): parse the journal, assert the exact five-field key set,
check `policyId`/`rulesDigest` against a pinned manifest, check the
`proofNonce` shape (the offline CLI's added check), and verify the receipt seal
against the pinned ImageID. Two consumers: the coordinator's
`pnpm verify-receipt`, and the browser's **Verify offline** button. A
differential test asserts the TS verifier agrees with `prover-verify`
byte-for-byte on the five committed fixtures. (Seal verification in TS may
require a wasm build of the risc0 verifier or a documented boundary — the plan's
first task is a spike to determine whether full seal verification is feasible
in-browser or whether the browser checks structure + journal and delegates seal
verification to the coordinator. Honest labelling either way.)

## 7. Frontend proof beat — the wow (playground)

The emphasized deliverable. On the playground request card:

1. **Gate (instant).** The verdict chip resolves in ~57 ms — `ALLOW` or `DENY`
   — with the authoritative `policyId`. DENY shows the request stopping: no
   credential, no provider, no downstream graph path.
2. **Answer (sub-second).** The response decrypts in the browser as today.
3. **Proving (the visual).** A live `PROVING…` state on the card: an animated,
   honest progress affordance for the ~2-minute STARK — NOT a fake progress bar
   claiming to know the ETA (proving time is variable; §2c of VALIDATION says
   so). Something like a pulsing "generating zero-knowledge proof" state with an
   elapsed timer and the real ImageID visible, so the wait reads as "real
   cryptography is happening" rather than "the page is stuck." The two-minute
   lag is real and shown, not hidden.
4. **Verified (~2 min later).** The chip flips to `VERIFIED ✓`, fed by the
   existing projection. A **Verify offline** button expands the 13 named checks
   and runs the TS verifier live, checks going green one by one, revealing the
   journal's five fields (and nothing else).
5. **`PROVER_UNAVAILABLE`.** If the daemon is down, the card shows an honest
   failure state distinct from a provider failure — "the prover is unavailable;
   this request was not gated and was refused," never a silent success.

The trust page rewrites its two columns: the ZK proof moves from
"not established" to "established — local, against a simulated enclave," the
enclave stays "simulated," and `prover/host` joins the trust-boundary row. The
preview-vs-gate Unicode skew (2a's bidirectional inventory) is labelled in the
Policy Lab: the guest can disagree with the preview on Unicode-17-only
codepoints, and the guest is authoritative.

## 8. Error handling & honesty

- `PROVER_UNAVAILABLE` is a first-class request state with its own event,
  projector case, and graph rendering — not FAILED-as-generic.
- The daemon's fixed-string error taxonomy is surfaced to the UI as-is; the
  coordinator never re-wraps a daemon error in a way that could echo bytes.
- Method-not-allowed and the other 2a-review shape nits (carry-forward C5)
  ride along if cheap; otherwise 2c.
- Every still-simulated element (the enclave, the attestation) keeps its label
  at equal weight. The 405/error-shape and skew labels are additions, not
  softenings.

## 9. Deferred to Phase 2c (recorded, not dropped)

From the carry-forward block: queue persistence and real backpressure (§5.6);
the unbounded per-request work cap and request timeouts (2a review I2); the
worker-panic `PROVING`-forever recovery + `catch_unwind` (C2); the `:4500`
privacy-canary sweep (§4, C7); `MAX_QUEUED` vs spec default reconciliation;
the deck-mode guided walkthrough (Phase 4). 2b assumes a single local demo
operator and a daemon that is either up or honestly reported down.

## 10. Testing

- e2e: guest-authoritative ALLOW and DENY on the real request path; the TS
  engine no longer gates (assert a request routes on the guest verdict);
  `PROVER_UNAVAILABLE` when the daemon is down, with no TS fall-through and no
  dispatch; the receipt split verifies end-to-end; a proof reaches `VERIFIED`
  through the projection (gated/slow test — one real proof).
- Differential: the TS verifier agrees with `prover-verify` byte-for-byte on
  the five committed fixtures.
- Web: the playground proof-beat states render for each path (ALLOW→proving→
  verified, DENY, PROVER_UNAVAILABLE) — component-level, not a 2-minute e2e.
- The honesty labels (trust page two-column, skew note, `prover/host` in the
  boundary) have their assertions.
- Same subagent-driven SDD discipline as 2a: fresh Opus implementer per task,
  independent reviewer, fix loops, ledger.

## 11. Build phases (cumulative, each demoable)

1. **Wiring + gate authority** — `ProverClient`, guest-authoritative `/execute`,
   `PROVER_UNAVAILABLE`, TS engine demoted. Demo: real gate, still-simulated
   proof.
2. **Real proofs + receipt split** — `/prove` in `Prover.run()`, the three-way
   receipt split, `ProofBindingV2` with the real digest. Demo: real proofs land
   in the graph.
3. **TS verifier** — the port + differential agreement + `verify-receipt`.
4. **Frontend proof beat + trust page** — the playground UX, Verify-offline,
   trust-page rewrite, skew label. Demo: the wow.

Phase 2b begins only after the Phase 2a branch merges to `main` (pending the
ImageID path-independence fix and its re-review).

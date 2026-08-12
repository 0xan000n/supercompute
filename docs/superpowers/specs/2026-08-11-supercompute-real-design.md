# Supercompute "For Real" — Design

**Date:** 2026-08-11 (revised same day after changes-requested review)
**Status:** Revised — addressing 9-finding review; pending re-approval
**Repo:** `compute-trust-network`
**Predecessor:** v0.1 prototype (see `HANDOFF.md`, `VALIDATION.md`)

## 1. Goal

Take the v0.1 prototype — where key encryption and receipt signing are real but the
trust root is simulated — and make the end-to-end flow real for a local demo:

1. A real API key is contributed and HPKE-encrypted in the browser, **together with
   the contributor's constraints** (see §5.1 — intent binding).
2. A prompt is proxied through the enclave to a **real provider** (Anthropic or
   OpenAI), spending that key.
3. Policy compliance is proved with a **real ZK proof** (RISC Zero STARK), not a
   signed re-execution.
4. Signed receipts bind validated input/output to the policy verdict — for
   **allows and denials alike** (§5.5).
5. A **fully local Clio-style insights layer** shows contributors what their
   compute is used for, via threshold-suppressed aggregates (§5.3).
6. A **guided deck mode** walks a viewer through one real request step by step,
   in plain language, showing live artifacts.

**The honesty invariant from v0.1 carries over unchanged:** every remaining
simulation and every limitation (the TEE, the expanded trust boundary, the
Sybil-ability of requester counts, dev-mode if ever active) is labelled at equal
weight with the guarantees, in the UI, README, and VALIDATION.md. No change may
soften this labelling.

## 2. Decisions (settled in design review + revision)

| Question | Decision |
|---|---|
| Trust mechanism to make real | **Real ZK proof** (RISC Zero, local M1 Pro). TEE stays simulated, labelled. |
| Provider | **Both Anthropic and OpenAI**, chosen per-credential at contribution time, sealed inside the contributor's encrypted intent. Mock retained for seeded traffic. |
| Deployment | **Local demo only.** No auth work. Must not be network-exposed (unchanged from v0.1). |
| Clio insights | **In scope, fully local**: closed-enum facets via local classification, local embeddings, enum-derived cluster labels, **threshold suppression** (never called anonymity), enclave-signed bulletins. No external calls, no insights credential. |
| Demo UX | **Deck mode**: full-screen step-by-step guided walkthrough driving one real request. |
| Engine authority | **Single engine — Rust.** The RISC Zero guest is the authoritative policy engine; it gates requests via the zkVM executor and the same image is proved async. **Executor gating is required — no native-compile fallback.** TS engine demoted to UI preview, CI-cross-validated. |
| Capability mutability | **Immutable.** The recapability endpoint is removed; editing a credential means revoke + re-contribute. |

## 3. Non-goals

- Streaming responses (receipts hash complete input/output).
- Authentication, rate limiting, hosting (separate future spec; prerequisite for
  any deployment — and for any anonymity claim stronger than threshold
  suppression, see §5.3).
- Real TEE hardware attestation (requires cloud confidential VM; future spec).
- ZK-proving the insights aggregation (bulletins are enclave-signed only, labelled).
- Hosted proving (Bonsai). All proving is local.
- Provider retries. No inference call is ever retried; there are no secondary
  inference calls in the system (insights is fully local).

## 4. Architecture & trust boundary

**Five services** after this work: `apps/web` (:3000), `services/coordinator`
(:4200), `services/mock-provider` (:4300), `services/tee-sim` (:4400), and
**`prover/host` (:4500, localhost only)**. Additions:

- **`prover/`** — new Rust workspace (RISC Zero), three crates:
  - `prover/guest` — the policy engine (deterministic, integer-only), with the
    **complete ruleset compiled into the guest image** (§5.2). **Authoritative.**
  - `prover/host` — daemon on localhost: `POST /execute` (executor run, fast,
    gates requests) and `POST /prove` (async proving queue, §5.6).
  - `prover/verify` — standalone CLI verifier, built with RISC Zero's
    `disable-dev-mode` feature, verifying **offline** against a pinned release
    manifest (§5.2).
- **`services/tee-sim/src/insights/`** — fully local Clio-lite module.
- **`apps/web/src/app/demo/`** — deck mode.

**Trust boundary (stated honestly everywhere):** the simulated confidential
boundary is **`tee-sim` + `prover/host` together**. The prover necessarily
receives the plaintext policy witness (canonical request bytes), and the enclave
acts on `/execute` verdicts before any proof exists — the ZK proof retroactively
verifies the gate; it does not replace trusting the prover process at gate time.
This is the same class of simulation as the TEE itself and is labelled with it.
`prover/host` is subject to the same log-redaction discipline and privacy-test
canary sweep as `tee-sim`.

Demotion: `packages/policy` (TS engine) no longer gates anything. It powers the
Policy Lab live preview only. CI asserts TS-vs-guest agreement (§8).

### Build phases (cumulative; each phase ends in a demoable state)

1. **Intent-bound contribution + real providers** — sealed `CredentialIntentV1`,
   immutable capabilities, anthropic + openai adapters.
2. **Real proof** — Rust guest + executor gating + async STARK proving + offline
   verifier + pinned release manifest + decision/outcome receipt split.
3. **Clio-lite** — local facets, clustering, threshold-suppressed bulletins,
   Insights page.
4. **Deck mode** — guided walkthrough of the full pipeline (depends on 1–3).

Phase 2 begins with a **timing spike** (§9) before anything depends on proving
or executor latency.

## 5. Components

### 5.1 Intent-bound contribution & real providers (Phase 1)

**Credential intent (new, fixes capability-binding gap).** Today the browser
HPKE-seals only the API key; provider and models travel as coordinator-relayed
plaintext, and the enclave signs whatever metadata arrives
(`services/tee-sim/src/index.ts` ingestion). A malicious coordinator could alter
the provider or models before minting and receive a valid capability signature.
Fix:

- The browser seals a versioned **`CredentialIntentV1`** to the attested ingress
  key: `{ version: 1, secret, provider, allowedModels, allowedPolicies,
  contributorId, intentNonce (32 bytes) }` — one HPKE envelope, one AAD-bound
  structure.
- The enclave derives the capability **solely from the decrypted intent**. The
  capability additionally carries `intentDigest = SHA256(canonical intent minus
  secret)` so the capability is bound to exactly what the contributor sealed.
  `blobDigest` binding is unchanged.
- **Capabilities are immutable.** The `/credentials/recapability` endpoint and
  the coordinator's model-editing path are **removed** — in an unauthenticated
  demo, any "edit" API is a widening oracle. Editing = revoke + re-contribute.

**Provider adapters.** `services/tee-sim/src/providers.ts` already defines
`ProviderAdapter`, `ProviderOutcome`, integer micro-USD pricing, and an
`OpenAICompatibleAdapter`. Extend:

- `AnthropicAdapter` — `POST https://api.anthropic.com/v1/messages`, `x-api-key`,
  pinned `anthropic-version`; token counts from response `usage`.
- `OpenAIAdapter` — real base URL + real model list over the existing
  OpenAI-compatible base.
- `mock` — unchanged, used by seeded traffic.
- Egress allow-list becomes exactly `api.anthropic.com`, `api.openai.com`, local
  mock. Process-level discipline, not network enforcement — labelled.

**Cost accounting (honest observations, not guarantees).**

- Receipts keep `estimatedCostMicroUsd` (integer micro-USD) and add
  `pricingTableDigest` — the digest of the checked-in per-model price table the
  estimate was computed from. Token counts are recorded as provider-reported
  observations.
- **`UPSTREAM_OUTCOME_UNKNOWN`**: a timeout after the request was sent is *not* a
  known-zero-spend failure — the provider may have processed and billed it. It is
  a distinct outcome state in the receipt and in cap accounting (which must
  assume the conservative estimate was spent).
- Non-streaming only; `max_tokens` required and policy-capped.

### 5.2 Real ZK proof (Phase 2)

**Guest program** (`prover/guest`): Rust port of the policy engine.

- **Rules are compiled into the guest image.** No host-supplied ruleset: a
  host-selected subset could omit the rule that denies a prompt, making any proof
  unsound relative to the advertised policy. Compiling them in also means a
  one-byte rule change changes the **ImageID** — strengthening the
  measurement/KMS-refusal beat — and removes per-execution JSON parsing.
  Performance-motivated policy changes are policy *version* changes (new ImageID,
  new pinned manifest), never host-side trimming.
- **Guest input — `PolicyInputV1`:** `{ protocolVersion, canonicalRequestBytes,
  requestNonce (32 bytes) }`. The guest computes
  `requestCommitment = SHA256("CTN_REQUEST_V1" || canonicalRequestBytes || nonce)`
  **itself** (matching `packages/protocol/src/crypto.ts`) — it never trusts a
  host-supplied commitment.
- **Journal (public output)** — exactly the existing verifier allowlist, no more:
  `{ protocolVersion, requestCommitment, policyId, decision, proofNonce }`.
  `policyId` is baked in at build. **Category scores never appear in the
  journal** — the current verifier's "no prompt-derived fields" invariant
  (`services/tee-sim/src/verify.ts`) is preserved, not weakened. Scores are a
  **private executor output**: returned alongside the journal to `tee-sim`, used
  for differential testing and sealed into the requester's HPKE-encrypted
  response (that channel exists: `tee-sim/src/index.ts` `encryptedResponse`).
  Scores are never persisted and never appear in any public artifact.

**Gating path:** `tee-sim` calls `POST :4500/execute`; the host runs the guest in
the zkVM **executor** and returns `{ journal, privateScores }` synchronously.
**Executor gating is required.** There is no native-compile fallback — same
source does not guarantee the same compiled semantics as the proved image, and a
gate that diverges from the proof is the exact bug this design exists to prevent.
If the spike (§9) shows unacceptable executor latency, that latency is accepted
and documented; the policy may be slimmed only via a versioned policy change.

**Proving path:** on **every decision — ALLOW and DENY alike** — `tee-sim`
enqueues `POST /prove` (queue semantics: §5.6). The host produces a composite
STARK receipt. On completion `tee-sim` verifies it in-process (subprocess call to
the same verifier code path as `prover/verify`) and signs a `ProofBindingV2`
(§5.5).

**Proof artifact — `ProofArtifactV1`** (replaces stretching the current
`ProofReceipt`): `{ proofSystem: "risc0", risc0Version, receiptCodec:
"bincode-v1", receiptBytes (the serialized receipt), imageId, journalVersion,
decodedJournal }`. Its digest is domain-separated:
`SHA256("CTN_ZK_RECEIPT_V1" || receiptBytes)`. `proverPublicKey` is
simulation-only and absent here. Node invokes verification by spawning the
`prover/verify` binary (subprocess; no FFI).

**Verification & trust anchor:** a checked-in **pinned release manifest**
(`prover/release.json`): `{ imageId, policyId, rulesDigest, journalVersion,
risc0Version, receiptCodec }`. `prover/verify` verifies **offline** against this
manifest — a receipt proves execution of *an* image; the manifest is what says
that image is the approved policy. `verify-receipt --file` must complete with
networking disabled (the current implementation fetches attested keys
unconditionally; that changes — signed artifacts embed the material needed, and
the manifest pins the rest). `pnpm verify-receipt <id>` (online mode) checks the
same things plus coordinator state.

**Dev mode is hard-excluded from the demo:** `tee-sim` and `prover/host` **refuse
to start** if `RISC0_DEV_MODE=1` outside an explicitly-labelled `pnpm dev:fast`
workflow, `prover/verify` is built with the `disable-dev-mode` crate feature, and
receipts record the proving mode. A UI badge alone is insufficient because dev
receipts are fake receipts.

### 5.3 Clio-lite insights — fully local, threshold-suppressed (Phase 3)

Lives in `services/tee-sim/src/insights/`, inside the (expanded) trust boundary.
**No external calls of any kind** — no facet-extraction model call, no cluster
naming call, no insights credential. Raw prompts genuinely never leave the
boundary, and nothing free-text derived from a prompt is ever published.

- **Facets** per allowed request — all computed locally, all closed-form:
  - `category`: closed enum (~12 task types), assigned by nearest-centroid over
    local MiniLM-class ONNX embeddings of the prompt against checked-in seed
    exemplars per category. The enum and exemplar set are defined in
    `policy/v1/manifest.json`, so the facet schema is attested by the same
    measurement as `k_min`.
  - `language`: local detection library.
  - `sensitiveFlagged`: boolean derived from private category scores (the scores
    themselves stay private).
  - `lengthBucket`: coarse bucket.
  - No free-text topic. No model-generated names. A five-word topic or a
    model-written cluster name can reproduce sensitive prompt content; closed
    enums cannot.
- **Embeddings** are computed in-process, used transiently for classification and
  clustering, and never persisted outside the enclave's memory/state; they never
  leave the boundary.
- **Clustering:** k-means over facet embeddings; **cluster labels are
  enum-derived only** (dominant category + language/length mix).
- **Publication — threshold suppression, not anonymity.** The enclave signs an
  insights bulletin containing only clusters with
  `distinctRequesters ≥ k_min` (demo value 3, attested via the manifest).
  Honest labelling, verbatim requirements:
  - `distinctRequesters` counts **unauthenticated requester session ids**, which
    are trivially Sybilable — there is no identity layer (a settled non-goal).
    The mechanism is called **threshold suppression** everywhere; the words
    "anonymous"/"k-anonymity" must not appear in UI or docs claims.
  - **Differencing mitigation:** bulletins are regenerated at most every 60 s
    *and* only after ≥5 new faceted requests; counts are rounded to the nearest
    5. Residual differencing risk is labelled as a known limitation.
- Bulletin: `{ bulletinId, period, clusters: [{ label, roundedCount,
  categoryMix }], kMin, policyId, coverage: { faceted, skipped } }`, signed by the
  enclave. Coordinator stores bulletins; facets, embeddings, and cluster
  membership never leave the boundary.
- **Web:** Insights page renders bulletins with the k notice and the limitation
  labels at equal weight.

### 5.4 Deck mode (Phase 4)

`apps/web/src/app/demo/` — full-screen stepper, keyboard `←/→`, presenter-size
type. One beat per screen: plain-English headline, 2–3 sentences, a live artifact
panel, and a "what's real / what's simulated here" footnote. Drives **one real
request** end-to-end:

1. **Contribute** — seal a real key **and its constraints** in the browser; show
   the single HPKE envelope and the returned capability with `intentDigest`.
2. **Prompt** — compose; show canonical bytes and the commitment (with nonce).
3. **Gate** — attestation document, vault decrypt, capability checks.
4. **Score** — the executor's public journal (commitment, policyId, decision) —
   plus the category scores **decrypted from the requester's own encrypted
   response**, labelled "visible only to you; never in the public journal."
5. **Provider call** — real API round-trip; model, provider-reported token
   counts, estimated micro-USD cost + pricing table digest.
6. **Receipts** — the signed decision receipt and outcome receipt, verified live.
7. **Proof** — polls until the STARK receipt lands (genuinely async; elapsed time
   shown honestly), then shows ImageID vs. the pinned manifest and the offline
   `prover/verify` command the viewer can run themselves.
8. **Insights** — the current bulletin, aggregate only. The deck **does not link
   the live request to a cluster** — the screen says why: linking one
   identifiable request to its cluster is precisely what aggregate publication
   must not do.
9. **Trust recap** — the two-column real/simulated table, updated: real ZK proof
   in the real column; TEE **and prover host** in the simulated column; threshold
   suppression caveats stated.

Implementation: consumes the existing SSE pipeline events; deck state is a thin
client-side machine (step index + awaited event per step). A "seeded mode" toggle
rehearses against the mock provider without spending real money — and without
enqueueing seeded proofs ahead of live ones (§5.6).

### 5.5 Receipt & artifact schema (split, fixes ALLOW-only gap)

The current `ComputeReceipt` hard-codes `decision: "ALLOW"` and only represents
successful provider calls — a denied request would have nothing for a proof to
bind to. Split:

- **`PolicyDecisionReceiptV1`** — signed at decision time for **every** request:
  `{ requestId, requestCommitment, policyId, decision: "ALLOW" | "DENY",
  imageId, timing }`. This is what proofs bind to.
- **`ComputeOutcomeReceiptV2`** — signed after the provider call (ALLOW path
  only): route, usage (+ `pricingTableDigest`), timing, upstream hashes, outcome
  `"success" | "failed" | "UPSTREAM_OUTCOME_UNKNOWN"`.
- **`ProofBindingV2`** — binds the `ProofArtifactV1` digest to the
  `PolicyDecisionReceiptV1` (not to the outcome receipt).

**`PROVER_UNAVAILABLE` is a system failure (503-class), never a policy DENY.**
Requests still fail closed (no gate → no provider call), but the outcome is
recorded as system failure so infrastructure outages cannot contaminate denial
metrics or the graph's denial visuals.

### 5.6 Proving queue

Every request (allow and deny) enqueues a proof, and composite proving takes
30 s–3 min, so the queue needs real semantics:

- Concurrency 1 (single M1; measured by the spike).
- FIFO with two priority classes: **live** (deck / interactive) ahead of
  **seeded**; seeded jobs are capped at 3 queued at a time and dropped-oldest
  beyond that (drop recorded in the proof status — visible absence, as ever).
- Queue persisted in the coordinator's SQLite; jobs resume after restart.
- Backpressure: if the queue exceeds a bound (default 25), new seeded requests
  skip proving entirely (status `NOT_REQUIRED`, labelled), live requests never
  skip.

## 6. Data flow (end to end)

Browser seals `CredentialIntentV1` (key + constraints, one envelope) →
coordinator stores blob (opaque) → enclave decrypts intent, derives + signs
immutable capability (`intentDigest`, `blobDigest`) → prompt submitted with
canonical bytes + nonce → tee-sim: attestation-gated vault decrypt → prover
`/execute` (executor; authoritative gate; journal + private scores) →
`PolicyDecisionReceiptV1` signed → ALLOW → provider adapter → real API →
response digested → `ComputeOutcomeReceiptV2` signed; scores sealed into the
requester's encrypted response → async `/prove` (queued) → STARK receipt
verified (subprocess) → `ProofBindingV2` signed → SSE to graph, receipt viewer,
deck. In parallel per allowed request: local facet classification → local
embedding/clustering (enclave-only state) → bulletin (≥ k_min, ≥5 new, 60 s,
rounded) signed → coordinator → Insights page.

## 7. Error handling

- **Fail closed, classified honestly:** prover daemon down → request refused as
  `PROVER_UNAVAILABLE` **system failure** (503-class), never a DENY; no provider
  call. Consistent with the §69 type-state gate — there is no unscored path.
- **Provider errors:** existing `classification` taxonomy drives outcomes
  (`auth_failed` disables the credential; `rate_limited` cools down). Failed
  calls produce honest failed-outcome receipts. Timeouts after send →
  `UPSTREAM_OUTCOME_UNKNOWN` (spend assumed at estimate). No retries.
- **Proving failure/timeout:** decision receipt stays valid; proof status
  `FAILED` in viewer and deck. Visible absence, never fake success.
- **Facet classification failure:** skip; bulletin coverage records it.
- **Key safety:** provider key plaintext exists only in enclave memory during the
  call. `safe-log` redaction gains explicit tests for `x-api-key`,
  `Authorization`, and key material in error bodies — and the same discipline
  and tests apply to **`prover/host` logs** (it sees plaintext witnesses).
  Real keys never enter seeded/demo fixtures.
- **Deck resilience:** each beat has a timeout state with an honest failure
  message (e.g. "this is a real proof; it takes minutes").

## 8. Testing

**Differential (CI, blocking) — TS engine vs Rust guest via executor:**

- All 125 policy fixtures: private score vectors and decisions identical.
- Canonical request bytes byte-identical; request commitments (incl. nonce)
  identical; NFKC normalization output identical.
- Rules digest / policyId / imageId consistency with the pinned manifest.
- **Randomized Unicode differential tests are required from day one** (property
  tests over adversarial unicode: fullwidth, ZWJ, combining marks, mixed
  normalization forms) — not added "if divergence appears".

**Adversarial suite:**

- Coordinator tampering with provider/models at contribution → capability
  mint must fail (intent digest mismatch).
- Any capability-widening attempt (the removed recapability path, direct
  re-signing) → no endpoint exists; regression test asserts absence.
- Forged/absent decision receipt for a denial → verifier rejects.
- Journal with extraneous fields (e.g. scores) → verifier rejects (existing
  invariant, retained).
- Offline verification with networking disabled (`--file` path) → must pass.
- Dev-mode receipt presented as real → verifier (built `disable-dev-mode`)
  rejects; demo startup with `RISC0_DEV_MODE=1` → refuses to boot.
- Prover log canary: privacy-test canary sweep extended to `prover/host`
  stdout/stderr/logs and all insights surfaces (facets, bulletins, coordinator
  DB, Insights page, deck artifacts).
- Queue saturation: seeded flood must not starve a live proof; bounds honored.
- Bulletin differencing: consecutive bulletins must not reveal a single new
  request's facets (rounding + ≥5-new gate asserted).

**Other:**

- Proving/executor benchmarks from the spike recorded in `VALIDATION.md`
  (updates §66 latency findings).
- E2E: mock path always-on; real-provider smoke test (tiny `max_tokens`) only
  when `ANTHROPIC_API_KEY` / `OPENAI_API_KEY` present.
- `verify-receipt` E2E: tampered journal, wrong image ID, wrong codec version.
- Insights unit tests: threshold enforcement (k−1 withheld), rounding, coverage
  accounting, no-free-text invariant (bulletin schema rejects strings outside
  the enum).
- Deck: Playwright walkthrough of all nine beats in seeded mode.

## 9. Risks & spikes

1. **Executor gating latency** — unknown until measured. Spike: run the guest
   via executor on representative requests. If slow, the latency is accepted and
   documented (no native fallback; §5.2). Policy slimming only via versioned
   policy change.
2. **Proving time** — estimated 30 s–3 min composite on M1 Pro (Metal). The
   deck's proof beat absorbs it honestly. If > ~10 min, slim the policy via a
   **versioned policy change** (new ImageID, new manifest) — never host-side
   subsetting.
   > [Phase 2a measured: ~50 s composite for a 4 KB hash-only guest, CPU-only —
   > risc0 3.0.6 does not dispatch to Metal. The estimate's range was about
   > right; its stated cause was not. See VALIDATION.md §2c.]
3. **Rust port fidelity** — NFKC + token-aware matching must match TS exactly.
   Fixtures + required randomized differential tests (§8) are the contract.
4. **ONNX embeddings inside the enclave process** — memory/startup cost unknown.
   Fallback: a separate local worker process, explicitly documented as inside
   the simulated trust boundary (same label as `prover/host`).
5. **Real-key handling during demos** — a revoked/mistyped key mid-demo is an
   `auth_failed` beat; rehearse in seeded mode; keep a backup key.
6. **Queue behavior under demo load** — §5.6 bounds; asserted by the saturation
   test.

## 10. Labelling requirements (unchanged invariant, updated content)

The trust page, README, VALIDATION.md, and deck footnotes must state, at equal
visual weight with the guarantees:

- The TEE is simulated (ordinary process; self-signed attestation).
- **The simulated confidential boundary is `tee-sim` + `prover/host`**; the
  gate trusts the prover's executor verdict at request time; the ZK proof
  verifies it after the fact.
- The ZK proof is real (RISC Zero composite STARK), verified offline against a
  pinned manifest; dev-mode is refused at demo startup.
- Insights are **threshold-suppressed aggregates**, not anonymity: requester
  counts are unauthenticated and Sybilable; differencing risk is mitigated
  (rounding, ≥5-new, 60 s) but not eliminated.
- Spend figures are estimates from a pinned pricing table over
  provider-reported token counts; timeouts can leave upstream spend unknown.
- There is no authentication; the system must not be network-exposed.

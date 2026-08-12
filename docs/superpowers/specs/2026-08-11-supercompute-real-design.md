# Supercompute "For Real" — Design

**Date:** 2026-08-11
**Status:** Approved (design review with Ankit, this session)
**Repo:** `compute-trust-network`
**Predecessor:** v0.1 prototype (see `HANDOFF.md`, `VALIDATION.md`)

## 1. Goal

Take the v0.1 prototype — where key encryption and receipt signing are real but the
trust root is simulated — and make the end-to-end flow real for a local demo:

1. A real API key is contributed and HPKE-encrypted in the browser (already real).
2. A prompt is proxied through the enclave to a **real provider** (Anthropic or
   OpenAI), spending that key.
3. Policy compliance is proved with a **real ZK proof** (RISC Zero STARK), not a
   signed re-execution.
4. The signed receipt binds validated input/output to the policy verdict (already
   real; upgraded to reference the real proof).
5. A **Clio-style anonymous insights layer** shows contributors what their compute
   is used for, without anyone seeing a raw prompt.
6. A **guided deck mode** walks a viewer through one real request step by step,
   in plain language, showing live artifacts.

**The honesty invariant from v0.1 carries over unchanged:** every remaining
simulation (the TEE itself, the signed-not-proved insights bulletin, dev-mode
proofs if ever active) is labelled at equal weight with the guarantees, in the UI,
README, and VALIDATION.md. No change may soften this labelling.

## 2. Decisions (settled in design review)

| Question | Decision |
|---|---|
| Trust mechanism to make real | **Real ZK proof** (RISC Zero, local M1 Pro). TEE stays simulated, labelled. |
| Provider | **Both Anthropic and OpenAI**, chosen per-credential at contribution time. Mock retained as third adapter for seeded traffic. |
| Deployment | **Local demo only.** No auth work. Must not be network-exposed (unchanged from v0.1). |
| Clio insights | **In scope, full**: facets + local embeddings + clustering + model-named clusters, k-anonymity threshold, enclave-signed bulletins. |
| Demo UX | **Deck mode**: full-screen step-by-step guided walkthrough driving one real request. |
| Engine authority | **Single engine — Rust.** The RISC Zero guest is the authoritative policy engine; it gates requests via the zkVM executor and the same image is proved async. TS engine demoted to UI preview, CI-cross-validated. |

## 3. Non-goals

- Streaming responses (receipts hash complete input/output).
- Authentication, rate limiting, hosting (separate future spec; prerequisite for any deployment).
- Real TEE hardware attestation (requires cloud confidential VM; future spec).
- ZK-proving the insights aggregation (bulletins are enclave-signed only, labelled as such).
- Hosted proving (Bonsai). All proving is local.
- Retries on provider failure (idempotency/replay design deferred).

## 4. Architecture

Existing four-service shape survives: `apps/web` (:3000), `services/coordinator`
(:4200), `services/mock-provider` (:4300), `services/tee-sim` (:4400). Additions:

- **`prover/`** — new Rust workspace (RISC Zero), three crates:
  - `prover/guest` — the policy engine (deterministic, integer-only), compiled to
    a zkVM guest image. **Authoritative.**
  - `prover/host` — daemon on localhost (:4500): `POST /execute` (executor run,
    fast, gates requests) and `POST /prove` (async proving jobs).
  - `prover/verify` — standalone CLI verifier: checks the STARK receipt, image ID,
    and journal fields. Anyone can run it without trusting this machine.
- **`services/tee-sim/src/insights/`** — Clio-lite module inside the enclave
  (the only place plaintext exists).
- **`apps/web/src/app/demo/`** — deck mode.

Demotion: `packages/policy` (TS engine) no longer gates anything. It powers the
Policy Lab live preview only. CI asserts TS-vs-guest agreement on all 125 fixtures.

### Build phases (each independently demoable)

1. **Real providers** — anthropic + openai adapters, provider bound in capability.
2. **Real proof** — Rust guest + executor gating + async STARK proving + verifier CLI.
3. **Clio-lite** — facets, local embeddings, clustering, signed bulletins, Insights page.
4. **Deck mode** — guided walkthrough stitching 1–3 together.

Phase 2 begins with a **timing spike** (see §9 Risks) before anything depends on
proving or executor latency.

## 5. Components

### 5.1 Real provider adapters (Phase 1)

- `services/tee-sim/src/providers.ts` already defines `ProviderAdapter`,
  `ProviderOutcome` (with `classification: "auth_failed" | "rate_limited" |
  "server_error" | "timeout" | "egress_denied"`), integer micro-USD pricing, and an
  `OpenAICompatibleAdapter`. Extend, don't replace:
  - `AnthropicAdapter` — `POST https://api.anthropic.com/v1/messages`,
    `x-api-key` header, `anthropic-version` pinned. Maps request/response to the
    protocol's canonical shapes; token counts from `usage` in the response.
  - `OpenAIAdapter` — `POST https://api.openai.com/v1/chat/completions`,
    `Authorization: Bearer`. The existing `OpenAICompatibleAdapter` is the base;
    real base URL + real model list.
  - `mock` — existing mock-provider, unchanged wire format, used by seeded traffic.
- `Provider` type (`packages/protocol/src/types.ts`) already includes
  `"anthropic" | "openai" | "mock"` (`"google"` remains declared but unimplemented;
  contribution UI offers only implemented providers).
- **Provider binding:** the contributor picks the provider at contribution time and
  it is signed inside the capability (alongside the existing `blobDigest`), so a
  malicious coordinator cannot re-point a credential at a different provider.
- **Pricing:** real per-model integer micro-USD tables for the supported model
  lists. Pre-call cap check uses a conservative estimate (prompt tokens measured,
  `max_tokens` as output bound); post-call actuals from the provider `usage` are
  recorded in the receipt. Caps remain operational accounting, as in v0.1.
- **Egress:** `assertEgressAllowed` allow-list becomes exactly
  `api.anthropic.com`, `api.openai.com`, and the local mock. Documented honestly:
  process-level discipline, not network-level enforcement (TEE is simulated).
- Non-streaming only; `max_tokens` required and capped by policy.

### 5.2 Real ZK proof (Phase 2)

- **Guest program** (`prover/guest`): Rust port of the policy engine. Input: the
  canonicalized request bytes (existing JCS-style canonicalisation) + `rules.json`
  bytes. Journal (public output): `{ rules_digest, request_commitment,
  category_scores[7], decision }`. All integer arithmetic; NFKC normalisation and
  token-aware matching semantics preserved exactly (the 125 fixtures are the
  contract).
- **Gating path:** `tee-sim` calls `POST :4500/execute`. The host runs the guest
  in the zkVM **executor** (no proof) and returns the journal synchronously. The
  enclave's authorize gate (§69 type-state, `authorize.ts`) consumes this verdict;
  the TS engine is removed from the gating path. Fail closed: prover daemon
  unreachable → request denied with `PROVER_UNAVAILABLE`.
  - Fallback (decided by spike): if executor latency exceeds ~250 ms, the host
    runs the same crate compiled natively for gating. Same source, same fixtures;
    the image is still what gets proved.
- **Proving path:** on every decision — ALLOW and DENY alike, so denials are
  provable too — `tee-sim` enqueues `POST /prove`. The host produces a **composite
  STARK receipt**. On completion `tee-sim` verifies it in-process, then signs the
  existing `ProofBinding` referencing the receipt digest and image ID.
  `proofSystem` moves from `"simulated-reexec"` to `"risc0"` (the union in
  `types.ts` already declares it). Receipt files are stored by the coordinator and
  downloadable from the receipt viewer.
- **Verification:** `pnpm verify-receipt <id>` gains a step that invokes
  `prover/verify` on the downloaded STARK receipt: checks seal validity, image ID
  against the published measurement, and journal fields against the
  `ComputeReceipt` (request commitment, rules digest, decision).
- **Measurement story:** the image ID (code) is published in the attestation
  document; the journal's `rules_digest` (policy version) preserves the
  one-byte-policy-change → `KMS_REFUSED` demo beat. `policy_id` derivation is
  unchanged.
- **Dev mode:** `RISC0_DEV_MODE=1` permitted for development iteration only. The
  attestation document and UI proof badge carry `devMode: true|false`; the deck
  and trust page must show real mode. CI runs real proving for at least one
  fixture nightly-equivalent (`pnpm test:prove`).

### 5.3 Clio-lite insights (Phase 3)

- Lives in `services/tee-sim/src/insights/` — inside the trust boundary, because
  facet extraction reads plaintext prompts.
- **Insights credential:** facet extraction and cluster naming use a designated
  operator-contributed credential (cheap model, e.g. Haiku-class), contributed
  through the normal flow with its own spend cap and provider binding. Its calls
  produce ordinary receipts tagged `purpose: "insights"` — the insights layer is
  itself a policy-bound workload. Requests tagged `purpose: "insights"` are
  **excluded from facet extraction** (no recursion: a facet call must never
  trigger another facet call). If its cap is exhausted, facet extraction skips
  (request unaffected) and the next bulletin records the coverage gap.
- **Facets** per allowed request: `{ category: closed enum, topic: ≤5 words,
  language: ISO code, sensitive: bool }`. The category enum (~12 task types) is
  defined in `policy/v1/manifest.json` alongside `k_min`, so the facet schema is
  attested by the same measurement as the privacy threshold. Extracted by one
  schema-constrained model call; output validated, retry once on schema failure,
  then skip.
- **Embeddings:** computed locally inside the enclave process (MiniLM-class ONNX
  model via transformers.js) over the **facet strings only**. Raw prompts are
  never embedded, never leave the enclave, and never appear in any insights store.
- **Clustering:** k-means over facet embeddings (small n; k chosen by silhouette
  over a small range). Cluster naming: one model call per cluster over its facet
  summaries (insights credential).
- **Publication:** the enclave signs an **insights bulletin**:
  `{ bulletin_id, period, clusters: [{ name, count, distinct_requesters,
  category_mix }], k_min, policy_id, coverage: { faceted, skipped } }` — including
  **only clusters with `distinct_requesters ≥ k_min`**. `k_min` (demo value: 3)
  lives in `policy/v1/manifest.json`, so it is covered by the measurement: changing
  the privacy threshold changes the measurement and trips `KMS_REFUSED`. The
  coordinator stores bulletins; raw facets/embeddings/cluster membership never
  leave the enclave. Cadence: a bulletin is regenerated at most every 60 s and
  only when new faceted requests exist since the last one.
- **Web:** an Insights page renders bulletins (cluster cards, counts, k notice).
  Labels, at equal weight: bulletins are enclave-signed, **not ZK-proved**; demo
  volume comes from seeded mock traffic plus real requests.
- **Privacy test:** the existing canary methodology extends to all insights
  surfaces — a canary prompt must never appear in facets, bulletins, coordinator
  storage, or the Insights page.

### 5.4 Deck mode (Phase 4)

- `apps/web/src/app/demo/` — full-screen stepper, keyboard `←/→`, presenter-size
  type, Geist. One beat per screen: plain-English headline, 2–3 sentences, a live
  artifact panel, and a "what's real / what's simulated here" footnote.
- Drives **one real request** end-to-end as the presenter advances:
  1. **Contribute** — encrypt a real key in the browser; show actual HPKE
     ciphertext bytes and the signed capability JSON (provider binding visible).
  2. **Prompt** — compose; show the request commitment.
  3. **Gate** — attestation document, vault decrypt, capability checks.
  4. **Score** — executor journal: category scores, decision, rules digest.
  5. **Provider call** — real API round-trip; model, token counts, integer
     micro-USD cost.
  6. **Receipt** — signed `ComputeReceipt`, verified live in the browser.
  7. **Proof** — screen polls until the STARK receipt lands (genuinely async;
     the deck says so and shows elapsed time), then shows image ID, journal, and
     the `prover/verify` command the viewer can run themselves.
  8. **Insights** — the request's cluster appearing (or withheld under k), the
     k notice, the bulletin signature.
  9. **Trust recap** — the two-column real/simulated table, updated: ZK proof
     moves to the real column; TEE stays simulated.
- Implementation: consumes the same SSE pipeline events the graph already uses;
  deck state is a thin client-side machine (step index + awaited event per step).
  A "seeded mode" toggle runs the deck against mock provider for rehearsal
  without spending real money.

## 6. Data flow (end to end)

Browser HPKE-encrypts key → coordinator stores blob → capability signed (binds
`blobDigest` + provider) → prompt submitted with commitment → tee-sim:
attestation-gated vault decrypt → prover `/execute` (authoritative gate) →
ALLOW → provider adapter → real API → response digested → `ComputeReceipt`
signed → async `/prove` → STARK receipt verified in-enclave → `ProofBinding`
signed → SSE to graph, receipt viewer, deck. In parallel per allowed request:
facet call (insights credential) → local embedding → cluster store (enclave-only)
→ periodic bulletin (≥ k_min) signed → coordinator → Insights page.

## 7. Error handling

- **Fail closed:** prover daemon down → deny (`PROVER_UNAVAILABLE`), no provider
  call. Consistent with the §69 type-state gate — there is no unproven-scored path.
- **Provider errors:** existing `classification` taxonomy drives outcomes
  (`auth_failed` disables the credential; `rate_limited` cools down). Failed calls
  produce honest failed-outcome receipts; no retries in v1.
- **Proving failure/timeout:** the `ComputeReceipt` stays valid; proof status
  shows `failed` in the viewer and deck. Visible absence, never fake success.
- **Facet-call failure:** skip after one retry; bulletin coverage records it.
- **Key safety:** provider key plaintext exists only in enclave memory during the
  call. `safe-log` three-layer redaction gains explicit tests for `x-api-key` and
  `Authorization` headers and for key material in error bodies. Real keys never
  enter seeded/demo fixtures.
- **Deck resilience:** each beat has a timeout state with an honest failure
  message (e.g. proof still running — "this is a real proof; it takes minutes").

## 8. Testing

- **Fixture cross-validation (CI, blocking):** all 125 policy fixtures run against
  (a) TS engine, (b) Rust guest via executor. Score vectors and decisions must be
  identical. Divergence fails CI.
- **Proving benchmarks (spike, then recorded):** executor latency and composite
  proving time on the M1 Pro, measured before Phase 2 lands; results in
  `VALIDATION.md` (updates the §66 latency findings).
- **E2E:** `scripts/test-e2e.mts` keeps the mock path always-on; adds a
  real-provider smoke test (tiny `max_tokens`) that runs only when
  `ANTHROPIC_API_KEY` / `OPENAI_API_KEY` are present in env.
- **Receipt verification:** `verify-receipt` E2E extended to run the Rust
  verifier and to fail on a tampered journal, wrong image ID, or dev-mode receipt
  presented as real.
- **Privacy:** `privacy-test.ts` canary sweep extended to insights surfaces
  (facets, bulletins, coordinator DB, Insights page, deck artifacts).
- **Deck:** Playwright walkthrough of all nine beats against the seeded stack in
  seeded mode.
- **Insights unit tests:** k-threshold enforcement (cluster with k−1 requesters
  withheld), coverage accounting, schema-validation retry/skip.

## 9. Risks & spikes

1. **Executor gating latency** — unknown until measured. Spike task: run the
   guest via executor on representative requests. If > ~250 ms, use native-compile
   fallback for gating (§5.2). Decision recorded in VALIDATION.md.
2. **Proving time** — estimated 30 s–3 min composite on M1 Pro (Metal). If worse,
   the deck's proof beat design (poll + honest elapsed time) already absorbs it;
   if > ~10 min, reduce guest input size (rules subsetting) before weakening
   anything else.
3. **Rust port fidelity** — NFKC + token-aware matching must match TS exactly.
   The 125 fixtures are the contract; add property tests (random unicode strings,
   both engines) if divergence appears.
4. **transformers.js inside the enclave process** — memory/startup cost unknown.
   Fallback: a separate local worker process that is documented as inside the
   simulated trust boundary (same honesty label as the TEE itself).
5. **Real-key handling during demos** — a revoked/mistyped key mid-demo is an
   `auth_failed` beat; rehearse with seeded mode, keep a backup key.

## 10. Labelling requirements (unchanged invariant)

The trust page, README, VALIDATION.md, and deck footnotes must state, at equal
visual weight with the guarantees:

- The TEE is simulated (ordinary process; self-signed attestation).
- The ZK proof is now real (RISC Zero composite STARK) — and whether dev-mode
  was active for any given receipt.
- Insights bulletins are enclave-signed, not ZK-proved; k_min is attested via
  the measurement.
- Spend caps are operational accounting, not cryptographic guarantees.
- There is no authentication; the system must not be network-exposed.

# Session Handoff — Supercompute: Phase 2a complete (standalone RISC Zero prover), pending final review

- **Date:** 2026-08-14 (Phase 1 section below dated 2026-08-12)
- **Repo / branch:** `compute-trust-network` @ `phase2a-standalone-prover`, branched from `main` after the Phase 1 merge. Not yet merged.
- **Prepared by:** Claude (Fable 5) with Ankit

## Phase 2a — what now exists

Plan: `docs/superpowers/plans/2026-08-12-phase2a-standalone-prover.md`; ledger:
`.superpowers/sdd/2026-08-12-phase2a-standalone-prover/progress.md` (on disk, not
committed — `.superpowers/sdd/.gitignore` is `*`). Seven tasks, all complete.

`prover/` is a real RISC Zero workspace and **nothing calls it**:

- **The guest image is Safety Policy v1.** `policy/v1/{rules,manifest}.json` are
  compiled into the image as a prepared form, the request commitment is
  recomputed inside the zkVM, and the journal is exactly
  `{decision, policyId, proofNonce, protocolVersion, requestCommitment}`.
  ImageID `75751480a7e7d6b329de6614fee99e8d2cf9a793c32e9c1e3de057f8196b0ee1`.
- **`policy-core`** is a line-for-line port of `packages/policy/src/engine.ts`,
  held to it by `scripts/differential-test.ts` (CI-blocking, part of `pnpm test`):
  125 fixtures, generated Unicode adversarial cases, a full 1,112,064-code-point
  skew sweep, six end-to-end cases through the real image, and 18 manifest
  canonicalizer probes.
- **`host --serve`** is a loopback daemon on `127.0.0.1:4500`: `/execute` (the
  executor fast path), `/prove` (202 + a single-worker in-memory FIFO), `/jobs/:id`,
  `/health`. It refuses to start under `RISC0_DEV_MODE` without `--dev`, and
  refuses a non-local prover backend outright.
- **`prover-verify`** is a standalone offline verifier: 13 named checks against
  the pinned `prover/release.json`, no network in its dependency graph, dev-mode
  receipts rejected cryptographically (the `disable-dev-mode` feature, not a
  string check). Five real receipts are committed as fixtures.
- **Measured, not modelled.** See `prover/README.md` "Measured on this machine"
  and `VALIDATION.md` §2c. The short version: the executor gate costs ~56 ms
  across the whole fixture corpus, a composite proof takes two to three minutes
  of CPU on an M1 Pro, a receipt is ~525 KB, and verification is milliseconds.

**What Phase 2b has to wire**, none of which exists yet: `tee-sim` calling
`/execute` on the request path and `/prove` off it; the decision/outcome receipt
split (§5.5); queue persistence and real backpressure (§5.6); a `PROVER_UNAVAILABLE`
state; reconciling the TypeScript `policyId` with the guest's `POLICY_ID_V2`; a TS
verifier matching `prover-verify`'s checks; and the trust-page rewrite. Until then
every proof artifact the demo shows is still `simulated-reexec`, and the trust page
says so — it was read during Phase 2a and deliberately left unchanged, because
nothing on it became false.

## Where things stand (Phase 1)

**v0.1 prototype** (on `main`): the full simulated demo — HPKE vault, policy engine,
simulated TEE, signed receipts, live graph. See git history and `VALIDATION.md`.

**Phase 1** (this branch, complete): the first "for real" slice of the approved spec at
`docs/superpowers/specs/2026-08-11-supercompute-real-design.md`:

- **Intent-bound contribution.** The API key AND its constraints (provider, pinned
  snapshot model IDs, policies, client-chosen credentialId, nonce) travel in ONE HPKE
  envelope (`CredentialIntentV1`); the enclave derives capabilities solely from the
  decrypted intent (`services/tee-sim/src/intent.ts`) and rejects replays. The
  recapability endpoint is gone; capabilities are immutable; revocation is terminal
  and *enforced* (runtime status validation + a race guard, both tested).
- **Real provider adapters.** `AnthropicAdapter` (`/v1/messages`, `x-api-key`, pinned
  version, clamps) + real OpenAI wiring, catalog-driven registry
  (`services/tee-sim/src/catalog.ts` — dated snapshot IDs only), narrowed egress.
  Malformed 200s and every post-dispatch failure are UNKNOWN outcomes; a 3xx is
  `redirect_refused` (dispatched, terminal).
- **Single dispatch.** Once bytes leave the enclave, routing terminates — no
  second credential ever sees the prompt. Rate-limit "fallback" now happens at
  request granularity via cooldown (DEMO.md updated; seeded demo shows 5 complete /
  1 FAILED, truthfully).
- **Honest cost accounting.** Pinned integer pricing table + digest in receipts;
  worst-case UTF-8-byte bound; unknown outcomes book conservative assumed spend
  atomically against the same daily counters (schema migration included).
- **Redaction hardening, provider catalog endpoint + UI wiring, gated real-provider
  smoke tests (e2e 70/71), and the honesty-labelling pass** (README table, trust
  page, VALIDATION §2b).

**Gates at HEAD (`5a86b1a`):** tsc clean · unit 88/88 · web build clean ·
e2e 28/28 + 2 env-gated skips (fresh stack) · privacy-test clean.

## Live-key status

**Case 70 (real Anthropic round-trip) PASSED with a live key on 2026-08-13** — twice:
sealed-intent contribution, one real dispatch to `api.anthropic.com`
(`claude-haiku-4-5-20251001`, 15/5 tokens, est $0.000040 from pinned price table
`0x6c0977f2`), COMPLETE receipt, credential auto-revoked, terminal revocation held.
A reusable test key lives in the gitignored `.env.local` (semi-exposed — keep a
provider-side spend cap on it). **Case 71 (OpenAI) has still never run with a live
key.** To rerun:

```bash
set -a; source .env.local; set +a; pnpm test:e2e   # add OPENAI_API_KEY=… for 71
```

## Open items (triaged, none merge-blocking)

- ~~Parked from final review: the `max_tokens` assumed-spend ceiling~~ **closed
  on this branch** (`8e2949f`): VALIDATION §2b now labels the caller-chosen half —
  the clamp is the pinned model's 64,000 output ceiling, so a caller sending
  128,000 books roughly 60× (not 125×) more assumed spend than the 1,024 default.
  A real per-credential output-token cap remains the stronger fix, unscheduled.
- Carry list (all reviewed, all fine-to-carry): redaction `\b` prefix gap;
  `events.ts` missing `xapikey`; `enclaveLog` dead code has no key-name layer;
  PATCH accepts weight/limits on DELETED rows (labelled in VALIDATION §2b);
  `PRICING_TABLE` mutability + unpinned digest test; `providerTimeoutMs` unguarded
  `Number()`; `policy/page.tsx` single-shot fetch; `/v1/models` no dedupe +
  could advertise an unpriced model (unreachable today); tee-client has no fetch
  timeout (inherited pattern); assorted one-directional test assertions.

## Next phases (per the approved spec — each gets its own plan)

- **Phase 2a — the standalone prover: DONE** (this branch). RISC Zero workspace,
  policy engine in the image, `--serve` daemon, offline verifier, pinned release
  manifest, dev mode hard-refused, everything measured. See the section at the top.
- **Phase 2b — wiring it in:** `tee-sim` calls `/execute` on the request path and
  `/prove` off it; decision/outcome receipt split (§5.5); queue persistence and
  backpressure (§5.6); `PROVER_UNAVAILABLE`; TS-side `policyId` v2 reconciliation;
  a TypeScript verifier matching `prover-verify`'s thirteen checks; trust-page
  rewrite. The plan is not written yet — the accumulated carry-forwards are
  consolidated at the end of
  `.superpowers/sdd/2026-08-12-phase2a-standalone-prover/progress.md` under
  "PHASE 2B CARRY-FORWARD", and that block is the input to writing it.
- **Phase 3 — Clio-lite insights:** fully local (closed enums, local embeddings,
  threshold suppression — never "anonymity"), enclave-signed bulletins.
- **Phase 4 — deck mode:** `/demo` guided walkthrough driving one real request.

## How to resume

```bash
cd ~/code/supercompute/compute-trust-network
node scripts/dev.mjs   # web :3000, coordinator :4200, mock :4300, tee-sim :4400
pnpm seed              # if .data was reset
```

The prover is not part of `pnpm dev` and does not need to be running for any of
the above. To exercise it:

```bash
cd prover
cargo run -rp host -- --bench --fixtures     # ~30 s, all 125 fixtures through the real image
cd .. && cargo run --release --manifest-path prover/verify/Cargo.toml -p prover-verify -- \
  --receipt prover/verify/tests/fixtures/allow-real.receipt.bin   # builds if needed
```

**Gates at Phase 2a HEAD:** `cargo fmt --check` (prover + verify + guest) ·
`cargo clippy -D warnings` (prover workspace, verify workspace, guest
incantation) · `cargo test` 81 pass / 1 ignored (prover) + 33 (verify) ·
`npx tsc --noEmit` clean · `pnpm test` 88 unit + the differential (625/625, the
1,112,064-code-point skew sweep, 6 guest cases at imageId `75751480…`, 18
canonicalizer probes) · `pnpm --filter web build` clean. ImageID unchanged
through the whole phase, including a cold rebuild under the newly pinned host
toolchain.

Spec: `docs/superpowers/specs/2026-08-11-supercompute-real-design.md` ·
Phase 1 plan: `docs/superpowers/plans/2026-08-11-phase1-intent-providers.md` ·
Phase 2a plan: `docs/superpowers/plans/2026-08-12-phase2a-standalone-prover.md` ·
Demo script: `DEMO.md` (updated for single dispatch) · Honesty ledger:
`VALIDATION.md` §2b (Phase 1) and §2c (Phase 2a).

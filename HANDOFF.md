# Session Handoff — Supercompute: Phase 1 complete (real providers, intent-bound contribution)

- **Date:** 2026-08-12
- **Repo / branch:** `compute-trust-network` @ `phase1-intent-providers` (22 commits ahead of `main`), not yet merged
- **Prepared by:** Claude (Fable 5) with Ankit

## Where things stand

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

- **Parked from final review:** VALIDATION's `max_tokens` clause labels the
  "required" half but not "policy-capped" — a caller passing `max_tokens: 128000`
  raises the assumed-spend ceiling ~125×. One honest sentence (or a real cap) closes it.
- Carry list (all reviewed, all fine-to-carry): redaction `\b` prefix gap;
  `events.ts` missing `xapikey`; `enclaveLog` dead code has no key-name layer;
  PATCH accepts weight/limits on DELETED rows (labelled in VALIDATION §2b);
  `PRICING_TABLE` mutability + unpinned digest test; `providerTimeoutMs` unguarded
  `Number()`; `policy/page.tsx` single-shot fetch; `/v1/models` no dedupe +
  could advertise an unpriced model (unreachable today); tee-client has no fetch
  timeout (inherited pattern); assorted one-directional test assertions.

## Next phases (per the approved spec — each gets its own plan)

- **Phase 2 — real ZK proof:** RISC Zero workspace (`prover/`), Rust guest is the
  authoritative policy engine (executor gates, same image proves async), rules
  compiled into the image, decision/outcome receipt split, offline verifier +
  pinned release manifest, dev-mode hard-refused. **Starts with the timing spike**
  (executor latency + proving time on the M1 Pro) — the plan's shape depends on it.
- **Phase 3 — Clio-lite insights:** fully local (closed enums, local embeddings,
  threshold suppression — never "anonymity"), enclave-signed bulletins.
- **Phase 4 — deck mode:** `/demo` guided walkthrough driving one real request.

## How to resume

```bash
cd ~/code/supercompute/compute-trust-network
node scripts/dev.mjs   # web :3000, coordinator :4200, mock :4300, tee-sim :4400
pnpm seed              # if .data was reset
```

Spec: `docs/superpowers/specs/2026-08-11-supercompute-real-design.md` ·
Phase 1 plan: `docs/superpowers/plans/2026-08-11-phase1-intent-providers.md` ·
Demo script: `DEMO.md` (updated for single dispatch) · Honesty ledger:
`VALIDATION.md` §2b.

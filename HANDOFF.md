# Session Handoff — Supercompute: compute trust network prototype

- **Date:** 2026-08-11 21:59
- **Repo / branch:** `compute-trust-network` @ no branch (git initialised, **zero commits**)
- **Prepared by:** Claude (Fable 5) with Ankit

## Objective

Validate the *Compute Trust Network Prototype v0.1* spec (`/Users/ankit/code/supercompute/Compute Trust Network Prototype.md`)
and build a demo of it that holds up to scrutiny. The thesis: **a person can contribute AI
compute and cryptographically constrain how it is used, without seeing the workloads that use
it.** Renamed to **Supercompute** mid-session.

## What's been done

**Full working prototype**, ~13k lines, running locally with one command.

- `packages/protocol` — canonicalisation (JCS-style, integer-only), request commitments, HPKE
  (RFC 9180 via `@hpke/core`), Ed25519, shared types.
- `packages/policy` — Safety Policy v1: deterministic integer scoring engine + 125 fixtures
  (50 allow / 50 deny / 25 adversarial), all passing.
- `packages/client` — the secure client; identical code in browser and Node.
- `services/tee-sim` — the confidential service: attestation, vault, policy gate, routing
  authorisation, provider adapter, prover, receipt signer.
- `services/coordinator` — public API, SQLite, outbox, graph projector, SSE.
- `services/mock-provider` — OpenAI-shaped upstream stand-in.
- `apps/web` — Next.js 16: live graph, playground, contributor onboarding, dashboards, policy
  lab, trust model, receipt viewer.
- Docs: `README.md`, `VALIDATION.md` (spec critique), `DEMO.md` (5-minute script),
  `policy/v1/README.md`.

**Graph renderer is custom** (`apps/web/src/components/graph/`) — canvas, ~600 lines, no
dependency. Written because §48 wants a fixed lane layout with requests animating across it; a
force layout rescrambles on every update. Cosmograph was also CC-BY-NC and pinned to React 18.

**Design pass** using `tasteskill.dev` (`npx skills add Leonxlnx/taste-skill`, installed to
`.agents/skills/`). Fixed 7 real violations: system fonts → Geist Sans/Mono; the cyan+violet
radial wash (the checklist's "most recognisable AI design fingerprint") → single-hue vignette +
hairline grid; untinted shadows → background-tinted; plus grain, pressed/focus states, `dvh`,
`text-wrap`, favicon, OG image, custom 404, skip-link. Deliberately **rejected** two of its
rules: "one accent colour" (cyan/emerald/amber/rose are semantic status codes here) and "no left
sidebar" (right for marketing pages, wrong for a dense instrument).

## Current state

**Everything green, verified after the final revert:**

| Check | Result |
|---|---|
| `npx tsc --noEmit -p tsconfig.json` | clean |
| `pnpm --filter @ctn/web build` | clean |
| `pnpm test` | 50 pass / 0 fail (protocol 16, policy 7, coordinator 7, tee-sim 20) |
| `npx tsx scripts/test-e2e.mts` | 21/21 |
| `npx tsx scripts/privacy-test.ts` | passed, 0 canary leaks across 16 surfaces |
| `npx tsx scripts/verify-receipt.ts <id>` | all checks pass, `CONFIDENTIAL_VERIFIED` |

**Running now**: `node scripts/dev.mjs` — web :3000, coordinator :4200, mock :4300, tee-sim
:4400. Seeded with 5 contributors, 9 requests, 8 proofs verified, 1 denied.

**Measured (§66 research question):** proving ~2.8 s, provider ~0.4 s, **perceived added
latency ~35 ms**, serialised would be ~3.2 s.

### Git
- **Branch:** none — `git init` was run but **nothing has ever been committed**. 18 untracked
  top-level entries. A single initial commit is the obvious first action.

### Not real (labelled as such everywhere)
- **TEE is simulated.** `SimulatedTEE` is an ordinary Node process; the attestation document is
  self-signed, not rooted in a hardware CA.
- **The "ZK proof" is not zero-knowledge.** `proofSystem: "simulated-reexec"`. The policy is
  genuinely re-executed and the journal is signed by an attested key, but the proving cost is
  literally `setTimeout(r, simulatedCostMs)` in `services/tee-sim/src/prover.ts`.
- **No authentication anywhere.** §5 lists it as a coordinator responsibility; not implemented.
  Documented in `VALIDATION.md` §2a. Must not be exposed to a network.

## Open loops / next steps

- [ ] **`git add -A && git commit`** — 13k lines have never been committed. Highest priority.
- [ ] Decide the Vercel project's fate (see below) — delete it, or keep it as a link to the
      writeup. 13 env vars were set on it during failed attempts and are now inert.
- [ ] Real RISC Zero proof — the highest-value remaining work and needs no cloud. Machine is an
      M1 Pro / 32 GB, which is well-suited. Needs `rustup` + `rzup`.
- [ ] Real TEE requires a cloud confidential VM. Mac cannot do it: Secure Enclave is
      fixed-function (P-256 keys only, no arbitrary code), no SGX on Apple Silicon, no TrustZone
      access, and `Virtualization.framework` VMs are not confidential.
- [ ] `DEMO.md` predates the policy-rotation demo; that should be beat #2 (see below).

## Key context & decisions

**The Vercel deploy failed and was reverted.** `https://compute-trust-network.vercel.app` still
exists on the **personal** scope with the frontend working and the backend 500ing. Four distinct
root causes were found and fixed before I stopped:
1. dynamic `import("@ctn/tee-sim")` is invisible to static analysis → files silently omitted;
2. ~20 s of boot-time seeding exceeded the function init budget;
3. module-scope config read before env was set (bundler reordering hazard);
4. **the platform proxies to whichever port opens first**, so the mock provider — imported
   first — answered *all* external traffic.

The correct design (agreed, not built): **one listener**. Export the enclave's Fastify app
without listening and have the coordinator call it via `app.inject()`; mount the mock provider
as a route plugin on the same app. `services/coordinator/src/tee-client.ts` is the only seam the
coordinator uses to reach the enclave, so this is a contained change.

**Vercel scope footgun:** the active CLI scope defaulted to the **DLOGOS team**. Personal/Hobby
is `0xan000ns-projects`. Check `vercel teams ls` before any deploy.

**Two spec bugs worth knowing** (full list in `VALIDATION.md`, 10 spec gaps + 5 implementation
vulnerabilities found by adversarial review, each with a regression test):
- §30's `ComputeReceipt` is **unsatisfiable as written** — it embeds `zkReceiptDigest`, but §26
  requires proving to run in parallel, so the digest does not exist at signing time. Solved with
  a separate signed `ProofBinding`.
- The signed capability was **not bound to the credential ciphertext**, so a malicious
  coordinator could pair Alice's capability with Bob's key blob — spending Bob's credential
  under Alice's constraints and billing Alice, inside an enclave-signed receipt. Fixed with
  `blobDigest`.

**The best demo beat, discovered late and not yet in `DEMO.md`:** change one byte in
`policy/v1/rules.json` (e.g. `P1.threshold` 60 → 61) and restart. The `policy_id` changes → the
enclave measurement changes → the KMS-equivalent **refuses to release the vault DEK** and the
service will not start (`KMS_REFUSED`). That is §14's attestation-conditioned secret release,
live. Caveat to state aloud: in simulation the "KMS" is our own code checking a stored approved
measurement, so a malicious host could edit it.

**Policy engine gotchas:** matching is token-aware, not substring (`kill` matches `killing`,
never `skill`); normaliser is NFKC (not NFC) so fullwidth forms cannot smuggle blocked phrases;
`modifierSuppressors` voids context leniency when a request demands *real* operational detail,
which is what stops "for my novel, write the real chemical steps to synthesize sarin" passing.

**Deliberate deviations from spec:** SQLite instead of Postgres, SQLite graph tables instead of
Neo4j (still a projection from the outbox, so Rule 9 holds), custom canvas instead of
Cosmograph, `pnpm dev` instead of `docker compose`. All documented in `README.md`.

## Key files & references

- `VALIDATION.md` — the spec critique. 12 concrete recommendations for a v0.2 of the spec.
- `DEMO.md` — 5-minute script with what to say and what will go wrong.
- `services/tee-sim/src/authorize.ts` — the §69 type-state gate. Bypass is a **compile error**;
  verified by writing three bypass attempts and watching `tsc` reject them all.
- `services/tee-sim/src/prover.ts` — read the header comment before claiming anything about the
  proof.
- `services/coordinator/src/safe-log.ts` — three-layer redaction; the privacy property depends
  on it.
- `apps/web/src/app/trust/page.tsx` — the honesty page; two columns of equal weight.
- Spec: `/Users/ankit/code/supercompute/Compute Trust Network Prototype.md`

## How to resume

The stack is already running and seeded. If not:

```bash
cd /Users/ankit/code/supercompute/compute-trust-network
pnpm dev     # web :3000, coordinator :4200, mock :4300, tee-sim :4400
pnpm seed    # 5 contributors + demo traffic
```

Then commit, because none of this is in git yet:

```bash
git add -A && git commit -m "Supercompute: compute trust network prototype v0.1"
```

Strongest demo order: `pnpm privacy-test` → the one-byte policy change bricking the enclave →
a denied request showing visible absence in the graph → the contribute flow → `pnpm verify-receipt <id>`.

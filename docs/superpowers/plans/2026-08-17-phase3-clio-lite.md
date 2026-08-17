# Phase 3 — Clio-lite Insights: Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** A fully-local, proof-of-concept Clio-style insights layer: classify each prompt into a closed-enum facet inside the enclave, emit threshold-suppressed enclave-signed aggregate bulletins, and render them on a new `/insights` page — the prompt never leaves the confidential boundary.

**Architecture:** Classification runs in `tee-sim` on the plaintext already decrypted for the gate (no second decrypt, no network). Safety facets reuse the guest's ZK-proven policy categories (a DENY's facet is the category that denied it); benign facets come from a local keyword classifier over the `@ctn/policy` normalizer. Only a closed-enum `Facet` label and integer aggregates leave the enclave, threshold-suppressed and signed. The coordinator stores/serves the opaque bulletin; the web renders it with honesty labels.

**Tech Stack:** TypeScript (Node 22, `node:sqlite`), `@ctn/policy` (the NFKC normalizer + category scores), the enclave signing key (reused from receipts), Next.js (`apps/web`).

**Spec:** `docs/superpowers/specs/2026-08-17-phase3-clio-lite-design.md`.

## Global Constraints

- **Fully local. No LLM, no external call, no model download, no network** anywhere in classification. A reviewer must be able to confirm the prompt never leaves.
- Classification runs on the plaintext ALREADY in the enclave during the gate step — it must NOT add a second decrypt, a second `/execute`, or any request-path latency the caller feels.
- Only a closed-enum `Facet` label and integer aggregates ever leave the enclave. The prompt, any free text derived from it, and any per-request facet are NEVER persisted for insights, logged, evented, or served.
- Threshold suppression: a facet appears only at ≥ `K_MIN` (default 5); below, it folds into `other`, and `suppressedFacets`/`otherCount` record it (visible absence). Never called anonymity.
- Honesty invariant (equal weight, on the page): heuristic classifier (not an LLM), facet-grouping (not semantic embedding), threshold suppression (not anonymity), safety facets as good as the policy engine (obfuscation-resistant, not semantically complete).
- Integer counts; the bulletin is canonicalized (sorted facets, no floats) before signing — same discipline as receipts.
- No change to the request-path proof pipeline, latency, or the prompt-never-leaves guarantee.

Exact shapes (spec §5/§7), used verbatim below:

```typescript
type Facet =
  | "weapons" | "malware_cyber" | "phishing_fraud" | "violence" | "self_harm" | "csam"   // safety (policy categories)
  | "coding" | "writing" | "research" | "data_analysis" | "education" | "business"
  | "creative" | "translation" | "conversation" | "technical_ops"                        // benign
  | "other";
interface SignedInsightsBulletinV1 {
  version: 1; generatedAt: string; windowRequests: number; kMin: number;
  facets: Array<{ facet: Facet; allow: number; deny: number }>;   // only facets with allow+deny >= kMin
  suppressedFacets: number; otherCount: number; policyId: string; enclaveSignature: string;
}
```

---

### Task 1: Local facet classifier (in the enclave)

**Files:** Create `services/tee-sim/src/insights/facets.ts` (the closed enum + benign keyword classifier), `services/tee-sim/src/insights/classify.ts` (`classify`); Test `services/tee-sim/src/insights/classify.test.ts`. Reference: `@ctn/policy` (grep `packages/policy/src` for the exported `normalize` and the category/score types — the DENY category source); `services/tee-sim/src/index.ts` gate path (where the plaintext + gate decision + category scores are available — grep for `proverClient.execute` / `privateScores` / the gate result).

**Interfaces — Produces (Task 2 consumes):**

```typescript
export const FACETS: readonly Facet[];            // the closed enum, including "other"
export const SAFETY_FACETS: readonly Facet[];     // the 6 policy-category facets
/**
 * Runs on the plaintext already in the enclave. DENY → the deciding policy
 * category's facet; ALLOW → the benign keyword classifier; unclassifiable → "other".
 * Returns ONLY the enum label — never the prompt or any derived text.
 */
export function classify(input: {
  normalizedPrompt: string;                        // from @ctn/policy normalize
  decision: "ALLOW" | "DENY";
  categoryScores: Record<string, number>;          // per-category scores from the guest/policy (P1..P7)
  categoryThresholds: Record<string, number>;
}): Facet;
```

- [ ] **Step 1: Failing tests** (`classify.test.ts`): a DENY whose top over-threshold category is P4 → `weapons`; P2 → `malware_cyber`; P1/P6 → `phishing_fraud`; P3 → `violence`; P7 → `self_harm`; P5 → `csam`. An ALLOW "write a python function to sort a list" → `coding`; "write a short story about..." → `creative`/`writing`; "translate this to French" → `translation`; an ALLOW with no keyword hit → `conversation` or `other`. Determinism: same input → same facet, twice. The function returns ONLY a `Facet` (type-level; and assert no substring of the prompt is in the output).
- [ ] **Step 2:** Run the tee-sim test runner (grep `services/tee-sim/package.json`); verify fail.
- [ ] **Step 3: Implement** — `FACETS`/`SAFETY_FACETS`; the P1..P7→facet map; the benign classifier as a keyword/pattern map over the normalized text (reuse `@ctn/policy` `normalize`, do NOT re-implement it); DENY picks the highest over-threshold category, ALLOW runs the benign classifier, ties/none → `other`. Pure function, no I/O.
- [ ] **Step 4:** Run tests, verify pass.
- [ ] **Step 5:** `git add services/tee-sim/src/insights && git commit -m "insights: local closed-enum facet classifier (safety facets from policy categories, benign from keywords)"`

---

### Task 2: Bulletin accumulator + threshold suppression + signing + coordinator serving

**Files:** Create `services/tee-sim/src/insights/bulletin.ts` (accumulator + `buildBulletin`), `packages/protocol/src/insights.ts` (`SignedInsightsBulletinV1` + canonical form); Modify `services/tee-sim/src/index.ts` (call `classify` in the gate step; increment the accumulator; expose the signed bulletin — e.g. `GET /insights` on the enclave), `services/coordinator/src/index.ts` (fetch/store the signed bulletin opaquely; `GET /v1/insights`); Test `services/tee-sim/src/insights/bulletin.test.ts`, extend `scripts/privacy-test.ts`.

**Interfaces — Consumes:** `classify`, `FACETS` (Task 1). **Produces:** `SignedInsightsBulletinV1` (Global Constraints) served at `GET /v1/insights` (coordinator).

- [ ] **Step 1: Failing tests** (`bulletin.test.ts`): the accumulator records `{allow,deny}` per facet from a stream of `classify` results; `buildBulletin(kMin)` includes only facets with `allow+deny >= kMin`, folds the rest into `other` with correct `suppressedFacets`/`otherCount`; a facet at exactly `kMin` appears; counts are integers; the canonical form (sorted facets, no floats) is stable; the enclave signature verifies against the enclave key; the bulletin contains NO prompt text (assert a planted marker classified in never appears in the bulletin JSON).
- [ ] **Step 2:** Run, verify fail.
- [ ] **Step 3: Implement** — the in-memory accumulator; `classify` called in the gate step in `index.ts` using the plaintext + gate decision + category scores already there (confirm `privateScores` / category scores are available at that point — if the gate does not currently request scores, request them, but do NOT add a second `/execute`); `buildBulletin` with threshold suppression; canonicalize + sign with the enclave key (reuse the receipt-signing helper); enclave `GET /insights`; coordinator fetches/stores opaquely and serves `GET /v1/insights`. The prompt is discarded after classification exactly as it is today — nothing new persists it.
- [ ] **Step 4:** Run tests. **Extend `scripts/privacy-test.ts`**: a planted canary in a prompt must NOT appear in the bulletin, the `/insights` responses (enclave + coordinator), or any log. Run `pnpm privacy-test` (needs the stack) — the insights surface is swept clean.
- [ ] **Step 5:** `git add services packages/protocol scripts/privacy-test.ts && git commit -m "insights: threshold-suppressed enclave-signed bulletins; coordinator /v1/insights; privacy canary extended"`

---

### Task 3: The `/insights` page

**Files:** Create `apps/web/src/app/insights/page.tsx` + any insights components (match the app's component conventions — grep `apps/web/src/components`); Modify the nav if the app has one (grep for the trust/policy nav links). Test: a source-guard case in `scripts/test-e2e.mts` (same style as 2b.8/2b.9/2b.10) + one live fetch of `/v1/insights`.

- [ ] **Step 1: Failing test** (`scripts/test-e2e.mts`, e.g. `3.1`): `GET /v1/insights` returns a `SignedInsightsBulletinV1` with the expected shape; the `/insights` page source renders the facet scatter, the allow/deny breakdown, the deny-category safety view, and the honesty panel strings ("classified locally", "prompts never leave", "heuristic classifier, not an LLM", "grouping, not semantic embedding", "threshold suppression", "not anonymity"); and it renders the suppressed state.
- [ ] **Step 2:** Run, verify fail.
- [ ] **Step 3: Implement** — the page: a facet **cluster scatter** (each facet a labelled region; dots placed deterministically within it, colored by facet — safety warm/red, benign cool — sized by count), a **breakdown** (allow vs deny per facet), a **safety view** (deny categories in aggregate), and the always-visible **honesty panel** (§8/§9 copy). Reuse the app's existing tokens/components (as the ProofBeat did — grep `apps/web/src/components/ui`). Honest labels are load-bearing, not decoration: nothing may read as semantic embedding, LLM classification, or anonymity.
- [ ] **Step 4:** Run the e2e case; `pnpm --filter web build` clean; `npx tsc --noEmit`; `pnpm test:e2e` green.
- [ ] **Step 5:** `git add apps/web scripts/test-e2e.mts && git commit -m "web: /insights — local facet clusters, allow/deny breakdown, safety view, honesty panel"`

---

## Self-Review

**Spec coverage:** §4 classifier → Task 1; §6 threshold suppression + §7 bulletin + §4 coordinator serving → Task 2; §8 page + §9 honesty labels → Task 3; §11 testing → distributed (classifier determinism, privacy canary, suppression, signature, safety tie-in, web render). §10 non-goals are out of scope. Covered.

**Placeholder scan:** the one "confirm scores are available at the gate step" is a real instruction with a fallback (request scores, but no second `/execute`), not a placeholder. File paths that may have moved are given as path + grep-target.

**Type consistency:** `Facet`/`FACETS`/`SAFETY_FACETS` defined once (Task 1) consumed in Task 2; `classify` signature consumed in Task 2; `SignedInsightsBulletinV1` defined once (Global Constraints) produced in Task 2, consumed in Task 3; `K_MIN`/`kMin` consistent.

## Execution Handoff

Subagent-driven (Opus), same discipline as 2a/2b: fresh implementer per task, independent reviewer, fix loops; ledger at `.superpowers/sdd/2026-08-17-phase3-clio-lite/progress.md`.

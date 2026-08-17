# Phase 3 — Clio-lite Insights (fully-local, proof of concept)

**Date:** 2026-08-17
**Status:** Design approved in chat; pending spec review, then implementation plan
**Predecessor:** Phase 2b (the prover wired into the live request path; merged to `main`)
**Parent spec:** `docs/superpowers/specs/2026-08-11-supercompute-real-design.md` §5.3
**Reprioritized ahead of Phase 2c** (queue backpressure) at the user's request — 2c is hardening the demo works around via the DEMO.md runbook; this is a new visible capability.

## 1. Goal

Give contributors and viewers a **Clio-style view of what the network's compute is used for** — clustered by topic, including the safety categories the policy *refused* — **without any prompt ever leaving the confidential boundary**. It answers "what is my contributed compute doing, and what is it protecting against?" in aggregate.

**This is a proof of concept.** The classifier is a local heuristic, not an LLM; the layout is honest facet-grouping, not semantic embedding; the aggregates are threshold-suppressed. Everything is labelled as such — the honesty invariant (parent §1) governs this phase exactly as it governs the proof.

## 2. The thesis constraint (why this design)

The whole system's promise is **the prompt never leaves the confidential boundary** (`tee-sim` + `prover/host`). Real Clio feeds conversations to an LLM to extract themes — the opposite direction. So Clio-lite is **fully local**: classification runs *inside the enclave* on the plaintext, and only a **closed-enum facet label** and threshold-suppressed **aggregate counts** ever leave. No prompt, no free text, no external model, no network. Nothing on the trust page needs to change — the guarantee holds.

## 3. Settled decisions

| Question | Decision |
|---|---|
| Classification | **Fully local, in the enclave.** No LLM, no external call, no model download. |
| Breadth | **Broad closed-enum taxonomy** — benign topics + the safety/deny categories (weapons, malware, …). |
| Safety facets | **Reuse the policy engine's categories** (P1–P7) — a denied prompt's facet is the category that denied it, which is already inside the ZK proof. Benign facets come from a second local keyword classifier. |
| Cluster visual | **Honest facet-grouping** — dots placed in their facet's region, deterministically. Labelled "grouped by locally-classified facet," NOT semantic embedding. (Real local embeddings = a post-PoC upgrade.) |
| Privacy | **Threshold suppression** — a facet renders only at ≥ `k_min` requests; below that it folds into "other." Never called anonymity. |
| Output | **Enclave-signed aggregate bulletins** — per-facet allow/deny counts, no prompt content. |
| Surface | A new **`/insights`** page. |
| Scope | **PoC**: heuristic classifier, aggregate-only, one page. No trends, no sub-clusters, no per-request insight. |

## 4. Architecture

- **`services/tee-sim/src/insights/`** (new) — the classifier + bulletin generator, inside the enclave:
  - `facets.ts` — the closed-enum taxonomy (below) and the benign keyword/pattern classifier, built on the existing `policy-core` NFKC normalizer (reused, not re-implemented).
  - `classify.ts` — `classify(normalizedPrompt, gateResult) → Facet`. If the gate DENIED, the facet is the deciding policy category (weapons/malware/…). If ALLOWED, the facet is the benign classifier's result. Runs on the plaintext already in the enclave during the request; **emits only the `Facet` enum** — the prompt is never stored for insights.
  - `bulletin.ts` — accumulates per-facet `{allow, deny}` counts in enclave memory; on demand (or every N requests / T seconds) produces a `SignedInsightsBulletinV1`: threshold-suppressed, signed by the enclave key.
- **`services/coordinator`** — stores the latest signed bulletin (opaque; it never sees prompts) and serves `GET /v1/insights`.
- **`apps/web/src/app/insights/`** (new) — renders the bulletin: the facet cluster scatter, a breakdown, and the deny-category safety view, with the honesty labels.

**Data flow:** request → enclave gates + (during the same in-enclave step) classifies the plaintext into a `Facet` → increments an in-enclave counter → the prompt is discarded as always. Periodically the enclave signs a bulletin of threshold-suppressed aggregates → coordinator → `/insights`. **No prompt, no per-request facet, ever leaves** — only signed aggregates.

## 5. The facet taxonomy (closed enum)

**Safety facets** (from the policy categories; a DENY maps to the deciding category):
`weapons` (P4), `malware_cyber` (P2), `phishing_fraud` (P1/P6), `violence` (P3), `self_harm` (P7), `csam` (P5).

**Benign facets** (local keyword classifier over allowed prompts):
`coding`, `writing`, `research`, `data_analysis`, `education`, `business`, `creative`, `translation`, `conversation`, `technical_ops`.

Plus `other` (unclassified / suppressed). The enum is closed and versioned; adding a facet is a deliberate, labelled change.

## 6. Threshold suppression

A facet appears in a bulletin only if its total count ≥ `k_min` (default **5**). Below that, its counts fold into `other`, and the bulletin records `suppressedFacets` and `suppressedCount` so the suppression is *visible* (an honest absence, not a silent drop). This is stated on the page as "threshold suppression — clusters below N requests are not shown; this is not anonymity."

## 7. Bulletin schema

```typescript
interface SignedInsightsBulletinV1 {
  version: 1;
  generatedAt: string;          // enclave clock
  windowRequests: number;       // how many requests this bulletin summarizes
  kMin: number;                 // the suppression threshold in force
  facets: Array<{ facet: Facet; allow: number; deny: number }>;  // only facets >= kMin
  suppressedFacets: number;     // count of facets folded into `other`
  otherCount: number;
  policyId: string;             // the guest POLICY_ID_V2 the safety facets came from
  enclaveSignature: string;     // over the canonical bulletin (integer counts, sorted)
}
```

Counts are integers; the bulletin is canonicalized (sorted facets, no floats) before signing, matching the receipt discipline. The signature is the enclave's existing signing key.

## 8. Frontend `/insights`

- **Cluster scatter** — each facet is a labelled region; dots (one per request, up to a cap, or scaled) sit in their region, sized/colored by facet. Safety facets in warm/red, benign in cool tones. Reads as clusters; labelled honestly.
- **Facet breakdown** — a bar/treemap of allow vs deny per facet.
- **Safety view** — the deny categories in aggregate: "what the network refused, by category" — the "helps with safety" story, made visible.
- **Honesty panel** (equal weight, always visible): "Classified locally inside the enclave — prompts never leave, only these aggregate counts do. Heuristic keyword classifier, not an LLM; facets are approximate. Positioned by facet for legibility — this is grouping, not semantic embedding. Clusters below N requests are suppressed (threshold suppression, not anonymity)."

## 9. Honesty invariant (what must be labelled, at equal weight)

- The classifier is a **heuristic**, not an LLM or a real embedding model — facets are approximate and can be wrong.
- The layout is **facet-grouping**, not semantic clustering — dots near each other share a facet, nothing more.
- Suppression is **threshold suppression**, not anonymity — a determined operator with side information could still infer; §5.3's parent note stands.
- The safety facets are **as good as the policy engine** — same categories, same limits (obfuscation-resistant, not semantically complete).
- **Nothing here weakens the prompt-never-leaves guarantee** — and the design note (§2) says why, so a reviewer can confirm it.

## 10. Non-goals (PoC)

No LLM / Claude / external call of any kind. No real embedding model (facet-grouping only for the PoC). No per-request insight or drill-down to a prompt. No time-series/trends. No cross-contributor correlation. No claim of anonymity. No change to the request path's latency or the proof pipeline (classification piggybacks on the in-enclave plaintext step that already exists; it must not add a second decrypt or a network hop).

## 11. Testing

- **Classifier**: deterministic; a benign prompt → a benign facet; a denied "weapons" prompt → `weapons`; determinism replay.
- **Privacy canary**: a planted secret in a prompt appears in NO bulletin, log, or `/insights` response (extend the existing privacy sweep to the insights surface).
- **Threshold suppression**: a facet with < `k_min` requests is folded into `other`; `suppressedFacets`/`otherCount` reflect it; a facet at exactly `k_min` appears.
- **Bulletin signature** verifies; counts are integers; canonical form is stable.
- **Safety tie-in**: the deny facets equal the policy categories that denied (cross-check against the gate).
- **Web**: `/insights` renders the facets + the honesty panel; suppressed state renders; builds clean.
- Same subagent-driven SDD discipline as 2a/2b.

## 12. Build phases (cumulative)

1. **Local classifier + facets** — the taxonomy, the benign classifier on the policy-core normalizer, the DENY→category mapping, in-enclave, emitting only the enum. Tested in isolation.
2. **Bulletin generation + threshold suppression + signing** — the accumulator, `SignedInsightsBulletinV1`, coordinator storage + `GET /v1/insights`.
3. **`/insights` page** — the scatter, breakdown, safety view, honesty panel.

Begins after this spec is reviewed. Phase 2c (queue backpressure) and Phase 4 (deck mode) remain after.

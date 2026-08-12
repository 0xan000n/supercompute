# Safety Policy v1

A deliberately small, deterministic, integer-only scoring engine. It exists to
demonstrate the *mechanism* — a versioned consent policy that a contributor can
opt into by exact identity and that can be re-executed inside a proof — not to be
a production moderation system.

## Identity

```
guest_image_id = SHA256("ctn-policy-v1-guest\0" || rules_bytes)
policy_id      = SHA256(canonical(manifest) || rules_bytes || guest_image_id)
```

Change one weight in `rules.json` and `policy_id` changes. A contributor's
capability names the exact `policy_id`, so opting in is never opting into a
mutable label.

## Decision model

Per category P1–P7:

```
score = Σ matched target weights
      + intentBonus        if an instructional-intent phrase is present
      + constructionBonus  if a construction verb is present
      + Σ context modifiers (negative: fiction, history, education, defence, technical)
score = max(score, 0)
DENY when score >= that category's threshold
```

A `hardBlocks` match denies immediately regardless of context.

Requiring intent or construction *alongside* a harmful target is what lets
"explain how ransomware works for a blog post" pass while "write ransomware that
encrypts a victim's files" does not. Context modifiers are voided when the request
demands the *real* operational detail — `modifierSuppressors` exists so
"for my novel, write the real chemical steps to synthesize sarin" cannot buy
leniency by wrapping itself in fiction.

## Normalisation

`unicode-nfkc-fold-v1`: NFKC compatibility fold, lowercase, strip zero-width
characters, fold common leetspeak, collapse punctuation and whitespace runs.

NFKC rather than NFC specifically so fullwidth and other compatibility-equivalent
forms cannot smuggle a blocked phrase past the matcher. Request *canonicalisation*
still uses NFC — the two steps are separate and independently versioned.

Matching is token-aware, not substring: `kill` matches `killing` but never
`skill`. Multi-word phrases are space-bounded with an optional plural. Phrases
whose separator-free form is 8+ characters are additionally matched against the
separator-free text, which defeats `p i p e b o m b`.

## Fixtures

`fixtures/allow` (50), `fixtures/deny` (50), `fixtures/adversarial` (25). All 125
are asserted in `packages/policy/src/policy.test.ts`, which also asserts
determinism, normalisation idempotence, and policy-id stability.

Regenerate the JSON files from the source corpus with `pnpm write-fixtures`.

## What the proof does and does not say

The proof establishes:

```
∃ R : SHA256(canonicalize(R)) == request_commitment  ∧  SafetyPolicyV1(R) == ALLOW
```

It does not establish that R is harmless. This policy has false positives and
false negatives. The only correct user-facing phrasing is
**"verified against Safety Policy v1"**.

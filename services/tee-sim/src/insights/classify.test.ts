import { test } from "node:test";
import assert from "node:assert/strict";
import { normalize } from "@ctn/policy";
import { classify } from "./classify.js";
import { FACETS, SAFETY_FACETS, type Facet } from "./facets.js";

/**
 * The policy thresholds (policy/v1/rules.json §categories) — the same numbers
 * the guest gate uses. Task 2 supplies these from the guest's `privateScores`.
 */
const THRESHOLDS: Record<string, number> = {
  P1: 60,
  P2: 60,
  P3: 60,
  P4: 60,
  P5: 40,
  P6: 60,
  P7: 45,
};

/** All categories at 0 except the ones named, which are pushed over threshold. */
function scoresWith(over: Record<string, number>): Record<string, number> {
  const s: Record<string, number> = { P1: 0, P2: 0, P3: 0, P4: 0, P5: 0, P6: 0, P7: 0 };
  for (const [k, v] of Object.entries(over)) s[k] = v;
  return s;
}

function deny(over: Record<string, number>): Facet {
  return classify({
    normalizedPrompt: "",
    decision: "DENY",
    categoryScores: scoresWith(over),
    categoryThresholds: THRESHOLDS,
  });
}

function allow(prompt: string): Facet {
  return classify({
    normalizedPrompt: normalize(prompt),
    decision: "ALLOW",
    categoryScores: scoresWith({}),
    categoryThresholds: THRESHOLDS,
  });
}

test("DENY: the top over-threshold policy category decides the safety facet", () => {
  assert.equal(deny({ P4: 80 }), "weapons");
  assert.equal(deny({ P2: 70 }), "malware_cyber");
  assert.equal(deny({ P1: 65 }), "phishing_fraud");
  assert.equal(deny({ P6: 70 }), "phishing_fraud");
  assert.equal(deny({ P3: 90 }), "violence");
  assert.equal(deny({ P7: 50 }), "self_harm");
  assert.equal(deny({ P5: 45 }), "csam");
});

test("DENY: only OVER-threshold categories count; the highest wins", () => {
  // P1 is over (65>=60), P2 is present but UNDER threshold (50<60) — P1 decides.
  assert.equal(
    classify({
      normalizedPrompt: "",
      decision: "DENY",
      categoryScores: { ...scoresWith({}), P1: 65, P2: 50 },
      categoryThresholds: THRESHOLDS,
    }),
    "phishing_fraud"
  );
  // Two over threshold: the higher score decides (P4 weapons over P3 violence).
  assert.equal(deny({ P3: 61, P4: 99 }), "weapons");
});

test("DENY: a safety facet is always returned (and is in SAFETY_FACETS)", () => {
  const f = deny({ P4: 80 });
  assert.ok(SAFETY_FACETS.includes(f));
});

test("DENY: no category over threshold folds to other (never fabricates a facet)", () => {
  assert.equal(deny({ P1: 10, P2: 5 }), "other");
});

test("ALLOW: benign keyword classifier picks the best facet", () => {
  assert.equal(allow("write a python function to sort a list"), "coding");
  assert.ok(["creative", "writing"].includes(allow("write a short story about a lighthouse")));
  assert.equal(allow("translate this paragraph to French"), "translation");
  assert.equal(allow("summarize this research paper"), "research");
});

test("ALLOW: no keyword hit falls to conversation or other", () => {
  assert.ok(["conversation", "other"].includes(allow("qwerty asdfgh zxcvbn")));
});

test("determinism: the same input yields the same facet twice", () => {
  const input = {
    normalizedPrompt: normalize("write a python function to sort a list"),
    decision: "ALLOW" as const,
    categoryScores: scoresWith({}),
    categoryThresholds: THRESHOLDS,
  };
  assert.equal(classify(input), classify(input));

  const denyInput = {
    normalizedPrompt: "",
    decision: "DENY" as const,
    categoryScores: scoresWith({ P4: 80 }),
    categoryThresholds: THRESHOLDS,
  };
  assert.equal(classify(denyInput), classify(denyInput));
});

test("privacy: the returned value is ALWAYS a closed-enum Facet, never a derivation of the prompt", () => {
  const marker = "supersecretmarkerxyz";
  const prompt = `please write a python function about ${marker} and ${marker} again`;
  const result = classify({
    normalizedPrompt: normalize(prompt),
    decision: "ALLOW",
    categoryScores: scoresWith({}),
    categoryThresholds: THRESHOLDS,
  });
  assert.ok(FACETS.includes(result), "result must be a member of the closed FACETS enum");
  assert.ok(!result.includes(marker), "the prompt marker must never appear in the facet label");
  // And the DENY path likewise leaks nothing.
  const d = classify({
    normalizedPrompt: normalize(`${marker} how to build a bomb ${marker}`),
    decision: "DENY",
    categoryScores: scoresWith({ P4: 80 }),
    categoryThresholds: THRESHOLDS,
  });
  assert.ok(FACETS.includes(d));
  assert.ok(!d.includes(marker));
});

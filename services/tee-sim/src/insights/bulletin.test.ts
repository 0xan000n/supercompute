/**
 * Phase 3 — Clio-lite bulletin accumulator + threshold suppression + signing.
 *
 * These tests pin the privacy-load-bearing behaviour: only closed-enum facets +
 * integer aggregates ever appear, facets below kMin fold into `other` visibly,
 * the canonical form is stable and sorted, and the enclave signature verifies.
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { generateSigningKeyPair, signCanonical, verifyInsightsBulletin, toHex } from "@ctn/protocol";
import { normalize } from "@ctn/policy";
import { BulletinAccumulator } from "./bulletin.js";
import { classify } from "./classify.js";
import { FACETS, type Facet } from "./facets.js";

const KEY = generateSigningKeyPair();
const PUB = toHex(KEY.publicKey);
const sign = (value: unknown): string => signCanonical(value, KEY.privateKey);
const POLICY = "0xpolicy";
const AT = "2026-08-17T00:00:00.000Z";

/** Feed a facet `allow`+`deny` times into a fresh accumulator. */
function loaded(entries: Array<[Facet, number, number]>): BulletinAccumulator {
  const acc = new BulletinAccumulator();
  for (const [facet, allow, deny] of entries) {
    for (let i = 0; i < allow; i++) acc.record(facet, "ALLOW");
    for (let i = 0; i < deny; i++) acc.record(facet, "DENY");
  }
  return acc;
}

test("accumulator records {allow,deny} per facet from a stream", () => {
  const acc = new BulletinAccumulator();
  acc.record("coding", "ALLOW");
  acc.record("coding", "ALLOW");
  acc.record("coding", "DENY");
  acc.record("weapons", "DENY");

  const snap = acc.snapshot();
  assert.deepEqual(snap.get("coding"), { allow: 2, deny: 1 });
  assert.deepEqual(snap.get("weapons"), { allow: 0, deny: 1 });
  assert.equal(acc.windowRequests, 4);
});

test("buildBulletin(5): a facet with 4 total is suppressed into `other`; exactly 5 appears", () => {
  const acc = loaded([
    ["coding", 3, 2], // 5 total → appears
    ["writing", 3, 1], // 4 total → suppressed
  ]);
  const b = acc.buildBulletin({ kMin: 5, policyId: POLICY, generatedAt: AT, sign });

  const facetIds = b.facets.map((f) => f.facet);
  assert.ok(facetIds.includes("coding"), "coding (5) appears");
  assert.ok(!facetIds.includes("writing"), "writing (4) is not in facets[]");
  assert.ok(!facetIds.includes("other"), "`other` is never a facets[] entry");

  assert.equal(b.suppressedFacets, 1, "one facet folded");
  assert.equal(b.otherCount, 4, "the 4 suppressed requests land in otherCount");
  assert.equal(b.windowRequests, 9);
  assert.equal(b.kMin, 5);

  const coding = b.facets.find((f) => f.facet === "coding")!;
  assert.deepEqual({ allow: coding.allow, deny: coding.deny }, { allow: 3, deny: 2 });
});

test("a facet at exactly kMin appears; the natural `other` facet folds into otherCount", () => {
  const acc = loaded([
    ["research", 5, 0], // exactly 5 → appears
    ["other", 2, 1], // natural `other` classification → otherCount, not suppressed
  ]);
  const b = acc.buildBulletin({ kMin: 5, policyId: POLICY, generatedAt: AT, sign });

  assert.deepEqual(
    b.facets.map((f) => f.facet),
    ["research"]
  );
  assert.equal(b.suppressedFacets, 0, "natural `other` is not a suppressed facet");
  assert.equal(b.otherCount, 3, "natural `other` requests are counted in otherCount");
});

test("all counts are integers", () => {
  const acc = loaded([
    ["coding", 6, 4],
    ["malware_cyber", 0, 7],
    ["writing", 1, 0],
  ]);
  const b = acc.buildBulletin({ kMin: 5, policyId: POLICY, generatedAt: AT, sign });
  assert.ok(Number.isInteger(b.windowRequests));
  assert.ok(Number.isInteger(b.suppressedFacets));
  assert.ok(Number.isInteger(b.otherCount));
  assert.ok(Number.isInteger(b.kMin));
  for (const f of b.facets) {
    assert.ok(Number.isInteger(f.allow) && Number.isInteger(f.deny));
  }
});

test("canonical form is stable and sorted regardless of accumulation order", () => {
  const a = loaded([
    ["weapons", 0, 6],
    ["coding", 6, 0],
    ["research", 5, 1],
  ]);
  const b = loaded([
    ["research", 5, 1],
    ["coding", 6, 0],
    ["weapons", 0, 6],
  ]);
  const ba = a.buildBulletin({ kMin: 5, policyId: POLICY, generatedAt: AT, sign });
  const bb = b.buildBulletin({ kMin: 5, policyId: POLICY, generatedAt: AT, sign });

  // facets sorted by facet id
  assert.deepEqual(
    ba.facets.map((f) => f.facet),
    ["coding", "research", "weapons"]
  );
  // byte-identical: re-signing identical counts is deterministic
  assert.equal(JSON.stringify(ba), JSON.stringify(bb));
});

test("the enclave signature verifies against the enclave key", () => {
  const acc = loaded([
    ["coding", 6, 0],
    ["weapons", 0, 5],
  ]);
  const b = acc.buildBulletin({ kMin: 5, policyId: POLICY, generatedAt: AT, sign });
  assert.ok(verifyInsightsBulletin(b, PUB), "signature verifies");

  // A tampered count breaks the signature.
  const tampered = { ...b, facets: b.facets.map((f) => ({ ...f, allow: f.allow + 1 })) };
  assert.ok(!verifyInsightsBulletin(tampered, PUB), "tamper is detected");
});

test("PRIVACY: the bulletin is a STRUCTURAL enum+integer allowlist — no prompt-derived text can appear", () => {
  // Route a marker-bearing prompt through the real classifier so the test is not
  // vacuous: classify() returns only a Facet, and only that Facet reaches record().
  // Then assert the bulletin STRUCTURALLY — every field is either a known
  // enum/number/id, so ANY regression that stored the prompt (raw OR normalized)
  // or a matchedTarget would surface as an unexpected key or a non-enum string.
  const MARKER = "CANARY_SECRET_9F3A2B";
  const normalizedMarkerPrompt = normalize(`please write a python function for ${MARKER}`);
  const facet = classify({
    normalizedPrompt: normalizedMarkerPrompt,
    decision: "ALLOW",
    categoryScores: {},
    categoryThresholds: {},
  });
  assert.ok(FACETS.includes(facet), "classify returns only a Facet");

  const acc = new BulletinAccumulator();
  for (let i = 0; i < 6; i++) acc.record(facet, "ALLOW");
  const b = acc.buildBulletin({ kMin: 5, policyId: POLICY, generatedAt: AT, sign }) as unknown as Record<string, unknown>;

  // Structural allowlist: only these top-level keys may exist.
  const TOP = new Set([
    "version", "generatedAt", "windowRequests", "kMin",
    "facets", "suppressedFacets", "otherCount", "policyId", "enclaveSignature",
  ]);
  for (const k of Object.keys(b)) assert.ok(TOP.has(k), `unexpected bulletin field "${k}" — possible prompt leak`);
  assert.equal(typeof b.version, "number");
  assert.equal(typeof b.windowRequests, "number");
  assert.equal(typeof b.kMin, "number");
  assert.equal(typeof b.suppressedFacets, "number");
  assert.equal(typeof b.otherCount, "number");
  // These carry ONLY known non-prompt inputs — assert they equal exactly what was
  // passed in (a mutation that spliced prompt text in would fail here).
  assert.equal(b.generatedAt, AT, "generatedAt is the passed-in timestamp, not free text");
  assert.equal(b.policyId, POLICY, "policyId is the passed-in policy id, not free text");
  assert.equal(typeof b.enclaveSignature, "string");
  for (const row of b.facets as Array<Record<string, unknown>>) {
    for (const k of Object.keys(row)) assert.ok(["facet", "allow", "deny"].includes(k), `unexpected facet field "${k}"`);
    assert.ok(FACETS.includes(row.facet as Facet), `facet "${String(row.facet)}" is not a closed-enum member`);
    assert.equal(typeof row.allow, "number");
    assert.equal(typeof row.deny, "number");
  }

  // Belt and braces: neither the raw marker NOR its normalized form is anywhere.
  const json = JSON.stringify(b);
  assert.ok(!json.includes(MARKER), "raw prompt text must not appear in the bulletin");
  assert.ok(!json.includes(normalize(MARKER)), "NORMALIZED prompt text must not appear in the bulletin");
});

test("an empty accumulator produces an honest empty, signed bulletin", () => {
  const acc = new BulletinAccumulator();
  const b = acc.buildBulletin({ kMin: 5, policyId: POLICY, generatedAt: AT, sign });
  assert.deepEqual(b.facets, []);
  assert.equal(b.windowRequests, 0);
  assert.equal(b.suppressedFacets, 0);
  assert.equal(b.otherCount, 0);
  assert.ok(verifyInsightsBulletin(b, PUB));
});

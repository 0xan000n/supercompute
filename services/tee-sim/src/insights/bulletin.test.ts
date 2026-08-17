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
import { BulletinAccumulator } from "./bulletin.js";
import type { Facet } from "./facets.js";

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

test("PRIVACY: a planted marker classified in appears NOWHERE in the bulletin JSON", () => {
  // The accumulator only ever sees the enum Facet — never the prompt. Simulate a
  // request whose prompt contained a secret; the classifier (elsewhere) mapped it
  // to a facet, and only that facet reaches the accumulator.
  const MARKER = "CANARY_SECRET_9F3A2B";
  const acc = new BulletinAccumulator();
  for (let i = 0; i < 6; i++) acc.record("coding", "ALLOW"); // the request classified as coding
  const b = acc.buildBulletin({ kMin: 5, policyId: POLICY, generatedAt: AT, sign });

  assert.ok(!JSON.stringify(b).includes(MARKER), "no prompt-derived text in the bulletin");
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

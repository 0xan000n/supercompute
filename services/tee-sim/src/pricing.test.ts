import { test } from "node:test";
import assert from "node:assert/strict";
import { MODEL_CATALOG } from "./catalog.js";
import {
  PRICING_TABLE, PRICING_TABLE_DIGEST,
  estimateCostMicroUsd, estimateWorstCaseMicroUsd, UnpricedModelError,
} from "./pricing.js";

test("every catalog model is priced — no silent default for real money", () => {
  for (const models of Object.values(MODEL_CATALOG))
    for (const m of models) assert.ok(PRICING_TABLE[m], `missing price for ${m}`);
  assert.match(PRICING_TABLE_DIGEST, /^0x[0-9a-f]{64}$/);
});

test("estimates are integer micro-USD", () => {
  const v = estimateCostMicroUsd("claude-haiku-4-5-20251001", 1234, 567);
  assert.equal(v, Math.trunc(v));
  // 1234 in at $1/MTok + 567 out at $5/MTok = 1234 + 2835 = 4069 µUSD
  assert.equal(v, 4069);
});

test("unknown model refuses rather than guessing", () => {
  assert.throws(() => estimateCostMicroUsd("gpt-99", 1, 1), UnpricedModelError);
});

test("worst case is a UTF-8 byte UPPER bound — multibyte text cannot underestimate", () => {
  const ascii = estimateWorstCaseMicroUsd("claude-haiku-4-5-20251001", [{ content: "a".repeat(1000) }], 100);
  const cjk = estimateWorstCaseMicroUsd("claude-haiku-4-5-20251001", [{ content: "語".repeat(1000) }], 100);
  assert.ok(cjk > ascii, "CJK must bound higher than same-length ASCII");
  // 1000 CJK chars = 3000 UTF-8 bytes ≥ any BPE token count for that string.
  const bytes = Buffer.byteLength("語".repeat(1000), "utf8");
  const boundTok = bytes + 16 * 1 + 16;
  assert.equal(cjk, Math.ceil((boundTok * 1_000_000 + 100 * 5_000_000) / 1_000_000));
});

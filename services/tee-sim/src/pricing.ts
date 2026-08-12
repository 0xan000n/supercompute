/**
 * §5.1 — the pinned price table. Costs in receipts are ESTIMATES derived from
 * provider-reported token counts and THIS table; the table's digest travels in
 * the receipt so a verifier knows which prices produced the number. Integer
 * micro-USD per million tokens — no floats anywhere near signed bytes.
 */
import { canonicalHash } from "@ctn/protocol";

export class UnpricedModelError extends Error {
  constructor(model: string) {
    super(`UNPRICED_MODEL: ${model} has no entry in the pinned pricing table`);
  }
}

export interface ModelPrice {
  inMicroUsdPerMTok: number;
  outMicroUsdPerMTok: number;
}

export const PRICING_TABLE: Record<string, ModelPrice> = {
  // Anthropic (2026-08 list prices)
  "claude-haiku-4-5-20251001": { inMicroUsdPerMTok: 1_000_000, outMicroUsdPerMTok: 5_000_000 },
  "claude-sonnet-4-5-20250929": { inMicroUsdPerMTok: 3_000_000, outMicroUsdPerMTok: 15_000_000 },
  // OpenAI
  "gpt-4o-mini-2024-07-18": { inMicroUsdPerMTok: 150_000, outMicroUsdPerMTok: 600_000 },
  "gpt-4o-2024-08-06": { inMicroUsdPerMTok: 2_500_000, outMicroUsdPerMTok: 10_000_000 },
  // Local mock (demo values so seeded dashboards stay meaningful)
  "ctn/demo-model-a": { inMicroUsdPerMTok: 150_000, outMicroUsdPerMTok: 600_000 },
  "ctn/demo-model-b": { inMicroUsdPerMTok: 2_500_000, outMicroUsdPerMTok: 10_000_000 },
  "ctn/demo-model-fast": { inMicroUsdPerMTok: 50_000, outMicroUsdPerMTok: 200_000 },
};

export const PRICING_TABLE_DIGEST = "0x" + canonicalHash(PRICING_TABLE);

function price(model: string): ModelPrice {
  const p = PRICING_TABLE[model];
  if (!p) throw new UnpricedModelError(model);
  return p;
}

/** True when the pinned table can price this model. Capability predicate — an
 *  adapter must not offer a model whose spend it cannot account for. */
export function isPriced(model: string): boolean {
  return PRICING_TABLE[model] !== undefined;
}

/**
 * Refuse an unpriced model. Call this BEFORE dispatching anything upstream: a
 * price lookup that happens after the call has already burned real tokens, and
 * the only honest thing left to do at that point is charge someone for a number
 * we cannot compute.
 */
export function assertPriced(model: string): void {
  price(model);
}

export function estimateCostMicroUsd(model: string, inTok: number, outTok: number): number {
  const p = price(model);
  return Math.ceil((inTok * p.inMicroUsdPerMTok + outTok * p.outMicroUsdPerMTok) / 1_000_000);
}

/**
 * Pre-call UPPER bound on spend, used when the upstream outcome is unknown.
 * Token-count bound: BPE tokenizers over UTF-8 emit at least one byte per
 * token, so tokens(text) <= utf8Bytes(text). Add 16 tokens per message for
 * role/format framing and 16 for the wrapper — generous, and cheapness is
 * not the goal here; NOT undercounting is.
 */
export function estimateWorstCaseMicroUsd(
  model: string,
  messages: Array<{ content: string }>,
  maxTokens: number
): number {
  const p = price(model);
  const byteBound = messages.reduce((n, m) => n + Buffer.byteLength(m.content, "utf8"), 0);
  const promptTokBound = byteBound + 16 * messages.length + 16;
  return Math.ceil((promptTokBound * p.inMicroUsdPerMTok + maxTokens * p.outMicroUsdPerMTok) / 1_000_000);
}

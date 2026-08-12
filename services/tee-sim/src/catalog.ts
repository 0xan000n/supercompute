/**
 * §5.1 — the pinned model catalog. Capabilities name DATED SNAPSHOT IDs, not
 * movable aliases: consent to "claude-haiku-4-5" would be consent to whatever
 * that alias points at next month. A catalog change is a deliberate commit.
 */
export const MODEL_CATALOG = {
  anthropic: ["claude-haiku-4-5-20251001", "claude-sonnet-4-5-20250929"],
  openai: ["gpt-4o-mini-2024-07-18", "gpt-4o-2024-08-06"],
  mock: ["ctn/demo-model-a", "ctn/demo-model-b", "ctn/demo-model-fast"],
} as const satisfies Record<string, readonly string[]>;

export type CatalogProvider = keyof typeof MODEL_CATALOG;

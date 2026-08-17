/**
 * Phase 3 — Clio-lite facet taxonomy (spec §5). A CLOSED, versioned enum.
 *
 * Everything in this module runs INSIDE the enclave on the plaintext already
 * decrypted for the gate. Only a member of `Facet` ever leaves — never the
 * prompt, never any text derived from it. Adding a facet is a deliberate,
 * labelled change; do not open the enum to free text.
 */

export type Facet =
  // Safety facets — one per policy category (a DENY's facet is the category
  // that denied it; these are the ZK-proven categories P1..P7).
  | "weapons"
  | "malware_cyber"
  | "phishing_fraud"
  | "violence"
  | "self_harm"
  | "csam"
  // Benign facets — the local keyword classifier over ALLOWED prompts.
  | "coding"
  | "writing"
  | "research"
  | "data_analysis"
  | "education"
  | "business"
  | "creative"
  | "translation"
  | "conversation"
  | "technical_ops"
  // Unclassified / suppressed.
  | "other";

/** The 6 safety facets — derived from the policy categories, never keywords. */
export const SAFETY_FACETS: readonly Facet[] = [
  "weapons",
  "malware_cyber",
  "phishing_fraud",
  "violence",
  "self_harm",
  "csam",
] as const;

/** The 10 benign facets — the closed-enum outputs of the keyword classifier. */
export const BENIGN_FACETS: readonly Facet[] = [
  "coding",
  "writing",
  "research",
  "data_analysis",
  "education",
  "business",
  "creative",
  "translation",
  "conversation",
  "technical_ops",
] as const;

/** The complete closed enum, including "other". Order is stable and load-bearing. */
export const FACETS: readonly Facet[] = [
  ...SAFETY_FACETS,
  ...BENIGN_FACETS,
  "other",
] as const;

/**
 * Policy category id → safety facet (spec §5, verified against policy/v1/rules.json):
 *   P1 Credential theft / phishing   → phishing_fraud
 *   P2 Destructive malware           → malware_cyber
 *   P3 Actionable violent wrongdoing → violence
 *   P4 Weapons construction          → weapons
 *   P5 Sexual exploitation of minors → csam
 *   P6 Serious fraud facilitation    → phishing_fraud
 *   P7 Self-harm facilitation        → self_harm
 *
 * These are the SAME categories the guest proves; the facet is nothing more
 * than a rename of the deciding category. Not semantically complete — exactly
 * as obfuscation-resistant (and as limited) as the policy engine itself.
 */
export const CATEGORY_FACET: Readonly<Record<string, Facet>> = {
  P1: "phishing_fraud",
  P2: "malware_cyber",
  P3: "violence",
  P4: "weapons",
  P5: "csam",
  P6: "phishing_fraud",
  P7: "self_harm",
};

/**
 * Deterministic order used to break ties when two policy categories are over
 * threshold with the SAME score. Lower index wins. Matches the rules.json order.
 */
export const CATEGORY_ORDER: readonly string[] = ["P1", "P2", "P3", "P4", "P5", "P6", "P7"];

/**
 * The benign keyword classifier (spec §5/§9). A map of facet → representative
 * keywords/phrases, matched over the ALREADY-NORMALIZED text (`@ctn/policy`
 * `normalize`: NFKC fold, lowercase, leetspeak fold, whitespace/punctuation
 * collapsed to single spaces). This is a HEURISTIC, not an LLM and not an
 * embedding model — facets are approximate and can be wrong. Order matters:
 * ties in match count are broken by the order below (earlier = wins), so
 * generic facets (`conversation`) sit last.
 *
 * Single-token keywords match on whole tokens (space-bounded); multi-word
 * keywords match as a phrase. Deliberately no bare "write"/"make"/"help" — they
 * are too generic and would swamp every prompt.
 */
export const BENIGN_KEYWORDS: ReadonlyArray<readonly [Facet, readonly string[]]> = [
  [
    "coding",
    [
      "code",
      "coding",
      "function",
      "python",
      "javascript",
      "typescript",
      "java",
      "rust",
      "golang",
      "regex",
      "bug",
      "debug",
      "compile",
      "refactor",
      "algorithm",
      "api",
      "sql query",
      "unit test",
      "stack trace",
      "class",
      "variable",
      "loop",
      "array",
      "sort a list",
    ],
  ],
  [
    "translation",
    [
      "translate",
      "translation",
      "in french",
      "to french",
      "in spanish",
      "to spanish",
      "in german",
      "to german",
      "in japanese",
      "to japanese",
      "in chinese",
      "to chinese",
      "into english",
      "to english",
    ],
  ],
  [
    "data_analysis",
    [
      "analyze",
      "analyse",
      "dataset",
      "data set",
      "spreadsheet",
      "csv",
      "regression",
      "correlation",
      "statistics",
      "statistical",
      "chart",
      "graph the",
      "pivot table",
      "average of",
      "median",
      "histogram",
    ],
  ],
  [
    "research",
    [
      "research",
      "research paper",
      "cite",
      "citation",
      "hypothesis",
      "literature review",
      "study",
      "findings",
      "abstract of",
      "peer reviewed",
      "methodology",
    ],
  ],
  [
    "education",
    [
      "explain",
      "teach me",
      "what is",
      "how does",
      "homework",
      "study guide",
      "lesson",
      "quiz me",
      "tutor",
      "define",
      "learn about",
      "for my class",
      "exam",
    ],
  ],
  [
    "business",
    [
      "marketing",
      "business plan",
      "invoice",
      "sales pitch",
      "market research",
      "revenue",
      "startup",
      "pitch deck",
      "customer",
      "roi",
      "kpi",
      "quarterly",
      "strategy for",
      "product launch",
    ],
  ],
  [
    "creative",
    [
      "story",
      "short story",
      "poem",
      "poetry",
      "novel",
      "screenplay",
      "song",
      "lyrics",
      "fiction",
      "character",
      "fairy tale",
      "sonnet",
      "haiku",
      "fantasy",
    ],
  ],
  [
    "writing",
    [
      "essay",
      "blog post",
      "blog",
      "article",
      "email",
      "letter",
      "cover letter",
      "resume",
      "summary",
      "summarize",
      "paraphrase",
      "proofread",
      "rewrite",
      "grammar",
      "draft a",
    ],
  ],
  [
    "technical_ops",
    [
      "docker",
      "kubernetes",
      "server",
      "deploy",
      "nginx",
      "linux",
      "bash",
      "shell",
      "cron",
      "systemd",
      "firewall",
      "dns",
      "container",
      "ssh",
      "port",
      "restart the",
      "config",
    ],
  ],
  [
    "conversation",
    [
      "hello",
      "hi there",
      "how are you",
      "good morning",
      "lets chat",
      "chat",
      "your opinion",
      "what do you think",
      "tell me a joke",
      "advice",
      "recommend a",
    ],
  ],
];

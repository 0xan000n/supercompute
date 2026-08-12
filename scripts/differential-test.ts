/**
 * Differential test: TypeScript Safety Policy v1 engine vs the Rust `policy-core` port.
 *
 * The Rust crate is the engine that will run inside the zkVM guest, so the only
 * property that matters is that it agrees with `packages/policy/src/engine.ts`
 * on every input. This harness is the permanent, CI-blocking proof of that
 * claim: `pnpm test` runs it, and it exits non-zero on ANY divergence in
 * `normalize()` output, decision, the per-category score vector (values AND
 * order), `intentPresent` / `constructionPresent` / `hardBlock` /
 * `modifiersApplied`.
 *
 * Four suites:
 *
 *   1. FIXTURES (125)    every `policy/v1/fixtures/{allow,deny,adversarial}/*.json`
 *                        evaluated on both engines and compared field-for-field.
 *   2. RANDOMIZED (500)  generated Unicode adversarial cases — fullwidth folds,
 *                        zero-width splices, combining marks, mixed NFC/NFD/NFKD
 *                        source forms, leetspeak, punctuation/symbol separator
 *                        runs, rules.json phrases spliced into Unicode noise.
 *   3. ZERO-WIDTH (7)    the exact strip set at engine.ts:71 — U+200B..U+200F,
 *                        U+2060, U+FEFF — asserted stripped, identically, by both.
 *   4. SKEW AUDIT        a full sweep of the Unicode code point space comparing
 *                        `normalize()` on both engines, asserting every
 *                        behavioural divergence is FAIL-SAFE. See below.
 *
 * ## Why suite 2 samples from a restricted code point pool, and suite 4 exists
 *
 * The two engines read *different Unicode versions*. Node's V8/ICU is Unicode
 * 16.0 (`process.versions.unicode`); Rust's tables — `unicode-normalization`,
 * `unicode-properties`, and `str::to_lowercase` from the standard library — are
 * Unicode 17.0. Code points assigned in 17 but not in 16 are therefore
 * classified by Rust and passed through untouched by Node, which is a real,
 * measurable behavioural difference: V8 sees `\p{Cn}`, leaves the character in
 * place and the phrase does not match; Rust sees (say) `Po`, collapses it to a
 * space and the phrase does match.
 *
 * That skew is unavoidable — no amount of porting removes it — so it is
 * *characterised* instead of hidden:
 *
 *   * The randomized suite (2) samples only from long-stable, `\p{Assigned}`
 *     BMP material, so it is green today and stays green: a failure there means
 *     a genuine port bug, not a table version bump.
 *   * The skew audit (4) sweeps the entire code point space and asserts the
 *     direction of every divergence. Rust denying where TS allows is acceptable
 *     (fail-safe: the guest is stricter than the gateway). TS denying where Rust
 *     allows is a HARD FAIL — that would mean the proof says "safe" about a
 *     request the gateway itself rejected.
 *
 * VALIDATION.md §"Unicode version skew" states the same thing in prose.
 *
 * Usage:
 *   pnpm test:differential
 *   CTN_DIFF_SEED=12345 pnpm test:differential   # reproduce a randomized failure
 *   CTN_DIFF_CASES=5000 pnpm test:differential   # soak the randomized suite
 */

import { spawnSync, spawn, type ChildProcessByStdio } from "node:child_process";
import type { Readable, Writable } from "node:stream";
import { createInterface } from "node:readline";
import { existsSync, readdirSync, readFileSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import {
  loadPolicyPackage,
  evaluateRequest,
  normalize,
  requestText,
  type PolicyEvaluation,
} from "@ctn/policy";

const HERE = dirname(fileURLToPath(import.meta.url));
const ROOT = resolve(HERE, "..");
const PROVER_DIR = join(ROOT, "prover");
const RULES_PATH = join(ROOT, "policy", "v1", "rules.json");
const FIXTURE_DIR = join(ROOT, "policy", "v1", "fixtures");
const SHIM_BIN = join(PROVER_DIR, "target", "release", "policy_shim");

interface Message {
  role: string;
  content: string;
}

// ---------------------------------------------------------------- toolchain --

const CARGO_MISSING = `
  The differential test needs the Rust toolchain, and \`cargo\` was not found.

  This test is NOT optional and does NOT skip: it is the only thing keeping the
  Rust policy engine (the one that runs inside the zkVM guest, and therefore the
  one the proofs are about) byte-identical to the TypeScript engine the gateway
  enforces. A silent skip here would let the two drift apart unnoticed.

  Install it:

    curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
    source "$HOME/.cargo/env"

  If it is already installed, cargo lives in ~/.cargo/bin — make sure that is on
  PATH for whatever shell runs \`pnpm test\`:

    export PATH="$HOME/.cargo/bin:$PATH"
`;

/** cargo on PATH, else the rustup default location, else a loud failure. */
function resolveCargo(): string {
  if (spawnSync("cargo", ["--version"], { encoding: "utf8" }).status === 0) return "cargo";
  const home = process.env.HOME ?? "";
  const rustup = join(home, ".cargo", "bin", "cargo");
  if (home && existsSync(rustup)) return rustup;
  console.error(`\nDIFFERENTIAL TEST FAILED: cargo not found\n${CARGO_MISSING}`);
  process.exit(1);
}

/**
 * Build the shim once and return the compiled binary's path. The binary is then
 * spawned directly — `cargo run` per invocation pays cargo's whole resolve +
 * freshness-check cost on every call, which for a 1.1M-case sweep is absurd.
 */
function buildShim(): string {
  const cargo = resolveCargo();
  const build = spawnSync(
    cargo,
    ["build", "--release", "-p", "policy-core", "--bin", "policy_shim"],
    { cwd: PROVER_DIR, stdio: ["ignore", "inherit", "inherit"], encoding: "utf8" }
  );
  if (build.status !== 0) {
    console.error(
      `\nDIFFERENTIAL TEST FAILED: could not build the policy shim (cargo exit ${build.status}).\n` +
        `  cd prover && cargo build --release -p policy-core --bin policy_shim\n`
    );
    process.exit(1);
  }
  if (!existsSync(SHIM_BIN)) {
    console.error(`\nDIFFERENTIAL TEST FAILED: cargo reported success but ${SHIM_BIN} is missing.\n`);
    process.exit(1);
  }
  return SHIM_BIN;
}

// --------------------------------------------------------------- shim client --

/**
 * A short batch response would otherwise compare `undefined` against a real TS
 * answer and be reported as a divergence, which is a misleading way to say "the
 * protocol broke". Say the true thing instead.
 */
function expectSameLength<T>(op: string, want: number, got: T[] | undefined): T[] {
  if (!Array.isArray(got) || got.length !== want) {
    throw new Error(`${op}: asked for ${want} results, shim returned ${got?.length ?? "none"}`);
  }
  return got;
}

/**
 * One long-lived shim process speaking newline-delimited JSON. Requests are
 * answered in order, so a FIFO of pending resolvers is all the correlation this
 * needs. Batch ops exist because per-op line framing dominates at sweep scale.
 */
class Shim {
  /** stderr is inherited, so the shim's panics land in the test output verbatim. */
  readonly #proc: ChildProcessByStdio<Writable, Readable, null>;
  readonly #pending: Array<{
    resolve: (v: Record<string, unknown>) => void;
    reject: (e: Error) => void;
  }> = [];
  #dead: Error | null = null;

  constructor(bin: string) {
    this.#proc = spawn(bin, [], { stdio: ["pipe", "pipe", "inherit"] });
    createInterface({ input: this.#proc.stdout, crlfDelay: Infinity }).on("line", (line) => {
      const waiter = this.#pending.shift();
      if (!waiter) return;
      try {
        waiter.resolve(JSON.parse(line) as Record<string, unknown>);
      } catch (e) {
        waiter.reject(new Error(`shim emitted unparseable line: ${String(e)}`));
      }
    });
    const die = (why: string) => {
      this.#dead = new Error(why);
      while (this.#pending.length) this.#pending.shift()!.reject(this.#dead);
    };
    this.#proc.on("exit", (code, signal) => die(`shim exited (code=${code} signal=${signal})`));
    this.#proc.on("error", (e) => die(`shim failed to spawn: ${e.message}`));
  }

  async request(req: unknown): Promise<Record<string, unknown>> {
    if (this.#dead) throw this.#dead;
    const promise = new Promise<Record<string, unknown>>((resolve, reject) => {
      this.#pending.push({ resolve, reject });
    });
    this.#proc.stdin.write(JSON.stringify(req) + "\n");
    const res = await promise;
    if (typeof res.error === "string") throw new Error(`shim error: ${res.error}`);
    return res;
  }

  async normalizeBatch(texts: string[]): Promise<string[]> {
    const res = await this.request({ op: "normalizeBatch", texts });
    return expectSameLength("normalizeBatch", texts.length, res.normalized as string[]);
  }

  async evaluateBatch(requests: Message[][]): Promise<PolicyEvaluation[]> {
    const res = await this.request({ op: "evaluateBatch", rulesPath: RULES_PATH, requests });
    return expectSameLength("evaluateBatch", requests.length, res.evaluations as PolicyEvaluation[]);
  }

  close(): void {
    this.#proc.stdin.end();
    this.#proc.kill();
  }
}

// ------------------------------------------------------------- comparison ----

/**
 * Canonical string form of an evaluation. The category vector stays an ARRAY so
 * its order is compared, not just its contents (engine.ts:175 iterates
 * `Object.entries(rules.categories)` and that order is part of the contract).
 * `hardBlock` is absent on the normal TS return and `skip_serializing_if`-elided
 * on the Rust one, so both collapse to null here.
 */
function canonEval(ev: PolicyEvaluation): string {
  return JSON.stringify({
    decision: ev.decision,
    categories: (ev.categories ?? []).map((c) => ({
      category: c.category,
      name: c.name,
      score: c.score,
      threshold: c.threshold,
      matchedTargets: c.matchedTargets,
    })),
    intentPresent: ev.intentPresent,
    constructionPresent: ev.constructionPresent,
    hardBlock: ev.hardBlock ?? null,
    modifiersApplied: ev.modifiersApplied,
  });
}

/** Code-point escape of a string, so a failure report is copy-pasteable. */
function esc(s: string): string {
  return Array.from(s)
    .map((c) => {
      const cp = c.codePointAt(0)!;
      if (cp >= 0x20 && cp < 0x7f) return c;
      return `\\u{${cp.toString(16).toUpperCase()}}`;
    })
    .join("");
}

interface Divergence {
  suite: string;
  id: string;
  detail: string;
}

const divergences: Divergence[] = [];

function expectEqual(suite: string, id: string, what: string, ts: string, rs: string): void {
  if (ts === rs) return;
  divergences.push({
    suite,
    id,
    detail: `${what}\n      ts: ${esc(ts)}\n      rs: ${esc(rs)}`,
  });
}

// ------------------------------------------------------------- PRNG + pools --

/** mulberry32 — small, fast, fully specified, so a seed reproduces exactly. */
function mulberry32(seed: number): () => number {
  let a = seed >>> 0;
  return () => {
    a = (a + 0x6d2b79f5) | 0;
    let t = Math.imul(a ^ (a >>> 15), 1 | a);
    t = (t + Math.imul(t ^ (t >>> 7), 61 | t)) ^ t;
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
  };
}

type Rng = () => number;
const pick = <T>(rng: Rng, xs: readonly T[]): T => xs[Math.floor(rng() * xs.length)]!;
const int = (rng: Rng, lo: number, hi: number): number => lo + Math.floor(rng() * (hi - lo + 1));

/**
 * Blocks that have carried the same assignments and properties across many
 * Unicode versions. Deliberately conservative: nothing added after Unicode 8.0,
 * so a Node ICU bump or a Rust table bump cannot move any of it. Each range is
 * then filtered through Node's own `\p{Assigned}` to drop reserved holes
 * (U+2065, the halfwidth-forms gaps, ...). That filter consults only the TS
 * side's tables — it is a *version* filter, not an agreement filter, so it
 * cannot mask a genuine port bug.
 */
const STABLE_RANGES: ReadonlyArray<readonly [number, number]> = [
  [0x0030, 0x0039], // digits (leet fold sources)
  [0x0041, 0x005a], // basic latin upper
  [0x0061, 0x007a], // basic latin lower
  [0x00c0, 0x00ff], // latin-1 letters
  [0x0100, 0x017f], // latin extended-A
  [0x0300, 0x036f], // combining diacritical marks
  [0x2000, 0x206f], // general punctuation (incl. the zero-width set)
  [0x20a0, 0x20bd], // currency symbols, through Unicode 7.0
  [0x2200, 0x22ff], // mathematical operators
  [0x4e00, 0x9fa5], // CJK unified ideographs, the Unicode 3.0 core block
  [0xff01, 0xff5e], // fullwidth forms
  [0xff61, 0xffdc], // halfwidth forms
];

function buildPool(ranges: ReadonlyArray<readonly [number, number]>): string[] {
  const assigned = /\p{Assigned}/u;
  const out: string[] = [];
  for (const [lo, hi] of ranges) {
    for (let cp = lo; cp <= hi; cp++) {
      if (cp >= 0xd800 && cp <= 0xdfff) continue;
      const c = String.fromCodePoint(cp);
      if (assigned.test(c)) out.push(c);
    }
  }
  return out;
}

const STABLE_POOL = buildPool(STABLE_RANGES);
const MARK_POOL = buildPool([[0x0300, 0x036f]]);
const HALFWIDTH_POOL = buildPool([[0xff61, 0xffdc]]);
const SEPARATOR_POOL = STABLE_POOL.filter((c) => /[\p{P}\p{S}]/u.test(c));

/** engine.ts:71 — the exact zero-width strip set, as code points. */
const ZERO_WIDTH = ["​", "‌", "‍", "‎", "‏", "⁠", "﻿"];

/** Inverse of the engine.ts:73-81 leet fold. */
const LEET: Record<string, string[]> = {
  a: ["@", "4"],
  s: ["$", "5"],
  o: ["0"],
  i: ["1"],
  e: ["3"],
  t: ["7"],
};

// ---------------------------------------------------------------- fixtures ---

interface Fixture {
  id: string;
  expected: "ALLOW" | "DENY";
  description: string;
  request: { model: string; messages: Message[]; temperature: number; max_tokens: number };
}

function loadFixtures(): Fixture[] {
  const out: Fixture[] = [];
  for (const bucket of ["allow", "deny", "adversarial"]) {
    const dir = join(FIXTURE_DIR, bucket);
    for (const f of readdirSync(dir).sort()) {
      if (!f.endsWith(".json")) continue;
      out.push(JSON.parse(readFileSync(join(dir, f), "utf8")) as Fixture);
    }
  }
  return out;
}

// -------------------------------------------------------------- generators ---

/**
 * Each generator is a transform over an already-chosen base text, so cases can
 * compose two of them (a fullwidth fold of a zero-width-spliced phrase, etc.).
 */
type Transform = (rng: Rng, s: string) => string;

const TRANSFORMS: Record<string, Transform> = {
  /** ASCII -> fullwidth (U+FF01..U+FF5E), space -> U+3000 IDEOGRAPHIC SPACE. */
  fullwidth: (rng, s) =>
    Array.from(s)
      .map((c) => {
        const cp = c.codePointAt(0)!;
        if (rng() < 0.25) return c;
        if (cp === 0x20) return "　";
        if (cp >= 0x21 && cp <= 0x7e) return String.fromCodePoint(cp + 0xfee0);
        return c;
      })
      .join(""),

  /** Halfwidth katakana + fullwidth digits/letters mixed in, NFKC-foldable. */
  halfwidth: (rng, s) => {
    const chars = Array.from(s);
    const at = int(rng, 0, chars.length);
    const run = Array.from({ length: int(rng, 1, 4) }, () => pick(rng, HALFWIDTH_POOL)).join("");
    return chars.slice(0, at).join("") + run + chars.slice(at).join("");
  },

  /** Zero-width characters spliced mid-phrase — the classic phrase splitter. */
  zerowidth: (rng, s) => {
    const chars = Array.from(s);
    const n = int(rng, 1, 6);
    for (let i = 0; i < n; i++) {
      chars.splice(int(rng, 0, chars.length), 0, pick(rng, ZERO_WIDTH));
    }
    return chars.join("");
  },

  /** Combining marks stacked on letters (NFKC may or may not recompose them). */
  combining: (rng, s) =>
    Array.from(s)
      .map((c) => {
        if (!/\p{L}/u.test(c) || rng() < 0.6) return c;
        let out = c;
        for (let i = int(rng, 1, 3); i > 0; i--) out += pick(rng, MARK_POOL);
        return out;
      })
      .join(""),

  /** A random normalization form applied to a random slice of the input. */
  mixedforms: (rng, s) => {
    const form = pick(rng, ["NFC", "NFD", "NFKC", "NFKD"] as const);
    const chars = Array.from(s);
    if (chars.length < 4 || rng() < 0.4) return s.normalize(form);
    const a = int(rng, 0, chars.length - 1);
    const b = int(rng, a, chars.length);
    return (
      chars.slice(0, a).join("") +
      chars.slice(a, b).join("").normalize(form) +
      chars.slice(b).join("")
    );
  },

  /** Leetspeak, i.e. the inverse of the engine's fold. */
  leet: (rng, s) =>
    Array.from(s)
      .map((c) => {
        const subs = LEET[c.toLowerCase()];
        if (!subs || rng() < 0.45) return c;
        return pick(rng, subs);
      })
      .join(""),

  /** Runs of punctuation/symbol code points, which the engine collapses. */
  separators: (rng, s) => {
    const parts = s.split(" ");
    return parts
      .map((p, i) => {
        if (i === parts.length - 1) return p;
        let run = " ";
        if (rng() < 0.7) {
          run = Array.from({ length: int(rng, 1, 4) }, () => pick(rng, SEPARATOR_POOL)).join("");
        }
        return p + run;
      })
      .join("");
  },

  /** Splice the phrase into a bed of arbitrary version-stable Unicode noise. */
  noise: (rng, s) => {
    const noiseRun = () =>
      Array.from({ length: int(rng, 1, 8) }, () => pick(rng, STABLE_POOL)).join("");
    const chars = Array.from(s);
    const at = int(rng, 0, chars.length);
    return (
      (rng() < 0.6 ? noiseRun() + " " : "") +
      chars.slice(0, at).join("") +
      (rng() < 0.5 ? noiseRun() : "") +
      chars.slice(at).join("") +
      (rng() < 0.6 ? " " + noiseRun() : "")
    );
  },
};

const TRANSFORM_NAMES = Object.keys(TRANSFORMS);

interface RandomCase {
  id: string;
  gen: string;
  messages: Message[];
}

/**
 * Base texts: every phrase the rules document can match on (targets, modifiers,
 * intent, construction, suppressors, hard blocks) plus every fixture prompt.
 * Sampling from these keeps generated cases near the decision thresholds, where
 * a divergence actually changes an answer, rather than in the trivially-ALLOW
 * interior.
 */
function buildBaseTexts(fixtures: Fixture[]): string[] {
  const pkg = loadPolicyPackage();
  const r = pkg.rules;
  const phrases = [
    ...r.intentPhrases,
    ...r.constructionVerbs,
    ...r.modifierSuppressors,
    ...r.targets.flatMap((t) => t.phrases),
    ...r.hardBlocks.flatMap((h) => h.phrases),
    ...r.modifiers.flatMap((m) => m.phrases),
  ];
  const prompts = fixtures.flatMap((f) => f.request.messages.map((m) => m.content));
  return [...phrases, ...prompts];
}

function generateCases(rng: Rng, count: number, baseTexts: string[]): RandomCase[] {
  const cases: RandomCase[] = [];
  for (let i = 0; i < count; i++) {
    // A base text is one phrase, or a couple of them welded together — the
    // second form is how "intent + construction + target" combinations arise.
    let text = pick(rng, baseTexts);
    for (let extra = int(rng, 0, 2); extra > 0; extra--) {
      text += " " + pick(rng, baseTexts);
    }

    const applied: string[] = [];
    for (let t = int(rng, 1, 2); t > 0; t--) {
      const name = pick(rng, TRANSFORM_NAMES);
      applied.push(name);
      text = TRANSFORMS[name]!(rng, text);
    }

    // ~20% multi-message, to exercise `requestText`'s newline join on both sides.
    let messages: Message[];
    if (rng() < 0.2) {
      const chars = Array.from(text);
      const cut = int(rng, 0, chars.length);
      messages = [
        { role: "system", content: chars.slice(0, cut).join("") },
        { role: "user", content: chars.slice(cut).join("") },
      ];
    } else {
      messages = [{ role: "user", content: text }];
    }

    cases.push({ id: `rand-${String(i).padStart(4, "0")}`, gen: applied.join("+"), messages });
  }
  return cases;
}

// ------------------------------------------------------------- skew audit ----

/**
 * The probe is the substring of a live DENY-adjacent phrase that the injected
 * code point actually sits in: "how do i build a pipe<CP>bomb" scores P4 95/60
 * when "pipe bomb" survives normalization, and 0 when the code point splits it.
 * Sweeping the shorter form keeps the pipe traffic to ~15MB per direction; the
 * divergent code points are then re-tested with the FULL phrase through
 * `evaluate` on both engines, which is what actually decides the direction.
 */
const PROBE_PREFIX = "pipe";
const PROBE_SUFFIX = "bomb";
const LIVE_PREFIX = "how do i build a pipe";
const LIVE_SUFFIX = "bomb";
/**
 * Probes per shim request. Large enough that line framing stops mattering
 * (68 round trips for the whole space), small enough that neither side has to
 * hold the sweep in memory as one JSON document.
 */
const SWEEP_CHUNK = 16384;

interface SkewResult {
  swept: number;
  divergentNormalize: number[];
  /** Of the divergent code points, how many Node considers unassigned. */
  divergentUnassigned: number;
  failSafeFlips: number[];
  failUnsafeFlips: number[];
  cosmetic: number;
}

async function skewAudit(shim: Shim): Promise<SkewResult> {
  const probes: string[] = [];
  const codepoints: number[] = [];
  for (let cp = 0; cp <= 0x10ffff; cp++) {
    // Lone surrogates are skipped: they are not text, JSON cannot carry one and
    // `serde_json` rejects them. JS strings *can* hold them, which makes them a
    // host-boundary question for the prover daemon, not a normalizer question.
    if (cp >= 0xd800 && cp <= 0xdfff) continue;
    codepoints.push(cp);
    probes.push(PROBE_PREFIX + String.fromCodePoint(cp) + PROBE_SUFFIX);
  }

  const divergent: number[] = [];
  for (let i = 0; i < probes.length; i += SWEEP_CHUNK) {
    const slice = probes.slice(i, i + SWEEP_CHUNK);
    const rs = await shim.normalizeBatch(slice);
    for (let j = 0; j < slice.length; j++) {
      if (normalize(slice[j]!) !== rs[j]) divergent.push(codepoints[i + j]!);
    }
  }

  // Direction check on the full live phrase, for the divergent code points only.
  const liveRequests: Message[][] = divergent.map((cp) => [
    { role: "user", content: LIVE_PREFIX + String.fromCodePoint(cp) + LIVE_SUFFIX },
  ]);
  const rsEvals = liveRequests.length ? await shim.evaluateBatch(liveRequests) : [];

  const failSafe: number[] = [];
  const failUnsafe: number[] = [];
  let cosmetic = 0;
  for (let i = 0; i < divergent.length; i++) {
    const tsDecision = evaluateRequest(liveRequests[i]!).decision;
    const rsDecision = rsEvals[i]!.decision;
    if (tsDecision === rsDecision) cosmetic++;
    else if (tsDecision === "ALLOW" && rsDecision === "DENY") failSafe.push(divergent[i]!);
    else failUnsafe.push(divergent[i]!);
  }

  // Reported, not asserted. Today all 133 divergent code points are ones Node's
  // Unicode 16.0 tables call unassigned and Rust's Unicode 17.0 tables classify
  // — i.e. the divergence is purely a table-version artefact. A divergence on a
  // code point BOTH sides consider assigned would be a different and much worse
  // animal (a genuine property disagreement), so the split is printed every run
  // rather than folded into one number.
  const unassigned = /\P{Assigned}/u;
  const divergentUnassigned = divergent.filter((cp) =>
    unassigned.test(String.fromCodePoint(cp))
  ).length;

  return {
    swept: probes.length,
    divergentNormalize: divergent,
    divergentUnassigned,
    failSafeFlips: failSafe,
    failUnsafeFlips: failUnsafe,
    cosmetic,
  };
}

// -------------------------------------------------------------------- main ---

async function main(): Promise<void> {
  const seed = process.env.CTN_DIFF_SEED
    ? Number(process.env.CTN_DIFF_SEED) >>> 0
    : (Math.random() * 0x100000000) >>> 0;
  const randomCount = process.env.CTN_DIFF_CASES ? Number(process.env.CTN_DIFF_CASES) : 500;
  if (!Number.isFinite(seed) || !Number.isInteger(randomCount) || randomCount < 1) {
    console.error("CTN_DIFF_SEED must be a number; CTN_DIFF_CASES a positive integer");
    process.exit(1);
  }

  const bin = buildShim();
  const shim = new Shim(bin);
  const started = Date.now();

  try {
    // -- suite 1: fixtures ---------------------------------------------------
    const fixtures = loadFixtures();
    const fixtureEvals = await shim.evaluateBatch(fixtures.map((f) => f.request.messages));
    const fixtureTexts = fixtures.map((f) => requestText(f.request.messages));
    const fixtureNorms = await shim.normalizeBatch(fixtureTexts);
    for (let i = 0; i < fixtures.length; i++) {
      const f = fixtures[i]!;
      expectEqual("fixtures", f.id, "normalize()", normalize(fixtureTexts[i]!), fixtureNorms[i]!);
      const ts = evaluateRequest(f.request.messages);
      expectEqual("fixtures", f.id, "evaluate()", canonEval(ts), canonEval(fixtureEvals[i]!));
      if (ts.decision !== f.expected) {
        divergences.push({
          suite: "fixtures",
          id: f.id,
          detail: `ground truth: expected ${f.expected}, TS engine says ${ts.decision}`,
        });
      }
    }

    // -- suite 2: randomized -------------------------------------------------
    const rng = mulberry32(seed);
    const cases = generateCases(rng, randomCount, buildBaseTexts(fixtures));
    const caseTexts = cases.map((c) => requestText(c.messages));
    const caseNorms = await shim.normalizeBatch(caseTexts);
    const caseEvals = await shim.evaluateBatch(cases.map((c) => c.messages));
    for (let i = 0; i < cases.length; i++) {
      const c = cases[i]!;
      const id = `${c.id}[${c.gen}]`;
      expectEqual("randomized", id, "normalize()", normalize(caseTexts[i]!), caseNorms[i]!);
      expectEqual(
        "randomized",
        id,
        "evaluate()",
        canonEval(evaluateRequest(c.messages)),
        canonEval(caseEvals[i]!)
      );
    }

    // -- suite 3: the zero-width strip set (engine.ts:71) --------------------
    // Task 2's in-crate tests only reach 3 of the 7; this harness owns all 7,
    // permanently. Each must vanish, identically, on both engines — and must
    // therefore fail to split "pipe|bomb".
    const zwTexts = ZERO_WIDTH.map((z) => PROBE_PREFIX + z + PROBE_SUFFIX);
    const zwNorms = await shim.normalizeBatch(zwTexts);
    for (let i = 0; i < ZERO_WIDTH.length; i++) {
      const cp = ZERO_WIDTH[i]!.codePointAt(0)!.toString(16).toUpperCase().padStart(4, "0");
      const ts = normalize(zwTexts[i]!);
      expectEqual("zero-width", `U+${cp}`, "normalize()", ts, zwNorms[i]!);
      if (ts !== "pipebomb") {
        divergences.push({
          suite: "zero-width",
          id: `U+${cp}`,
          detail: `not stripped: normalize("pipe<ZW>bomb") = ${esc(ts)}, expected "pipebomb"`,
        });
      }
    }

    // -- suite 4: the Unicode version skew audit -----------------------------
    const skew = await skewAudit(shim);
    if (skew.failUnsafeFlips.length > 0) {
      divergences.push({
        suite: "skew-audit",
        id: "FAIL-UNSAFE",
        detail:
          `${skew.failUnsafeFlips.length} code point(s) flip DENY(TS) -> ALLOW(Rust). The guest ` +
          `would prove "safe" for a request the gateway rejects. Code points: ` +
          skew.failUnsafeFlips
            .slice(0, 40)
            .map((cp) => `U+${cp.toString(16).toUpperCase().padStart(4, "0")}`)
            .join(" "),
      });
    }

    const elapsed = ((Date.now() - started) / 1000).toFixed(1);
    const total = fixtures.length + cases.length;

    if (divergences.length > 0) {
      // A skew-audit failure is the safety-critical class — the guest proving
      // "safe" for something the gateway denies — so it is reported first and
      // is never the thing the truncation eats. An engine bug that breaks
      // normalize() typically raises hundreds of ordinary divergences with it.
      const ranked = [
        ...divergences.filter((d) => d.suite === "skew-audit"),
        ...divergences.filter((d) => d.suite !== "skew-audit"),
      ];
      console.error(`\nDIFFERENTIAL TEST FAILED — ${divergences.length} divergence(s):\n`);
      for (const d of ranked.slice(0, 25)) {
        console.error(`  [${d.suite}] ${d.id}: ${d.detail}`);
      }
      if (ranked.length > 25) console.error(`  ... and ${ranked.length - 25} more`);
      console.error(`\n  Reproduce: CTN_DIFF_SEED=${seed} pnpm test:differential\n`);
      shim.close();
      process.exit(1);
    }

    const unicodeTs = process.versions.unicode ?? "unknown";
    console.log(
      `differential: ${total}/${total} identical ` +
        `(${fixtures.length} fixtures + ${cases.length} randomized), seed ${seed}`
    );
    console.log(
      `differential: zero-width strip set ${ZERO_WIDTH.length}/${ZERO_WIDTH.length} agree ` +
        `(U+200B..U+200F, U+2060, U+FEFF)`
    );
    console.log(
      `differential: skew audit swept ${skew.swept.toLocaleString("en-US")} code points ` +
        `(TS/ICU Unicode ${unicodeTs} vs Rust tables) — ` +
        `${skew.divergentNormalize.length} normalize divergences ` +
        `(${skew.divergentUnassigned} unassigned in Unicode ${unicodeTs}), ` +
        `${skew.failSafeFlips.length} fail-safe ALLOW(TS)->DENY(Rust), ` +
        `${skew.cosmetic} decision-neutral, ` +
        `${skew.failUnsafeFlips.length} fail-unsafe (must be 0)`
    );
    console.log(`differential: ok in ${elapsed}s`);
    shim.close();
  } catch (e) {
    shim.close();
    console.error(`\nDIFFERENTIAL TEST FAILED: ${e instanceof Error ? e.stack : String(e)}\n`);
    process.exit(1);
  }
}

await main();

# Phase 2a: Standalone RISC Zero Prover — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** A working, self-contained RISC Zero prover for Safety Policy v1: the policy engine ported to Rust and compiled into a zkVM guest image, an executor-gating + proving daemon on :4500, an offline verifier CLI pinned to a release manifest, and measured M1 Pro timings — all provably byte-equivalent to the TS engine (125 fixtures + randomized Unicode differential tests).

**Architecture:** New `prover/` Cargo workspace, four crates: `policy-core` (the ported engine, host-and-guest shared), `methods` (the guest program, rules compiled into the image), `host` (daemon: `/execute` fast path + single-worker `/prove` queue), `verify` (offline CLI, `disable-dev-mode`). Services in `services/` are untouched — Phase 2b wires them in.

**Tech Stack:** Rust stable via rustup, RISC Zero via rzup (latest stable at install time — pinned in `prover/release.json` once known), serde/serde_json (`preserve_order`), `unicode-normalization`, `unicode-properties`, `sha2`, `postcard`, `axum`. Node-side: one differential-test script, no new npm deps.

**Spec:** `docs/superpowers/specs/2026-08-11-supercompute-real-design.md` §4, §5.2, §8, §9 (receipt schema split §5.5, queue persistence §5.6, and all `services/` wiring are **Phase 2b**).

## Global Constraints

- **The TS engine is the semantic contract.** `packages/policy/src/engine.ts` (202 lines) defines normalize/match/evaluate byte-for-byte; the 125 fixtures in `policy/v1/fixtures/{allow,deny,adversarial}` are the acceptance floor; randomized Unicode differential tests are REQUIRED from day one, not on divergence.
- **Executor gating is required — no native fallback.** The same guest image gates (executor) and proves. If the spike shows slow executor latency, it is accepted and documented; policy slimming only via a versioned policy change.
- **Dev-mode is hard-excluded from anything demo-shaped:** `prover/host` refuses `RISC0_DEV_MODE=1` unless started with an explicit `--dev` flag that stamps every response `devMode: true`; `prover/verify` is built with the `disable-dev-mode` feature so fake receipts can never verify.
- **Offline verification:** `prover/verify` must succeed with networking unavailable, trusting only its arguments and the checked-in `prover/release.json`.
- **policyId v2 decision (recorded here, reconciled TS-side in 2b):** the current TS `policyId = SHA256(canonical_manifest ‖ rules_bytes ‖ guestImageId)` is self-referential once the guest is real (an image cannot contain its own hash). Phase 2a bakes `policyId = "0x" + SHA256(canonical_manifest_bytes ‖ rules_bytes)` into the guest at build time; the ImageID binds the code separately, and `release.json` links the two. Journal shape: `{ protocolVersion: 1, requestCommitment, policyId, decision, proofNonce }` — exactly the existing verifier allowlist (`services/tee-sim/src/verify.ts`), scores NEVER in the journal.
- **Commitment formula (guest recomputes, never trusts the host):** `"0x" + hex(SHA256("CTN_REQUEST_V1" ‖ canonical_request_bytes ‖ request_nonce_32))` — matches `packages/protocol/src/crypto.ts:50`.
- Rust code: `cargo fmt` clean, `cargo clippy -- -D warnings` clean, `cargo test` green — these are the workspace gates alongside the repo's existing `npx tsc --noEmit -p tsconfig.json` && `pnpm test` (which must stay green; Phase 2a adds `pnpm test:differential` and it becomes part of `pnpm test`).
- risc0 API details (executor entry points, receipt serialization, image-id constants) MUST be verified against the installed version's docs (`cargo doc -p risc0-zkvm --open` or docs.rs pinned to the installed version) — the shapes in this plan are anchors, not gospel. Record the installed versions in `prover/release.json` and `prover/README.md`.
- Money/keys never touch this workspace; no secrets in prover logs (the canonical request bytes ARE the plaintext prompt — `prover/host` must never log request bodies; same discipline as `enclave-log`).

---

### Task 1: Toolchain + hello-guest spike (timings are this task's deliverable)

**Files:**
- Create: `prover/Cargo.toml` (workspace), `prover/rust-toolchain.toml`, `prover/.gitignore` (`target/`)
- Create: `prover/methods/Cargo.toml`, `prover/methods/build.rs`, `prover/methods/guest/Cargo.toml`, `prover/methods/guest/src/main.rs` (spike guest: sha256 of input, committed to journal)
- Create: `prover/host/Cargo.toml`, `prover/host/src/main.rs` (spike binary: `--bench` mode only for now)
- Create: `prover/README.md` (toolchain install, versions, dev-mode policy)
- Modify: `VALIDATION.md` (new §66 addendum: measured numbers)
- Modify: `README.md` (build prerequisites: rustup + rzup)

**Interfaces:**
- Produces: a building risc0 workspace; `cargo run -p host -- --bench` prints executor latency + composite proving time + receipt size for 256-byte and 4096-byte inputs; measured numbers recorded in VALIDATION.md.

- [ ] **Step 1: Install the toolchain** (system-level dev tooling — expected):

```bash
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y --default-toolchain stable
source "$HOME/.cargo/env"
curl -L https://risczero.com/install | bash
export PATH="$HOME/.risc0/bin:$PATH"   # or as the installer instructs
rzup install
cargo risczero --version && rustc --version
```

Record the exact risc0 / cargo-risczero / rustc versions in `prover/README.md`.

- [ ] **Step 2: Scaffold with the official template, then reshape**

```bash
cd /Users/ankit/code/supercompute/compute-trust-network
cargo risczero new prover --guest-name policy-guest
```

Reshape to the four-crate layout this plan names (keep `methods`/`methods/guest` as the template lays them out — the template's build.rs wiring is load-bearing). Add `prover/` to the repo's root `.gitignore` only for `prover/target/`.

- [ ] **Step 3: Spike guest** — read a `Vec<u8>` frame from the host, compute sha256, commit the digest:

```rust
// prover/methods/guest/src/main.rs
use risc0_zkvm::guest::env;
use sha2::{Digest, Sha256};

fn main() {
    let input: Vec<u8> = env::read_frame();          // verify exact read API against installed docs
    let digest: [u8; 32] = Sha256::digest(&input).into();
    env::commit_slice(&digest);
}
```

(If the installed risc0 exposes an accelerated sha256 precompile crate, note it in README but keep `sha2` — the policy guest needs the same crate host-side for identical bytes.)

- [ ] **Step 4: Bench harness in host** — for input sizes 256 B and 4096 B, measure and print:
  - executor-only wall time (no proof) — the number that will gate every live request,
  - composite proving wall time,
  - receipt byte size (bincode-serialized),
  - verify wall time.

Use the installed version's documented entry points (as of risc0 2.x: `default_executor().execute(env, ELF)` for executor-only; `default_prover().prove(env, ELF)` for composite; adjust to the real API). Run each measurement 3×, print median.

- [ ] **Step 5: Run the bench, record the numbers**

Run: `cd prover && cargo run -rp host -- --bench`
Record medians in `VALIDATION.md` §66 addendum ("Phase 2a spike, M1 Pro 32 GB: executor Xms / composite prove Ys / receipt Z KB / verify Wms") and in `prover/README.md`. If composite proving exceeds ~10 min, STOP and report BLOCKED (spec §9 escalation) — do not proceed on numbers that break the product shape.

- [ ] **Step 6: Gates + commit**

```bash
cd prover && cargo fmt --check && cargo clippy -- -D warnings && cargo test
cd .. && npx tsc --noEmit -p tsconfig.json && pnpm test   # untouched, must stay green
git add prover README.md VALIDATION.md .gitignore
git commit -m "prover: risc0 workspace + spike benchmarks (M1 Pro numbers in VALIDATION §66)"
```

---

### Task 2: `policy-core` — the engine port (native, no zkVM)

**Files:**
- Create: `prover/policy-core/Cargo.toml` (deps: `serde` + `serde_json` with `preserve_order`, `unicode-normalization`, `unicode-properties`; NO risc0 deps — this crate is shared host/guest)
- Create: `prover/policy-core/src/lib.rs`, `src/normalize.rs`, `src/rules.rs`, `src/engine.rs`
- Test: `prover/policy-core/src/engine_test.rs` (unit tests from the TS engine's own documented edge cases)

**Interfaces:**
- Produces (Task 3/4 consume):
  - `pub struct PolicyRules { … }` mirroring `packages/policy/src/engine.ts:24-41`, with `categories: IndexMap<String, CategoryMeta>` — **insertion order preserved** (`serde_json/preserve_order`), because the TS engine iterates `Object.entries(rules.categories)` in insertion order and the score vector's order must match.
  - `pub fn normalize(text: &str) -> String`
  - `pub struct Evaluation { pub decision: Decision, pub categories: Vec<CategoryScore>, pub intent_present: bool, pub construction_present: bool, pub hard_block: Option<String>, pub modifiers_applied: Vec<String> }`
  - `pub fn evaluate(rules: &PolicyRules, raw_text: &str) -> Evaluation`
  - `pub fn request_text(messages: &[Message]) -> String` — contents joined `"\n"` (`packages/policy/src/index.ts:81-83`)

- [ ] **Step 1: Extract the EXACT zero-width strip set from the TS source** — the regex at `packages/policy/src/engine.ts:71` contains raw codepoints. Do not guess:

```bash
sed -n '71p' packages/policy/src/engine.ts | hexdump -C
```

Decode the UTF-8 and enumerate the codepoints (expected shape: U+200B–U+200F range, U+2060, U+FEFF — but the bytes are the truth). Write them as an explicit Rust const with a comment citing the TS line.

- [ ] **Step 2: Write failing unit tests first** — port the TS engine's own documented behaviors as Rust tests before implementing:

```rust
#[test] fn kill_matches_killing_never_skill() { /* engine.ts:108-109 */ }
#[test] fn fullwidth_forms_cannot_smuggle() { /* NFKC: "ｂｏｍｂ" normalizes to "bomb" */ }
#[test] fn spaced_out_needle_is_caught_by_squash() { /* "p i p e b o m b" ; SQUASH_MIN=8 */ }
#[test] fn leet_folds() { /* "p1p3 b0mb" -> "pipe bomb" */ }
#[test] fn multiword_optional_plural() { /* " needle s " boundary matching */ }
#[test] fn suppressor_voids_modifiers() { /* engine.ts:159-170 */ }
#[test] fn hard_block_denies_immediately_with_empty_categories() { /* engine.ts:140-153 */ }
#[test] fn bonuses_only_when_target_matched_and_clamp_at_zero() { /* engine.ts:185-190 */ }
```

Run: `cargo test -p policy-core` — all fail (nothing implemented).

- [ ] **Step 3: Implement `normalize`** — the porting hazards, called out explicitly:
  - NFKC via `unicode_normalization::UnicodeNormalization::nfkc`, then lowercase. Rust `str::to_lowercase` and JS `toLowerCase` both implement full Unicode lowercasing; divergences are exactly what Task 3's differential tests exist to catch — do not "improve" either side.
  - Zero-width strip: the Step-1 const.
  - Leet folds: literal char replaces in the TS order (`@→a $→s 0→o 1→i 3→e 4→a 5→s 7→t`) — order matters only for idempotence, keep it identical anyway.
  - Collapse `[\s\p{P}\p{S}]+` → single space, then trim. JS `\s` and Rust `char::is_whitespace` differ on U+FEFF (JS includes it; Rust does not) — harmless HERE because FEFF is stripped earlier, but write the comment so nobody "simplifies" the strip set. `\p{P}`/`\p{S}` via `unicode_properties::GeneralCategoryGroup::{Punctuation,Symbol}`.

- [ ] **Step 4: Implement corpus + match + evaluate** as a line-for-line port of `engine.ts:87-202`: padded/tokens/squashed corpus; multi-word = space-bounded whole phrase + optional trailing `s`; single-word = exact token, or token-prefix when needle `len >= 4` (chars of the normalized needle; `str::starts_with` on normalized tokens is correct because both sides are the same UTF-8); squashed substring when separator-free needle `len >= 8` (`SQUASH_MIN`); hard-blocks first; suppressors void modifiers; bonuses and modifier total apply only when the category matched at least one target; clamp at 0; DENY when `score >= threshold`.

- [ ] **Step 5: Run tests** — `cargo test -p policy-core`: all green. `cargo fmt --check && cargo clippy -- -D warnings`.

- [ ] **Step 6: Commit**

```bash
git add prover/policy-core
git commit -m "policy-core: rust port of the safety policy engine"
```

---

### Task 3: Fixture cross-validation + randomized Unicode differential tests (CI-blocking)

**Files:**
- Create: `prover/policy-core/src/bin/policy_shim.rs` (stdin JSON → stdout JSON: `{"op":"normalize","text":…}` → `{"normalized":…}`; `{"op":"evaluate","rulesPath":…,"messages":…}` → full evaluation incl. score vector)
- Create: `prover/policy-core/tests/fixtures.rs` (Rust side: run all 125 fixtures directly)
- Create: `scripts/differential-test.ts` (Node side: both engines, fixtures + randomized cases)
- Modify: root `package.json` (`"test:differential": "tsx scripts/differential-test.ts"`, and append it to the root `"test"` chain so `pnpm test` runs it — a missing cargo toolchain must FAIL LOUDLY with install instructions, never skip silently)

**Interfaces:**
- Consumes: fixture format `policy/v1/fixtures/{allow,deny,adversarial}/*.json`: `{ id, expected: "ALLOW"|"DENY", description, request: { model, messages: [{role, content}], temperature, max_tokens } }` (125 files).
- Produces: `pnpm test:differential` — exits non-zero on ANY divergence in: decision, per-category score vector (values AND order), `intentPresent`/`constructionPresent`/`hardBlock`/`modifiersApplied`, and `normalize()` output.

- [ ] **Step 1: Rust fixture test (failing first if the port is wrong):** read `policy/v1/rules.json` + every fixture, `evaluate(rules, request_text(messages))`, assert `decision == expected`. Run: `cargo test -p policy-core --test fixtures` → 125/125.

- [ ] **Step 2: The shim** — one process per invocation is too slow for 125+N cases; read newline-delimited JSON ops from stdin until EOF, answer one JSON line each. Keep it dumb.

- [ ] **Step 3: `scripts/differential-test.ts`** — spawn the shim once (`cargo run -q -rp policy-core --bin policy_shim`), then:
  - all 125 fixtures: compare full TS evaluation (`evaluateRequest` from `@ctn/policy`) against shim output field-by-field;
  - **500 randomized cases** (deterministic PRNG, seed printed and overridable via `CTN_DIFF_SEED` so failures reproduce): generators for fullwidth/halfwidth forms, zero-width joiners inserted mid-phrase, combining marks, mixed NFC/NFD/NFKD source forms, leet substitutions, random `\p{P}\p{S}` separator runs, random phrases sampled from `rules.json` targets/modifiers spliced into random Unicode noise — compare `normalize()` outputs AND full evaluations;
  - print a one-line summary (`625/625 identical, seed 12345`), non-zero exit + a reproducer command on divergence.

- [ ] **Step 4: Wire into `pnpm test`** and run the full gate stack:

```bash
pnpm test              # now includes test:differential
npx tsc --noEmit -p tsconfig.json
cd prover && cargo fmt --check && cargo clippy -- -D warnings && cargo test
```

- [ ] **Step 5: Commit**

```bash
git add prover scripts/differential-test.ts package.json
git commit -m "differential: 125 fixtures + 500 randomized unicode cases, TS vs rust, CI-blocking"
```

---

### Task 4: The policy guest — rules compiled into the image

**Files:**
- Modify: `prover/methods/guest/src/main.rs` (replace spike guest), `prover/methods/guest/Cargo.toml` (add `policy-core`, `postcard`, `sha2`, `serde`)
- Create: `prover/methods/guest/build.rs` (embed rules: parse `policy/v1/rules.json` + `manifest.json` at build time → postcard bytes via `include_bytes!(concat!(env!("OUT_DIR"), …))`; also bake `POLICY_ID_V2` and `RULES_DIGEST` consts)
- Create: `prover/policy-core/src/input.rs` (shared input/journal types)
- Test: `prover/host/tests/guest_io.rs` (executor round-trip tests)

**Interfaces:**
- Produces (Task 5/6 and Phase 2b consume — exact shapes):

```rust
/// PolicyInputV1 — what the host sends the guest. postcard-serialized frame.
#[derive(Serialize, Deserialize)]
pub struct PolicyInputV1 {
    pub protocol_version: u32,            // must be 1
    pub canonical_request_bytes: Vec<u8>, // the SIGNED canonical request, verbatim
    pub request_nonce: [u8; 32],
    pub proof_nonce: String,              // caller-chosen; guest-validated ^(0x)?[0-9a-f]{1,64}$ (Task 4 fix round 1 — an unbounded host field was a journal exfiltration channel), then echoed in the journal
    pub emit_scores: bool,                // executor mode only; prove path sends false
}

/// PolicyJournalV1 — the ONLY public output. Field names match the TS verifier
/// allowlist (services/tee-sim/src/verify.ts): protocolVersion, requestCommitment,
/// policyId, decision, proofNonce. Serialized to the journal as canonical JSON bytes
/// (sorted keys, no floats) so the TS side can parse it without a Rust dependency.
pub struct PolicyJournalV1 {
    pub protocol_version: u32,   // "protocolVersion": 1
    pub request_commitment: String,
    pub policy_id: String,       // baked POLICY_ID_V2
    pub decision: String,        // "ALLOW" | "DENY"
    pub proof_nonce: String,
}
```

- Private scores: when `emit_scores`, the guest writes the full evaluation (category vector, flags) as one JSON line to guest stdout; the host captures it via the ExecutorEnv stdout hook (executor mode only — the prove path never captures it, and it is never committed).

- [ ] **Step 1: build.rs** — read `../../../policy/v1/{rules.json,manifest.json}` (path-relative to the crate; use `CARGO_MANIFEST_DIR`), validate with `policy-core`'s `PolicyRules` type, write postcard bytes + a generated `consts.rs` containing `POLICY_ID_V2` (= `"0x" + hex(sha256(canonical_manifest_bytes ‖ rules_bytes))` — reuse the TS `canonical()` semantics: implement canonical-manifest serialization in build.rs with sorted keys/NFC strings, mirroring `packages/policy/src/index.ts:31-47`) and `RULES_DIGEST` (= `"0x" + hex(sha256(rules_bytes))`). `cargo:rerun-if-changed` on both JSON files — **a one-byte rules change now changes the ImageID**, which is the §14 demo beat.

- [ ] **Step 2: Guest main:**

```rust
fn main() {
    let input: PolicyInputV1 = read_postcard_frame();      // exact API per installed docs
    assert_eq!(input.protocol_version, 1, "unsupported protocol version");

    // Commitment computed IN the guest — never trusted from the host (spec §5.2).
    let commitment = request_commitment(&input.canonical_request_bytes, &input.request_nonce);

    let rules: PolicyRules = postcard::from_bytes(EMBEDDED_RULES).unwrap();
    let request: CanonicalRequest = serde_json::from_slice(&input.canonical_request_bytes)
        .expect("canonical request bytes must parse");
    let eval = evaluate(&rules, &request_text(&request.messages));

    if input.emit_scores {
        // stdout, NOT the journal — captured only by the executor host.
        println!("{}", scores_json(&eval));
    }
    env::commit_slice(&journal_canonical_json_bytes(
        1, &commitment, POLICY_ID_V2, decision_str(&eval), &input.proof_nonce,
    ));
}
```

- [ ] **Step 3: Executor round-trip tests** (`prover/host/tests/guest_io.rs`), failing first:
  - a fixture ALLOW request: journal decision "ALLOW", commitment equals the value computed independently in the test (port the formula), `policyId` = build-time const, scores captured via stdout hook;
  - a fixture DENY request: "DENY";
  - `emit_scores: false` → stdout empty;
  - journal parses as JSON whose key set is EXACTLY `{protocolVersion, requestCommitment, policyId, decision, proofNonce}` (the allowlist, †no scores ever);
  - tampered `protocol_version: 2` → guest panics (executor session errors).

- [ ] **Step 4: Cross-check against TS**: extend `scripts/differential-test.ts` with 5 end-to-end cases — canonicalize a request TS-side (`toCanonicalRequest` + `canonicalJson` from `@ctn/protocol`), compute the commitment TS-side (`requestCommitment`), run the guest via a new shim op (`{"op":"guest-execute", …}` — host-side helper binary `prover/host --execute-stdin`), assert journal fields byte-equal the TS-computed expectations.

- [ ] **Step 5: Gates** (cargo suite + pnpm test incl. differential) — all green.

- [ ] **Step 6: Commit**

```bash
git add prover scripts/differential-test.ts
git commit -m "guest: policy engine in-image, journal = verifier allowlist, commitment in-guest"
```

---

### Task 5: `prover/host` — the daemon (:4500)

**Files:**
- Modify: `prover/host/Cargo.toml` (add `axum`, `tokio`, `base64`), `prover/host/src/main.rs`
- Create: `prover/host/src/server.rs`, `prover/host/src/queue.rs`
- Test: `prover/host/tests/api.rs` (spawn the server on an ephemeral port, hit every endpoint; ONE real (small) prove end-to-end, guarded so it runs in `--release` CI runs only if `CTN_PROVE_TEST=1` — document the ~minutes cost)

**Interfaces (Phase 2b consumes these exactly):**
- `POST /execute` `{ protocolVersion: 1, canonicalRequestBytesB64, requestNonceHex, proofNonce, emitScores }` → `200 { journal: {…allowlist fields…}, privateScores: {...}|null, execWallMs }`; malformed input → 400 with a reason that NEVER echoes request bytes.
- `POST /prove` (same body minus `emitScores`) → `202 { jobId }` — single-worker FIFO, in-memory (persistence is 2b, coordinator-side).
- `GET /jobs/:id` → `{ status: "QUEUED"|"PROVING"|"GENERATED"|"FAILED", receiptB64?, proveWallMs?, error? }` (receipt = bincode-serialized risc0 receipt).
- `GET /health` → `{ imageIdHex, policyId, rulesDigest, risc0Version, devMode: false }`.
- Startup: binds 127.0.0.1 ONLY; refuses `RISC0_DEV_MODE=1` unless `--dev` was passed, in which case `/health.devMode = true` and every job response carries `devMode: true`.
- Logging: request bodies and canonical bytes are NEVER logged (the bytes are the plaintext prompt) — log jobIds, sizes, timings, digests only.

- [ ] **Step 1: Failing API tests** (assert the shapes above, including: `/execute` twice on the same input is deterministic; dev-mode refusal — spawn with `RISC0_DEV_MODE=1` and no `--dev`, expect exit non-zero with a clear message; a log-capture assertion that a request's canonical bytes never appear in server output).
- [ ] **Step 2: Implement** (single tokio runtime; the prove worker is one dedicated thread consuming an mpsc queue — proving is CPU/GPU-bound and must not starve `/execute`).
- [ ] **Step 3: Run tests**; run ONE `CTN_PROVE_TEST=1` release-mode prove test and record its wall time in `prover/README.md`.
- [ ] **Step 4: Gates + commit**

```bash
git add prover
git commit -m "prover/host: :4500 execute/prove daemon, single-worker queue, dev-mode refusal"
```

---

### Task 6: `prover/verify` CLI + pinned release manifest

**Files:**
- Create: `prover/verify/Cargo.toml` (dep `risc0-zkvm` with **`disable-dev-mode`** feature; `policy-core` for journal parsing)
- Create: `prover/verify/src/main.rs`
- Create: `prover/release.json` (generated once, committed): `{ imageIdHex, policyId, rulesDigest, journalVersion: 1, risc0Version, receiptCodec: "bincode-v1", builtAt }` — emitted by `cargo run -rp host -- --emit-release`
- Test: `prover/verify/tests/verify.rs`
- Modify: `prover/README.md` (verification instructions anyone can follow)

**Interfaces:**
- `prover-verify --receipt <file> [--release <path=prover/release.json>] [--expect-commitment 0x… --expect-decision ALLOW|DENY --expect-proof-nonce …]` → exit 0 + a check-by-check report (seal valid against pinned imageId; journal parses; journal key set is exactly the allowlist; policyId/rulesDigest match the manifest; expectations match if given). Non-zero + the failing check otherwise. **No network I/O anywhere in the binary.**

- [ ] **Step 1: Failing tests:** valid receipt verifies; tampered journal byte → fails on seal; receipt proved from a different image (re-prove the Task-1 spike guest for this) → fails on imageId; `release.json` with wrong rulesDigest → fails on manifest; a dev-mode receipt (produce one via `RISC0_DEV_MODE=1` with the host's `--dev`) → **fails to verify** (the `disable-dev-mode` feature is the enforcement, not a string check).
- [ ] **Step 2: Implement; generate + commit `prover/release.json`.**
- [ ] **Step 3: Offline proof:** run the passing verify under a network-denied environment (`--offline` is structural — but demonstrate: run with networking disabled via sandbox or by asserting the binary has no reqwest/hyper in `cargo tree`) — record the method used in the README.
- [ ] **Step 4: Gates + commit**

```bash
git add prover
git commit -m "prover/verify: offline verifier pinned to release.json, dev-mode receipts rejected"
```

---

### Task 7: Bench suite + docs + labelling

**Files:**
- Modify: `prover/host/src/main.rs` (`--bench` grows a fixtures mode)
- Modify: `VALIDATION.md` (§66 addendum finalized), `prover/README.md`, root `README.md`
- Modify: `apps/web/src/app/trust/page.tsx` — ONLY if a claim there is now false; otherwise leave it (the trust-page rewrite belongs to 2b when the proof is actually wired in). Read it and decide; state the decision in the report.

- [ ] **Step 1: Bench over the fixture corpus:** executor latency distribution across all 125 fixture requests (min/median/p95), 3 real composite proofs (one ALLOW, one DENY, one adversarial) timed end-to-end incl. verify. **Debt from Task 4 fix round 1:** prove/receipt/verify numbers and total/paging/reserved cycles in `prover/README.md` are still the PRIOR image's (`4a05b4e9…`, marked †) — this bench re-measures them at the current image and retires the daggers; also fix the undaggered prose restatements the re-review flagged (README ~:255-260, :393-421, :674, and the backwards-reading delta at :340).
- [ ] **Step 2: Record** in VALIDATION §66 (replacing the spike's provisional numbers) with the honest sentence about what they mean for a live demo (per-request gate cost; proof lag).
- [ ] **Step 3: Docs:** `prover/README.md` = install, build, bench, verify walkthrough (the "anyone can verify" §5.2 promise, written down); root README gains the Rust prerequisite + one paragraph on what `prover/` is and is not (not yet wired into the demo — 2b).
- [ ] **Step 4: Full gates:** cargo suite; `pnpm test` (incl. differential); tsc; web build untouched-but-run.
- [ ] **Step 5: Commit**

```bash
git add prover VALIDATION.md README.md
git commit -m "prover: fixture benchmarks + verification walkthrough; phase 2a complete"
```

---

## Self-review notes (applied)

- Spec coverage (2a slice): §5.2 guest input/journal/commitment-in-guest/rules-in-image/dev-mode ✓ (Tasks 4/5/6), §5.2 verification+manifest ✓ (Task 6), §8 differential requirements ✓ (Task 3), §9 spike-first ✓ (Task 1), §4 prover crates ✓. Deliberately NOT here (2b): receipt schema split (§5.5), queue persistence/backpressure (§5.6), enclave/coordinator wiring, `PROVER_UNAVAILABLE`, TS-side policyId v2 reconciliation, trust-page proof claims.
- The policyId v2 decision and the journal-as-canonical-JSON choice are recorded in Global Constraints so 2b implements against them, not around them.
- Type consistency: `PolicyInputV1`/`PolicyJournalV1` defined once (Task 4 Interfaces), consumed by Tasks 5/6 verbatim; shim ops defined in Task 3 and extended in Task 4.
- risc0 API shapes are marked as anchors requiring verification against the installed version — the one place this plan cannot be exact ahead of `rzup install`.

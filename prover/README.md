# prover

The real RISC Zero prover for Safety Policy v1. Phase 2a builds it; this
directory is currently at **Task 6 — the offline verifier**. The guest image *is*
Safety Policy v1 (the ruleset is compiled in, the request commitment is
recomputed inside the zkVM, and the journal it commits is the verifier's
allowlist and nothing else); `host --serve` puts it behind `127.0.0.1:4500` with
an executor fast path and a single-worker proving queue; and `prover-verify`
checks a receipt against `release.json` with no network and no trust in whoever
produced it. **Nothing in `services/` calls any of this** — wiring the daemon
into `tee-sim` is Phase 2b, and until that happens a verified receipt says a
proof exists, not that anything was gated on it.

Phase 1 modelled the cost of proving (`CTN_SIMULATED_PROVING_MS`, default
2400 ms) and labelled it as modelled. Everything from Task 1 on uses
measurements instead — see "Measured on this machine" below, which now carries
both the Task 1 spike numbers (a guest that only hashed its input) and the Task 4
policy-guest numbers. They are different guests and the difference is large.

---

## Toolchain

Two installers, neither of which is vendored into the repo. Both write outside
the working tree (`~/.cargo`, `~/.rustup`, `~/.risc0`).

```bash
# 1. Rust
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y --default-toolchain stable
source "$HOME/.cargo/env"

# 2. RISC Zero
curl -L https://risczero.com/install | bash
export PATH="$HOME/.risc0/bin:$PATH"
rzup install
```

`rzup install` fetches a purpose-built Rust toolchain for the zkVM target and
takes a while; several minutes is normal.

### Versions these numbers were taken on

| Component | Version |
|---|---|
| `rustc` (host) | 1.97.1 (8bab26f4f 2026-07-14) |
| `cargo` (host) | 1.97.1 (c980f4866 2026-06-30) |
| `rzup` | 0.5.0 |
| `cargo-risczero` | 3.0.6 |
| `r0vm` | 3.0.6 |
| risc0 Rust toolchain (guest) | 1.97.0 — `rustc 1.97.0-dev (e638c6cfe 2026-07-15)` |
| risc0 C++ toolchain | 2024.1.5 |
| `risc0-zkvm` / `risc0-build` crates | 3.0.6 |
| `unicode-normalization` / `unicode-properties` | 0.1.25 / 0.1.4 |

`release.json` carries these as data rather than prose — `cargo run -rp host --
--emit-release` reads them out of the build that produced the image, so they
cannot drift from this table without the table being visibly wrong.

`rust-toolchain.toml` still says `channel = "stable"`, and that is a decision
rather than an oversight. The toolchain that determines the ImageID is the
**guest** one, and it is already pinned outside cargo: `risc0-build` looks up
rzup's default Rust toolchain and forces it into the nested guest build through
`RUSTC`, after stripping `RUSTUP_TOOLCHAIN` from the environment
(`risc0-build-3.0.6/src/lib.rs:355-383, 436`). Pinning the host channel to
`1.97.1` would install a second copy of a compiler already present under another
toolchain name, force a full rebuild, and — given how little it takes to move an
ImageID (see "Reproducibility of the image") — require re-verifying the image and
re-cutting `release.json` and every fixture. What it would buy is host-side test
reproducibility, mainly the Unicode version behind `str::to_lowercase` in the
native differential runs. That is worth having and worth doing at a moment when
re-measuring is already planned; Task 7 re-measures. The concrete change, for
whoever does it:

```toml
[toolchain]
channel = "1.97.1"                                # was "stable"
components = ["rustfmt", "rust-src", "clippy"]    # clippy currently comes from
profile = "minimal"                               # the default-profile stable install
```

…followed by rebuilding and checking that
`cargo run -rp host -- --emit-release` still reports
`75751480a7e7d6b329de6614fee99e8d2cf9a793c32e9c1e3de057f8196b0ee1`. Meanwhile the
host compiler is *recorded* on every emit even though it is not enforced, so
drift is visible in a diff rather than silent.

Machine: Apple M1 Pro, 10 cores, 32 GB, macOS 26.0.1. **Proving here is CPU-only.**
Despite what the toolchain's shape suggests, risc0 3.0.6 does not use the GPU on
Apple Silicon — see "Proving is CPU-only" below.

---

## Layout

```
prover/
  Cargo.toml            workspace: host + methods + policy-core + release-manifest
                        (verify is EXCLUDED — its own workspace, see below)
  rust-toolchain.toml   stable, with rustfmt and rust-src
  release.json          the pinned image: ImageID, policy identity, toolchains
  policy-core/          the engine, compiled twice: natively and into the guest
    src/engine.rs         evaluate / evaluate_prepared — the port of engine.ts
    src/normalize.rs      the §23 normalizer
    src/prepared.rs       needles normalized once, at build time (see below)
    src/input.rs          PolicyInputV1, PolicyJournalV1, the commitment
    src/policy_id.rs      POLICY_ID_V2 / RULES_DIGEST derivation
    src/bin/policy_shim   the differential harness's Rust side
  methods/
    build.rs            embed_methods() + POLICY_ID_V2/RULES_DIGEST for host code
    src/lib.rs          include!(OUT_DIR/{methods.rs,policy_consts.rs})
    guest/build.rs      bakes policy/v1/{rules,manifest}.json INTO the image
    guest/src/main.rs   the guest: runs inside the zkVM
  host/
    build.rs            records the toolchains that built this binary
    src/lib.rs          execute_policy — run the image in the executor
    src/main.rs         --bench, --execute-stdin, --serve, --emit-release
    src/release.rs      builds release.json
    tests/guest_io.rs   executor round-trip tests against the real image
  release-manifest/     the shape of release.json — a leaf crate, shared by the
                        host that writes it and the verifier that reads it
  verify/               prover-verify: the offline verifier (own workspace)
    src/lib.rs            the checks
    src/main.rs           the CLI
    tests/fixtures/       four real receipts + how to regenerate them
```

This is the layout `cargo risczero new` generates, kept deliberately. The
`methods` build-script indirection is what produces `POLICY_GUEST_ELF` and
`POLICY_GUEST_ID`, and the image id is the measurement that says which policy
program produced a receipt — so the wiring is load-bearing, not boilerplate.

---

## What the guest commits, and what it does not

**Input** — one postcard frame, `PolicyInputV1`:
`{ protocolVersion, canonicalRequestBytes, requestNonce[32], proofNonce,
emitScores }`. `canonicalRequestBytes` is the signed canonical request verbatim;
it is the plaintext prompt, and nothing in this workspace may log it.
`proofNonce` must match `^(0x)?[0-9a-f]{1,64}$` — see below.

**Journal** — canonical JSON (JCS: keys sorted, no whitespace, strings NFC),
with the key set **exactly**
`{decision, policyId, proofNonce, protocolVersion, requestCommitment}` — the
allowlist `services/tee-sim/src/verify.ts` already enforces. Category scores are
prompt-derived and are never in it.

**Private scores** — when `emitScores` is set, the guest writes the full
evaluation as one JSON line to *stdout*, which only the executor host reads. The
prove path sends `emitScores: false` and captures nothing.

Three properties are the point of the design and each is one line of code:

1. **The ruleset is in the image.** `methods/guest/build.rs` reads
   `policy/v1/{rules,manifest}.json`, validates them with `policy-core`'s own
   types, and embeds them. A host-supplied ruleset could omit the rule that
   denies a prompt and the proof would still verify. A one-byte edit to either
   file changes the ImageID.
2. **The commitment is recomputed in the guest**:
   `"0x" + hex(SHA256("CTN_REQUEST_V1" ‖ canonicalRequestBytes ‖ nonce))`,
   matching `packages/protocol/src/crypto.ts:54`. It is never read from the
   frame.
3. **Non-canonical input is refused, not interpreted.** The request document is
   parsed with `deny_unknown_fields` and its roles are checked; anything else
   panics the guest and produces no journal.

Two more were added in Task 4's first fix round, and both are about the guest
not trusting the *host*.

### The journal's only variable-length field is bounded

`proofNonce` must match `^(0x)?[0-9a-f]{1,64}$`, checked **in the guest** before
anything is committed. Violations panic with a fixed string.

The journal is public. It is the one artifact this design promises carries no
prompt-derived data, and every verifier in the repository enforces that promise
by checking the *key set*. `proofNonce` was an unbounded, host-chosen string
echoed into that key set verbatim — so the promise held for the keys and not for
the bytes. Task 4's reviewer put a 2,298-byte journal containing a plaintext
prompt through it, and `services/tee-sim/src/verify.ts` accepted it, correctly:
the keys were right.

A key-set allowlist cannot close that. A bound can, and it has to be in the
guest, because the host is the party the bound is defending against — a
host-side check is advice, and the image is what the proof is about.

The shape is the tightest one every existing caller already satisfies:
`services/tee-sim/src/prover.ts:130` mints `"0x" + randomHex(32)`, and
`randomHex` (`packages/protocol/src/crypto.ts:121`) is lowercase hex. 66
characters is the longest legitimate nonce there is. Uppercase is rejected
rather than folded, because a guest that rewrote a caller's nonce would produce
a journal the caller cannot predict, and the journal is compared byte for byte.

### Every refusal is a constant

`policy_core::GuestRejection` is the closed set of reasons the guest stops, and
each renders to a `&'static str` with nothing interpolated. The host reduces any
executor failure to one of them (`host::classify_guest_failure`) or to
`UNCLASSIFIED_FAILURE`, and **never** returns the underlying error.

This is two independent defences because the channel needs two. risc0's
`PosixIo::default` wires guest fd 2 to the **host process's** `std::io::stderr()`
(`risc0-zkvm-3.0.6/src/host/client/posix_io.rs:36-43`), so a guest panic is
printed by the executor before any host code can decide whether it should be.
`execute_frame_with` now names an explicit in-memory sink for guest stderr, and
the guest's messages are constants, so neither the sink nor the taxonomy is
load-bearing alone.

The bug this closes was real and is reproducible on the previous commit: the
guest panicked with `serde_json`'s message, which quotes the offending value, so

```text
{"max_tokens":"<secret>", …}
  → canonical request bytes do not parse: invalid type: string "<secret>", expected i64
```

went back to the caller *and* to the host's stderr. `deny_unknown_fields` did the
same with the field name. The code comment asserting that serde errors "never
contain a fragment of a string value" was simply wrong.

`host/tests/guest_io.rs` plants a marker in six such positions and asserts it
appears in neither the returned error nor the process's stderr (captured via
`dup2`, because that write happens inside risc0 and no Rust-level shim can see
it). Both halves were negative-controlled: reintroducing the interpolation fails
the returned-error assertion, and additionally dropping the stderr sink fails the
stderr assertion.

`CTN_UNSAFE_GUEST_DIAGNOSTICS=1` prints the raw error and the guest's stderr on
failure. It is named to say what it is; nothing in CI may set it.

### `policyId` v2 differs from the TypeScript `policyId` — on purpose

The guest bakes
`POLICY_ID_V2 = "0x" + hex(SHA256(canonical_manifest_bytes ‖ rules_bytes))`.

`packages/policy/src/index.ts:67` computes something else: it folds a *simulated*
`guestImageId` into the hash. That definition is self-referential once the guest
is a real compiled image — the image would have to contain its own measurement —
so Phase 2a splits the two: `POLICY_ID_V2` names the policy, the ImageID names
the code, and `prover/release.json` (Task 6) links them. **The TypeScript side is
deliberately untouched**; reconciling it is Phase 2b, and doing it now would
change every artifact Phase 1 already signed.

`scripts/differential-test.ts` recomputes `POLICY_ID_V2` in TypeScript and
asserts the image agrees, so the two derivations cannot drift silently.

`policy-core`'s canonicalizer mirrors two asymmetries in the TypeScript rather
than correcting them, because the identity has to be the same number, not a
better one: object **keys are not NFC-normalized** (index.ts:36 normalizes a
string value, index.ts:43 emits a key as plain `JSON.stringify(k)`), and keys
**sort by UTF-16 code unit**, which is what JS does and which differs from
Rust's code-point ordering for a BMP key above U+E000 against a supplementary
one. Today's manifest is ASCII, so neither bites.

There is a **third** divergence, and it cannot be mirrored, so it fails closed:
a JS `Number` is an IEEE-754 double, and `JSON.parse("9007199254740993")` is
already `9007199254740992` by the time `String(value)` sees it, while
`serde_json` keeps the exact `i64`. The two sides would have derived different
policy ids from the same file with nothing reporting a problem. Numbers outside
±`Number.MAX_SAFE_INTEGER`, and non-integers, are now an error in
`canonical_manifest_bytes` — the same bound `canonicalJson` enforces through
`Number.isSafeInteger`, chosen over the looser "±2^53" so the two sides agree
exactly rather than nearly.

None of this is asserted against a hardcoded expectation any more. Suite 6 of
`scripts/differential-test.ts` feeds fifteen hostile manifests — combining marks
in keys, two keys that NFC-collide, the U+FFFD / U+D7FF / U+E000 boundaries
against supplementary characters, `MAX_SAFE_INTEGER`, 2^53, 2^53+1, a `u64`, a
fraction — through **both** canonicalizers and compares. A one-sided refusal by
Rust is fail-closed and allowed but has to be declared in the probe table; a
one-sided refusal by *TypeScript* is a failure, because that is the direction
where the guest bakes an identity no verifier can reproduce. The suite found one
case on its first run: `serde_json` parses `-0` as the float `-0.0` and refuses
it, while `canonicalJson` emits `0`. It is declared, and it is the only one.

### Reproducibility of the image

`prover/methods/guest/target/` and `prover/target/riscv-guest/` deleted, then
`cargo build --release -p host`: the guest ELF came back **byte-identical**
(SHA-256 `e5fd1e0d47a2b4422c7a2c614bfaf4d752cc389362f050d38afffb5864414301`) and
so did the ImageID. That is one machine, one toolchain, two builds — it is
evidence that the build is not gratuitously nondeterministic, not a claim of
cross-machine reproducibility, which nothing here has tested. `release.json`
pins the toolchain versions; that is what makes the claim checkable by someone
else.

`policy-core` exposes its `policy_id` module behind a default feature, and the
guest takes the dependency with `default-features = false`. This did **not**
shrink the ELF — the linker was already dropping the unused code, measured — so
it buys intent rather than bytes: an auditor reading the crate graph does not
have to ask why a JSON canonicalizer is inside a measured policy image.

**It does not mean an edit to that module is free.** An earlier version of this
paragraph claimed "an edit to the canonicalizer cannot move the ImageID", and
that is false. Task 6 measured it: adding a new module to `policy-core` behind
an off-by-default feature the guest does not enable moved the ImageID from
`75751480a7e7…` to `52c3ede0c090…`, with no behavioural change of any kind.
rustc folds a hash of a crate's contents into the symbol names of everything
that links it, so **any** source edit to a crate the guest links — a comment, a
blank line, a module the guest cfg's away — is a new image. (This is the same
mechanism behind the note that guest panic locations carry line numbers.) That is
why the shape of `release.json` lives in its own `release-manifest` crate: a file
describing the image must not be able to move it. Feature gating buys clarity;
only *not editing the crate* buys a stable ImageID.

### Needles are normalized at build time

`normalize()` — NFKC, full-Unicode lowercase, a character walk — is the most
expensive thing the engine does, and it runs over every phrase in `rules.json` on
every evaluation. None of that work depends on the request, so `PreparedRules`
does it once, in `build.rs`, and the image carries the *prepared* form.

Measured in-guest with `env::cycle_count()`, ALLOW fixture, this machine:
preparing the needles inside the zkVM costs **2,264,222 cycles** (plus 202,190 to
parse `rules.json`); postcard-decoding the prepared form costs **358,084**. The
hoist is worth ~1.9M user cycles per execution, which is the difference between a
5-segment session and a 2-segment one. It is a pure hoist —
`policy_core::evaluate` still takes a `PolicyRules` and prepares it eagerly — and
the differential suite is what keeps that claim honest.

Generated with:

```bash
cargo risczero new prover --guest-name policy_guest
```

(`policy_guest`, not `policy-guest`: 3.0.6 requires the guest name to be a valid
Rust identifier.)

---

## Running

```bash
cd prover
cargo run -rp host -- --serve           # the daemon, 127.0.0.1:4500
cargo run -rp host -- --bench           # executor + prove + verify, ALLOW and DENY
CTN_BENCH_PROVE=0 cargo run -rp host -- --bench   # executor only (proving is minutes)
cargo run -rp host -- --execute-stdin   # newline-JSON executor service
cargo run -rp host -- --emit-release --out release.json   # regenerate the manifest
```

### The daemon (`--serve`)

`--serve [--port N] [--dev]`. It binds `127.0.0.1` and only `127.0.0.1` — the
bind address is not configurable, `--port` is (0 picks an ephemeral one, which is
what the tests use). Run it under `--release`: a debug executor run is much
slower than the 57 ms below.

| Endpoint | Body | Answer |
|---|---|---|
| `POST /execute` | `{protocolVersion, canonicalRequestBytesB64, requestNonceHex, proofNonce, emitScores}` | `200 {journal:{…5 allowlist fields…}, privateScores:{…}\|null, execWallMs}` |
| `POST /prove` | the same, minus `emitScores` | `202 {jobId}` |
| `GET /jobs/:id` | — | `{status:"QUEUED"\|"PROVING"\|"GENERATED"\|"FAILED", receiptB64?, proveWallMs?, error?, devMode}` |
| `GET /health` | — | `{imageIdHex, policyId, rulesDigest, risc0Version, devMode}` |

- `receiptB64` is base64 of the **bincode**-serialized risc0 receipt — the same
  codec `--bench` measures and the one `release.json` pins as
  `receiptCodec: "bincode-v1"`.
- Unknown fields are rejected, so sending `emitScores` to `/prove` is an error
  rather than a silently ignored option: the prove path never captures scores.
- Every refusal is `{"error": "<one of a fixed set of strings>"}` with status
  400 (malformed request, including a body over the 10 MiB cap or the wrong
  content type), 404 (`no such job`, `no such endpoint`), 503 (`prove queue is
  full`) or 500 (the daemon's own fault). **No reason string ever contains a byte
  of the request** — the guest-side ones are the `policy_core::GuestRejection`
  constants, the host-side ones are `&'static str`s in `host/src/server.rs`, and
  `tests/api.rs` plants a marker in every caller-controlled field and asserts it
  comes back in none of them and is logged nowhere.
- The queue is one worker thread, FIFO, in memory, and dies with the process. It
  holds at most 32 waiting jobs (`503` past that) and retains the last 64
  finished ones. Persistence and real backpressure are Phase 2b (§5.6).
- Logs go to **stderr** at `host=info` unless `RUST_LOG` says otherwise, and
  carry job ids, byte counts, wall times, digests and decisions — never canonical
  bytes, never scores, never the caller's proof nonce (its length instead).

`--execute-stdin` is what `scripts/differential-test.ts` drives: one JSON request
per line, one response per line, until EOF.

```text
-> {"op":"identity"}
<- {"imageId":"…","policyId":"0x…","rulesDigest":"0x…","protocolVersion":1}
-> {"op":"guestExecute","protocolVersion":1,"canonicalRequestBytesB64":"…",
    "requestNonceHex":"…","proofNonce":"…","emitScores":true}
<- {"journalJson":"{…}","privateScores":"{…}"|null,"userCycles":…,
    "segments":…,"maxPo2":…}
```

Field names match the `POST /execute` body the daemon accepts, so the harness and
the daemon speak the same vocabulary.

---

## Dev mode

`RISC0_DEV_MODE=1` makes risc0 skip proving entirely: `prove` returns a stub
receipt almost instantly and `verify` accepts it. It is useful when iterating on
guest logic and catastrophic anywhere near a measurement or a trust claim.

The rule for this directory:

- **`--bench` refuses to run in dev mode.** It checks
  `ProverOpts::composite().dev_mode()` — the options actually being proved with,
  not a global — and exits with an error rather than printing fast, meaningless
  numbers.
- No number in this README or in `VALIDATION.md` was produced in dev mode.
- **The daemon refuses to start under `RISC0_DEV_MODE` unless `--dev` is
  passed** — it exits non-zero with a one-line reason before it binds a port.
  With `--dev`, `/health.devMode` is `true` and *every* `/jobs/:id` response
  carries `devMode: true`, so a fake receipt cannot be collected without the
  daemon having said so. `--dev` is permission, not a switch: passing it without
  the variable still reports `devMode: true`, because the claim being made is
  "do not trust receipts from this daemon" and the flag is reason enough.

---

## Verifying a receipt offline

A receipt is only worth something to someone who did not produce it. This is the
program that lets them check one, on their own machine, with no network and no
trust in whoever handed them the file.

```bash
cd prover/verify
cargo build --release
./target/release/prover-verify \
    --receipt tests/fixtures/allow-real.receipt.bin \
    --release ../release.json
```

Run from the repository root instead and the defaults line up:
`--release` defaults to `prover/release.json`, and the policy directory defaults
to `policy/v1` *relative to the manifest*, not to the working directory.

```text
[ ok ] manifest                   pins imageId 75751480a7e7…, journalVersion 1, risc0 3.0.6, built 2026-08-14T09:09:59Z
[ ok ] receipt-codec              bincode-v1
[ ok ] receipt-decodes            537794 bytes
[ ok ] image-id                   the receipt claims 75751480a7e7…
[ ok ] seal                       cryptographically valid for the pinned imageId
[ ok ] journal-parses             JSON object, 259 bytes
[ ok ] journal-key-set            exactly {decision, policyId, proofNonce, protocolVersion, requestCommitment}
[ ok ] journal-protocol-version   1
[ ok ] journal-decision           ALLOW
[ ok ] journal-request-commitment 0x8873f02c…
[ ok ] journal-proof-nonce        0xbe0c0000000000000000000000000000
[ ok ] policy-id                  journal and manifest agree: 0x1f74ba4f…
[ ok ] rules-digest               re-derived from policy/v1: 0x9f85ba59…

VERIFIED
```

Exit 0 verified, 1 a check failed (the first failing check is named twice: on its
own line and in the last line of output), 2 a usage error. `--expect-commitment`,
`--expect-decision` and `--expect-proof-nonce` add checks for a caller who knows
what the answer should have been.

### What each check means

| check | what it establishes |
|---|---|
| `manifest` | `release.json` parses as a manifest — every field present, none unknown, the identities the right shape. An unknown key is a refusal, not a shrug: a verifier that ignores a field is trusting a claim it did not read. |
| `receipt-codec` | the manifest names a codec this binary can decode (`bincode-v1`). |
| `receipt-decodes` | the file is a `risc0_zkvm::Receipt` under that codec. |
| `image-id` | the ImageID in the receipt's claim is the pinned one. Split out from `seal` so "a valid proof of the wrong program" reads differently from "not a valid proof". |
| `seal` | the zero-knowledge proof verifies against the pinned ImageID, the guest exited `Halted(0)`, and the journal is the one the proof commits to. **This is the check that carries the weight.** |
| `journal-parses` | the committed bytes are a JSON object. The journal is *parsed, never re-encoded* — the bytes are already bound by the seal, so re-canonicalizing them would only test this program's serializer. |
| `journal-key-set` | exactly `{decision, policyId, proofNonce, protocolVersion, requestCommitment}` — the allowlist `services/tee-sim/src/verify.ts` enforces. No category scores, no prompt-derived anything. |
| `journal-protocol-version` | matches the manifest's `journalVersion`. |
| `journal-decision` | one of the two the engine can produce. |
| `journal-request-commitment` | `0x` + 64 lowercase hex. |
| `journal-proof-nonce` | inside `^(0x)?[0-9a-f]{1,64}$`. The guest enforces this bound too, but the guest is *the thing being authenticated* — a journal from any other image is bounded by nothing, and `proofNonce` is the only variable-length field in a public artifact. Checked here so a fat nonce fails on a named check rather than sliding through the key-set test. |
| `policy-id` | the `policyId` the image committed is the one the manifest pins. |
| `rules-digest` | `policy/v1/{rules,manifest}.json` re-derive the manifest's `policyId` **and** `rulesDigest`, through `policy_core::policy_id` — the same function the guest's build script used. |

That last one is the only check that looks outside the receipt, and it has to.
`rulesDigest` is not in the journal and no receipt can attest to it. What *is* in
the journal is `policyId = sha256(canonical_manifest ‖ rules_bytes)`, and
`rulesDigest = sha256(rules_bytes)` — so re-deriving both from the same two files,
with the `policyId` half already matched against the journal, ties the pinned
digest to the exact rules bytes the proving image was built from. Without the
files the check reports `[ -- ]` (not available) and the summary counts it;
`--no-policy-dir` asks for that explicitly. It is never silently skipped.

### What verification does and does not establish

**Does:** this journal was committed by the image whose ImageID `release.json`
pins, that image's baked policy identity is the one the manifest names, and — with
`policy/v1` present — that identity is the one the rules in front of you derive.
Every field printed above is a field the image itself committed.

**Does not:**

- **That any gateway consulted this proof before answering.** Nothing in Phase 2a
  puts a proof on the request path. The tool says so on every successful run, in
  its own output, because a green check mark invites the reader to supply their
  own meaning for it.
- **That the journal's request is the request a user sent.** The journal carries
  a commitment (`sha256("CTN_REQUEST_V1" ‖ canonical_bytes ‖ nonce)`), not the
  request. Tying a commitment to a request needs the request and the nonce, which
  the requester has and the verifier does not.
- **That the pinned ImageID is reproducible on your machine.** `release.json`
  pins the compilers so you can *try*; two builds on one machine have matched
  (see "Reproducibility of the image"), across machines is untested.
- **That the policy is good.** It is a demo ruleset. Verification is about
  provenance, not about whether `DENY` was the right answer.

### Dev-mode receipts are rejected cryptographically

`prover-verify` takes `risc0-zkvm` with the **`disable-dev-mode`** feature. With
it, `VerifierContext` cannot carry `dev_mode: true` at all, so
`FakeReceipt::verify_integrity_with_context` takes its `Err(InvalidProof)` branch
unconditionally. Nothing in this crate inspects a receipt to decide whether it is
a stub; the 719-byte dev receipt in `tests/fixtures/` fails the `seal` check the
way any invalid proof does, and the note explaining what it was is printed
*because* the check already failed.

Setting `RISC0_DEV_MODE=1` in the verifier's own environment cannot change that —
risc0 panics on the contradiction, and this binary pre-empts the panic with a
sentence and exit 2.

The claim was checked by removing the feature. Rebuilt without
`disable-dev-mode` and run with `RISC0_DEV_MODE=1`, the same binary **accepts the
same dev-mode stub**: all thirteen checks pass and it prints `VERIFIED`, exit 0.
The feature is load-bearing, not decoration. (Reverted immediately; the committed
build rejects it, exit 1.)

### No network I/O

Structural first. `risc0-zkvm` is taken with `default-features = false`, which
drops two defaults that both speak HTTP: `bonsai` (a client for a remote proving
service) and `client` (which pulls in `rzup`, a toolchain downloader, and
`risc0-build`). What is left is 148 crates with nothing network-capable in them:

```console
$ cd prover/verify && cargo tree | grep -Ei 'reqwest|hyper|tokio|bonsai|rzup|risc0-build|rustls|native-tls|openssl|curl|ureq'
$                       # no output

$ cd prover && cargo tree -p host | grep -Ei 'reqwest|hyper|rzup|risc0-build' | head
hyper v0.14.32
hyper v1.11.0
hyper-rustls v0.24.2
reqwest v0.12.28
risc0-build v3.0.6
```

The contrast is the point: the daemon legitimately links an HTTP stack, and the
verifier legitimately cannot.

Then behaviourally, under a macOS sandbox that denies all networking:

```bash
cat > /tmp/no-network.sb <<'EOF'
(version 1)
(allow default)
(deny network*)
EOF

# control: the profile really does deny networking
sandbox-exec -f /tmp/no-network.sb curl -sS https://example.com
# curl: (6) Could not resolve host: example.com          exit 6

sandbox-exec -f /tmp/no-network.sb ./prover/verify/target/debug/prover-verify \
    --receipt prover/verify/tests/fixtures/allow-real.receipt.bin \
    --release prover/release.json
# … VERIFIED                                             exit 0
```

Exit 0 on the real receipt and exit 1 on the dev stub, both with networking
denied. The `curl` line is there because a sandbox demonstration without a
control demonstrates nothing.

### Which receipt kind, and what `receiptCodec` pins

`receiptCodec: "bincode-v1"` names a **serialization**, not a receipt kind.
Composite, succinct and Groth16 receipts are all the same `risc0_zkvm::Receipt`
type, all encode with bincode 1.3, and `Receipt::verify` handles all three — so
the verifier is kind-agnostic, and `tests/fixtures/allow-succinct.receipt.bin`
is the fixture that keeps that from being an unchecked claim.

Measured on this machine (M1 Pro, 32 GB, release, CPU-only, **one run each**),
starting from the committed ALLOW receipt:

| kind | bytes | to produce | verify |
|---|---|---|---|
| composite | 537,794 | 124.57 s (the prove itself) | ~30 ms † |
| succinct | 223,744 | +29.52 s compressing the composite | 12.5 ms |
| Groth16 | — | **not measurable here** | — |

† the composite verify number is still the previous image's; Task 7 owns
re-measuring it.

**Groth16 was not measured, and that is a limitation of this machine, not an
omission.** risc0 3.0.6's STARK-to-SNARK step shells out to a Docker image
(x86-64), Docker is not installed here, and
`compress(&ProverOpts::groth16(), …)` fails with `Please install docker first.`
after 41.56 s. Every Groth16 claim anywhere in this repository is therefore
unmeasured. What that costs: Groth16 is the ~200-byte receipt an on-chain
verifier would need, and nothing here knows what it costs to produce.

The daemon keeps shipping **composite**, and `release.json` does not pin a kind:

- composite is what a two-minute prove already produces; succinct adds 24 % to
  the wall time for a 2.4× smaller artifact, which is a trade worth making when
  something is paying to store or ship receipts and pointless while nothing is;
- the verifier accepts either, so switching later is a daemon change and not a
  manifest or verifier change;
- the one thing that *would* force the decision — an on-chain verifier, which
  needs Groth16 — cannot be evaluated on this machine at all.

### Fixtures

`prover/verify/tests/fixtures/` holds four real receipts so that `cargo test`
costs seconds instead of eight minutes of proving. `tests/fixtures/README.md` has
the regeneration commands, including how the wrong-image receipt was produced
without a second image ever existing inside this repository.

---

## Measured on this machine

Three timed runs per measurement after one discarded warmup, `--release`, dev
mode off, in-process prover (backend `local`, enforced). Reproduce with
`cargo run -rp host -- --bench`.

### Task 4 — the policy guest

Guest image id `75751480a7e7d6b329de6614fee99e8d2cf9a793c32e9c1e3de057f8196b0ee1`,
policy id `0x1f74ba4f2353012cd26f5d3279625c3b45e927eeb341f0ee4b72124b056a7db2`,
rules digest `0x9f85ba59fd1429f10c373efc56d69aefa255a01a08df3ab6bd8e1ccecd3f93ea`.
The policy id and the rules digest are unchanged from Task 4's first image —
`policy/v1/` was not touched — and the ImageID moved because the guest code did.
Two fixture requests: `allow-001` (a haiku prompt, 45 characters) and `deny-001`
(a phishing prompt, 71 characters).

> **Two images are quoted in this section, and the difference is stated rather
> than smoothed over.** Task 4's first fix round changed the guest — a bounded
> `proofNonce`, fixed-string refusals, the rules digest forced into `.rodata` —
> so the ImageID above is **not** the one the prove, receipt and verify numbers
> were taken on. Those were measured at image
> `4a05b4e9c27a79faa0a6989129d2436c910b02cc6222bdde0f8d2ba103ec8ace`, which
> differs from this one by **+8,353 user cycles** on ALLOW (+0.76%) at the same
> segment count and the same max po2, and they are **not re-measured here**: a
> full `--bench` is ~30 minutes, and the honest expectation is that the change is
> invisible underneath the ±20% run-to-run prove noise documented below. Task 7's
> fixture-corpus bench owns the re-measurement. Executor time and cycle counts —
> the reproducible quantities — *were* re-measured at the current image and are
> the ones in the tables.

Medians:

| Case | Executor only (this image) | Composite prove † | Receipt (bincode) † | Verify † |
|---|---|---|---|---|
| ALLOW | 57.0 ms | 137.69 s | 525.1 KB (537,736 B) | 29.4 ms |
| DENY | 56.3 ms | 126.14 s | 525.1 KB (537,734 B) | 30.1 ms |

† measured at image `4a05b4e9…`, +8,353 user cycles below this one. See the note
above.

Spread (min / median / max):

| Case | Executor ms (this image) | Prove ms † | Verify ms † |
|---|---|---|---|
| ALLOW | 56.3 / 57.0 / 57.4 | 127,275.0 / 137,693.6 / 166,816.3 | 29.4 / 29.4 / 30.3 |
| DENY | 56.2 / 56.3 / 56.3 | 122,718.5 / 126,139.9 / 126,205.3 | 29.0 / 30.1 / 30.2 |

The executor rows are one `CTN_BENCH_PROVE=0` run. A second run of the same
binary gave 56.1 / 56.3 / 57.8 (ALLOW) and 56.3 / 56.3 / 56.3 (DENY) — a 1.2%
median drift on ALLOW, well inside the ±6% band Task 1 recorded. Both runs
reported byte-identical cycle counts.

| Case | Segments | Max po2 | User cyc | Total cyc † | Paging cyc † | Reserved cyc † |
|---|---|---|---|---|---|---|
| ALLOW | 2 | 20 | 1,109,291 | 1,310,720 | 125,995 | 83,787 |
| DENY | 2 | 20 | 1,090,549 | 1,310,720 | 127,296 | 101,203 |

`total_cycles`, `paging_cycles` and `reserved_cycles` only come out of a prove
run, so they are the `4a05b4e9…` numbers. Segments and max po2 are identical
across the two images, and 8,353 extra user cycles cannot move a 2^20 + 2^18
padding total, but that is an argument rather than a measurement and is labelled
as one.

Five things in there are worth stating plainly, because three of them are worse
than Task 1 predicted.

**The executor gate costs ~56 ms, not ~20 ms.** The spike's floor was 16.9–18.3 ms
and this file told Phase 2b to budget ~20 ms per execution regardless of prompt
size. That was a floor, and the policy guest sits about 38 ms above it. This is
the number `tee-sim` will pay synchronously on every request once Phase 2b wires
`/execute` in; it does not go away by shrinking the prompt, because it is
dominated by the ruleset, not the request. (`POST /execute` now exists and costs
the same — see the Task 5 section below — but nothing calls it yet; the
`tee-sim` wiring is Phase 2b.)

**Proving is a little over two minutes per request, and the timing is noisy at
the ±20% level.** Within this run, ALLOW ranged 127.3–166.8 s. Between runs it is
worse: an earlier full bench of an image differing by 228 user cycles (the
trailing-bytes check, added after it) gave medians of 164.88 s ALLOW and
159.42 s DENY on the same otherwise-idle laptop — 20% and 26% above the table
above. Both runs had the enforced local backend, dev mode off, and nothing else
running; the difference is thermal or scheduling and is not characterised here.
Do not quote 138 s as a constant. Quote **"two to three minutes on an idle M1
Pro, CPU-only"**, and treat cycle counts — which were identical across repeated
runs of a given image — as the reproducible quantity.

**Task 1's linear-in-padded-rows extrapolation under-predicted by ~10–30%.** It
put po2 20 at ~105 s, from a rate of 0.087–0.096 ms per padded row. The rate here
is 137.69 s / 1,310,720 rows = **0.105 ms per row** (0.126 in the slower run). The
rule is the right shape — cost tracks padded rows — but its constant came from a
one-segment session and this is a two-segment one, and continuations are not
free. Task 7 should re-derive the constant from these rows rather than the
spike's, and should state it as a range.

**`total_cycles` is a sum of segment po2s, not one of them.** 1,310,720 =
2^20 + 2^18, which is what two segments of unequal size look like. The Task 1
planning rule — `po2 ≥ ceil(log2(user + paging))` — reads as "one segment of that
po2" and would have predicted 2^21 = 2,097,152 padded rows here; the real total is
1.31M, i.e. **cheaper** than that rule says, because segmentation packs the tail
into a smaller block. Read the rule as an upper bound on padded rows once a
session spans segments.

The receipt doubled with the segment count (525 KB against the spike's ~250 KB at
one segment) and verification roughly doubled with it (~30 ms against ~13 ms).
Both are per-receipt costs and both are still small next to proving.

Where the user cycles go, measured in-guest with `env::cycle_count()` on the
ALLOW case with `emitScores` off (1,089,150 cycles between the first and last
reading, against 1,100,938 for the whole session at image `4a05b4e9…`; the
breakdown has not been re-instrumented at the current image, which is 8,353
cycles heavier in total):

| Phase | Cycles |
|---|---|
| `evaluate_prepared` | 661,275 |
| postcard-decoding the embedded ruleset | 358,084 |
| building and committing the journal | 41,148 |
| the SHA-256 commitment | 19,434 |
| parsing the canonical request | 5,728 |
| decoding the input frame | 3,481 |

Nothing was optimized beyond the two hoists described above. If a later task
needs a po2 back, those first two rows are the entire conversation — and note
that the second one is *already* the cheap version: normalizing the needles
in-guest instead of at build time costs 2,264,222 cycles.

### Task 5 — the daemon (two runs, current image)

Same machine (Apple M1 Pro, 10 cores, 32 GB, macOS 26.0.1), `--release`, dev mode
off, backend `local`, **image `75751480…`** — the image the tables above describe
with a `†` on their prove column. Produced by the gated end-to-end test, which
enqueues one `POST /prove` for the `allow-001` fixture, fires one `POST /execute`
while it is running, then verifies the returned receipt against the baked
ImageID:

```bash
CTN_PROVE_TEST=1 cargo test -rp host --test api -- --ignored --nocapture
```

| Run | Composite prove | Receipt (bincode) | `/execute` during the prove | Machine state |
|---|---|---|---|---|
| 1 | 134.70 s | 525.3 KB | 66 ms | a release build + the differential suite were running |
| 2 | 122.58 s | 525.3 KB | 90 ms | otherwise idle |

**One run each, and they disagree by 10%.** That is the same ±20% prove noise the
Task 4 section documents, and run 1 was not on an idle machine — it is reported
rather than dropped because dropping the inconvenient run is how a ±20% number
becomes a ±0% claim. Expect ±20% and quote **"two to three minutes on an idle
M1 Pro, CPU-only"**, not either number.

What this **does** retire from the `†` list: prove wall time and receipt size are
now measured at the current image, and they land inside the previous image's band
(126.14–137.69 s prove, 525.1 KB receipt). What it does **not** retire: verify
wall time, `total_cycles`, `paging_cycles` and `reserved_cycles` still come only
from `--bench`, are still the `4a05b4e9…` image's, and are still marked `†`. Task
7 owns those, and owns re-measuring all of it properly rather than one run at a
time.

**`/execute` is not starved by a prove in flight, on this one probe.** 66 ms and
90 ms against a ~57 ms idle median — the prove worker is a separate OS thread and
the tokio runtime keeps its own. Two samples of one concurrent request is not a
load characterisation; the test's assertion is the weak one it can defend
(under 2 s), and the numbers above are the observation.

### Task 1 — the spike guest (a different, much smaller program)

Kept because the two together are the only honest way to read the policy-guest
numbers: the spike hashed its input and nothing else, so its executor floor and
its po2 are what the zkVM costs *before* any policy work. The `--bench` harness
no longer produces these — the spike guest is gone — so they cannot be
re-measured without checking out the Task 1 commit.

Medians:

| Input | Executor only | Composite prove | Receipt (bincode) | Verify |
|---|---|---|---|---|
| 256 B | 16.9 ms | 5.70 s | 216.1 KB (221,274 B) | 12.2 ms |
| 4096 B | 18.3 ms | 50.49 s | 262.0 KB (268,250 B) | 14.9 ms |

Spread (min / median / max), because the median alone hid a cold-start artifact
in the first version of this file:

| Input | Executor ms | Prove ms | Verify ms |
|---|---|---|---|
| 256 B | 15.5 / 16.9 / 22.4 | 5606.9 / 5701.9 / 5807.4 | 12.2 / 12.2 / 12.3 |
| 4096 B | 18.1 / 18.3 / 18.5 | 49070.7 / 50490.1 / 50662.9 | 14.8 / 14.9 / 15.0 |

Verify runs immediately after proving on a receipt still in memory, so it is a
cache-hot number. A verifier reading a receipt off disk would pay more.

The table above is one run. A second full run of the same binary gave medians of
17.3 / 18.9 ms (executor), 5.78 / 52.30 s (prove) and 12.9 / 14.9 ms (verify).
Per-measurement drift between the two runs:

| | 256 B | 4096 B |
|---|---|---|
| Executor | +2.4% | +3.3% |
| Prove | +1.4% | +3.6% |
| Verify | **+5.7%** | 0.0% |

So the honest bound is **up to ~5.7% between runs** — verify at 256 B, the
smallest and therefore proportionally noisiest measurement — with ~3.6% on prove
at 4096 B. Treat everything here as **±6%** on an otherwise-idle laptop, not as
constants; between-run drift exceeds the within-run spread at 4096 B. Cycle
counts, po2 and receipt sizes were byte-identical across both runs, as they
should be.

Spike guest image id
`d094ec7bbac59857234c8c316573b591e5830ed9656fec4cf332440a0e19ff50` — it changes
whenever the guest or its dependency graph does, which is the point, and it did:
the policy guest's id is in the Task 4 table above.

| Input | Segments | po2 | User cyc | Total cyc | Paging cyc | Reserved cyc |
|---|---|---|---|---|---|---|
| 256 B | 1 | 16 | 24,927 | 65,536 | 24,870 | 15,739 |
| 4096 B | 1 | 19 | 265,498 | 524,288 | 26,854 | 231,936 |

Three things in those tables matter more than the headline numbers.

**Executor latency is a fixed floor of roughly 17–18 ms.** 16.9 ms at 256 B and
18.3 ms at 4096 B, across a 10.6× difference in user cycles. The 1.4 ms gap
between the medians is smaller than the run-to-run spread at 256 B, which alone
covers 15.5–22.4 ms — so the marginal cost of 240,000 extra user cycles is real
but sits below this sample's noise floor rather than being separable from it.
What the number is made of is fixed setup: ELF load, page-in, session start.
Phase 2b should budget ~20 ms per execution regardless of prompt size, and should
not expect to recover it by shrinking the input.

An earlier version of this file reported 23 ms at 256 B and called the resulting
*inversion* — the small input measuring slower than the large one — evidence for
that same conclusion. It was not evidence; it was the harness. Sizes ran in a
fixed order with no warmup, so first-call cost landed entirely on the 256 B row.
The conclusion survived the fix, but it had been argued from an artifact, which
is why `--bench` now warms up and prints spread.

**Proving cost is set by paging as much as by arithmetic.** `reserved_cycles` is
not overhead in the usual sense — risc0 documents it as "the number of cycles
needed for the proof system which includes padding up to the nearest power of 2"
(`session.rs`), and the arithmetic bears that out: `total_cycles` lands on exactly
2^po2 in both rows, and `reserved` is whatever it takes to get there. The real
work is **user + paging**, and reserved is the filler:

| Input | User + paging | Rounds up to | Reserved (the filler) |
|---|---|---|---|
| 256 B | 49,797 | 65,536 = 2^16 | 15,739 |
| 4096 B | 292,352 | 524,288 = 2^19 | 231,936 |

That gives a usable planning rule for Tasks 4 and 7:
**po2 ≥ ceil(log2(user_cycles + paging_cycles))**, and cost follows from po2.

It is a lower bound rather than an equality, and the two rows above are why: they
are consistent with `reserved` being *pure* padding, but they cannot prove it. If
the proof system also needs some fixed non-padding allocation inside `reserved`,
the 256 B row caps it at 15,739 cycles — so the rule can under-predict by one po2
for a guest landing within roughly 15k cycles below a boundary. Plan against the
next po2 up when a guest lands that close.

Two things fall out of it. Paging is half the real work at 256 B (24,870 against
24,927 user cycles), so the policy guest's memory access pattern will move its po2
as readily as its arithmetic will. And **po2 cannot be predicted from user cycles
alone** — an earlier version of this file claimed 24,927 and 65,535 user cycles
would both fit po2 16. They would not: 65,535 user cycles plus even this spike's
modest ~25,000 paging cycles is ~90,000, which rounds to po2 17.

Time then scales near-linearly with padded rows: 8× the rows cost 8.85× the time
(po2 16 → 19), roughly 0.087–0.096 ms per row. Extrapolating: **~105 s at po2 20,
~210 s at po2 21.** Expect the policy guest a po2 or two above this spike at equal
input size — affordable off the request path, nowhere near affordable on it.
(Task 4 measured it: see the policy-guest table above for what actually
happened.)

**Composite receipts are ~250 KB and grow with execution length.** That is a
storage and transport cost per receipt, not per policy. Compressing to Groth16
yields a constant-size receipt of a few hundred bytes at the cost of extra
proving time; neither the compression time nor the resulting size has been
measured here, and Task 6 should measure both before the release manifest
commits to a receipt format.

### What is not established

Everything above is one laptop, one toolchain, a handful of runs, and two fixture
prompts. Specifically **not** shown:

- **A stable prove time.** The two full benches of near-identical images differ by
  20–26% at the median, and the within-run ALLOW spread is 127–167 s. There is a
  central tendency of roughly two to three minutes and no evidence for anything
  tighter. The cause of the between-run drift was not investigated.
- **A full set of prove numbers for the current image.** Task 5 measured *prove
  wall time and receipt size* at image `75751480…` (two single runs, below), which
  retires the `†` on those two quantities only. Verify time, `total_cycles`,
  `paging_cycles` and `reserved_cycles` are still the previous image's — they come
  out of `--bench`, not out of the daemon, and Task 7 owns re-measuring them.
- **Anything about GPUs.** Proving here is CPU-only (next section). A risc0 that
  re-enables the Metal path invalidates every prove number on this page, by an
  unmeasured amount.
- **How receipt size scales.** Two data points at one segment (spike, ~250 KB)
  and two at two segments (policy guest, ~525 KB) are consistent with "roughly
  linear in segments" and do not establish it. Nothing here measured a
  three-segment session.
- **Anything about Groth16.** Task 6 measured succinct (223,744 bytes, +29.52 s
  from the composite, 12.5 ms to verify) but Groth16 proving needs Docker, which
  this machine does not have — see "Which receipt kind". Any Groth16 number in
  this repository is unmeasured.
- **Cost as a function of the prompt.** Both fixtures are one short user message.
  The executor cost is dominated by the ruleset, which is why the two agree to
  0.4% — but that is an argument from two similar inputs, not a curve. Task 7's
  fixture corpus is where the distribution comes from.
- **Cross-machine reproducibility of the image.** Two builds on one machine with
  one toolchain, as the section above says.
- **Concurrency, beyond one probe.** Task 5 measured a single `/execute` fired
  during a single in-flight prove (66 ms and 90 ms, two runs) — enough to show
  the executor is not starved, not enough to characterise the daemon under load.
  Nothing here measures several concurrent `/execute` calls, a full queue, or
  what a second prove would do; the prove worker is one thread partly because
  that is unmeasured.

### Proving is CPU-only

The 50 s figure is a **CPU** number. Nothing here is GPU-accelerated, despite the
Metal Toolchain being a hard build requirement and Metal kernels being compiled
into the binary. In risc0 3.0.6 those kernels are dead code:

- `risc0-circuit-rv32im-4.0.5/src/prove/mod.rs:46-54` — the Metal branch of
  `segment_prover()` is **commented out**; the `cfg_if` falls through to
  `hal::cpu::segment_prover()`.
- `risc0-circuit-recursion-4.0.5/src/prove/mod.rs:83-91` — same shape for
  `recursion_prover()`, falling through to `hal::cpu::recursion_prover(hashfn)`.
- `risc0-circuit-recursion-4.0.5/src/prove/hal/mod.rs:26` — `// pub mod metal;`,
  the module itself is commented out.

`risc0-zkp-3.0.5/src/hal/metal.rs` still exists and is still a live module, so the
low-level HAL is there; nothing in either circuit prover dispatches to it. The
kernels are built (`risc0-sys/build.rs:35` compiles them for any `macos`/`ios`
target, unconditionally and with no feature gate — which is why enabling `prove`
is what made the Metal Toolchain a hard requirement) and then never called.

This is also the actual explanation for something the previous version of this file
got right by accident. In-process and external-`r0vm` proving times matched to
within noise; that section attributed it to "both being GPU-enabled". They matched
because **both are CPU**. The right conclusion, the wrong route.

**What follows for the numbers:** a future risc0 that re-enables the Metal path
would change proving time, possibly substantially, and this benchmark would need
re-running. How much is unmeasured and not guessed at here. The one thing that can
be said is that the ~50 s at 4 KB is what ten M1 Pro CPU cores cost, and that it is
a ceiling a GPU path could only improve on.

Two silent defaults in `risc0-zkvm` are worth recording, because both would have
produced numbers describing something other than this machine.

`prove` is **not** a default feature. Without it, `default_prover` and
`default_executor` shell out to an `r0vm` subprocess over IPC. That cost roughly
10 ms per executor call on top of the ~17 ms in-process figure — for a
measurement whose whole purpose is a ~20 ms budget, the difference between a
usable number and a misleading one. (That comparison was taken with the
pre-warmup harness, so treat it as indicative rather than precise.)

`bonsai` **is** a default feature, and `default_prover` checks for
`BONSAI_API_URL` / `BONSAI_API_KEY` *before* it checks the local branch. With
those two variables set in the environment, proving would have silently gone to
remote hardware over a network — the same class of failure, with a worse outcome,
since the resulting timings would describe somebody else's machine. Two things
close it: `default-features = false` removes the branch at compile time, and
`--bench` refuses to run unless the backend reports `local`, mirroring how it
refuses to run under `RISC0_DEV_MODE`. `RISC0_EXECUTOR` is checked too, since the
`Executor` trait exposes no name to enforce against.

---

## Two deviations from the plan's assumed API, and why

**`env::read_frame` is unstable in 3.0.6.** The host side,
`ExecutorEnvBuilder::write_frame`, is stable; the guest side is marked
`#[stability::unstable]` and will not compile without opting the guest into the
`unstable` feature. Rather than put the guest's only input path behind an
unstable flag — Task 4 builds the policy guest on this exact path — the guest
reproduces `read_frame` on `env::read_slice`, which is stable. It is the same
two reads and the same wire format (little-endian `u32` length, then payload),
so it stays compatible with the stable host-side writer.

**`cargo clippy` broke the guest build.** risc0-build spawns a nested
`cargo build` for the guest and sanitises `CARGO*` and `RUSTUP_TOOLCHAIN` from
its environment, but not `RUSTC_WORKSPACE_WRAPPER` — which `cargo clippy` sets
to `clippy-driver`. The guest then gets compiled by clippy-driver against
`riscv32im-risc0-zkvm-elf`, which has no clippy-visible `std`, and the build
fails with ``can't find crate for `std` ``. `methods/build.rs` clears the two
wrapper variables before calling `embed_methods()`, which keeps the gate command
below working unmodified.

---

## sha2, not a precompile

The guest hashes the commitment with the ordinary `sha2` crate. risc0 ships
accelerated patches for the RustCrypto hashes (wired in via `[patch.crates-io]`,
pointing `sha2` at `risc0/RustCrypto-hashes`), which would cut the cycle count
for hash-heavy work.

They are deliberately not used yet. The guest has to hash exactly the bytes
`packages/protocol/src/crypto.ts` hashes, and the differential suite is the thing
that proves it does. Keeping one unpatched crate on both sides means a digest
disagreement is a real bug rather than a library difference. It is also not where
the cycles are: the commitment costs ~19k of ~1.09M user cycles, measured, so the
precompile is worth at most ~1.5% here. The two places worth looking are
`evaluate` (~660k) and decoding the embedded ruleset (~360k).

---

## Gates

```bash
cd prover
cargo fmt --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test

# `verify` is its own workspace (see below) and the three lines above do not
# reach it either
cd verify
cargo fmt --check
cargo clippy --all-targets -- -D warnings
cargo test
cd ..

# the guest is its own workspace and the lines above never reach it
cd methods/guest
cargo fmt --check
RUSTFLAGS='-C passes=lower-atomic -C panic=abort --cfg getrandom_backend="custom"' \
  cargo +risc0 clippy --target riscv32im-risc0-zkvm-elf -- -D warnings
```

The guest lint needs both halves of that incantation and neither is optional.
`cargo +risc0` because the stock `clippy-driver` has no `core`/`std` for
`riscv32im-risc0-zkvm-elf` (it fails on the first `no_std` dependency); the
`RUSTFLAGS` because `risc0-build` normally supplies them and without
`getrandom_backend="custom"` the `getrandom` build emits a `compile_error!`. The
values are copied from `risc0-build-3.0.6/src/lib.rs:455-503`; `-Ttext` and the
link args are omitted because `clippy` does not link.

One test proves, and it is `#[ignore]`d twice over — by the attribute and by an
env var — because it is minutes:

```bash
CTN_PROVE_TEST=1 cargo test -rp host --test api -- --ignored --nocapture
```

`cargo test` is otherwise executor-only and stays fast. `host/tests/api.rs`
spawns the real binary and drives it over a socket: `/health` against the baked
identities, `/execute` for ALLOW and DENY (determinism on identical input,
scores present only when asked), eleven malformed-request shapes against both
POST endpoints with a marker planted in every caller-controlled field, a body
over the 10 MiB cap, the job lifecycle end to end in dev mode, the dev-mode
startup refusal (the process must exit non-zero *before* it binds), and a
log-capture assertion that reads the daemon's stdout and stderr and finds
neither the prompt, nor its base64 framing, nor the caller's proof nonce.
`host/tests/guest_io.rs` runs the real image seventeen ways — ALLOW and DENY journals against independently
recomputed commitments, the allowlist key set, canonical-JSON ordering,
`emitScores: false` writing nothing, a rejected protocol version, a rejected
non-canonical request, a rejected padded frame, determinism across two runs, the
`proofNonce` bound in both directions (every nonce this repository mints is
accepted; six out-of-bound shapes are refused with the taxonomy constant), and
the leak probes, which plant a marker in six positions `serde_json` used to quote
back and assert it reaches neither the caller nor the process's stderr, plus the
`CTN_UNSAFE_GUEST_DIAGNOSTICS` predicate (`=0` must mean off, with `=1` as the
positive control). A full `--bench`, at these po2s, is a **~30 minute** command;
use `CTN_BENCH_PROVE=0` while iterating.

### Three workspaces, on purpose

`prover/`, `prover/verify/` and `prover/methods/guest/` are three separate cargo
workspaces, so each of the three gate blocks above is necessary. The guest's
separation is inherent — a different target triple, a different toolchain. The
verifier's is a consequence of cargo unifying features across a workspace build:

```console
$ # with verify added as a member, for one command:
$ cargo tree --workspace -e features -f '{p} {f}' | grep -o 'risc0-zkvm v3.0.6.*' | sort -u
risc0-zkvm v3.0.6 client,disable-dev-mode,prove,std
```

One resolution for the whole workspace, so `host` would be compiled with
`disable-dev-mode` too — and with that feature, risc0 *panics* when it sees
`RISC0_DEV_MODE` set (`risc0-zkvm-3.0.6/src/lib.rs:211-218`) rather than letting
the daemon exit with the one-line refusal Task 5 specified. The two crates
genuinely disagree about whether dev mode may exist, and that disagreement is the
point of the verifier; two workspaces is what it costs.

`prover/target/`, `prover/verify/target/` and `prover/methods/guest/target/` (all
matched by `target/`) are the only gitignored paths here. All three `Cargo.lock`
files are committed on purpose: the guest image id depends on the exact
dependency graph.

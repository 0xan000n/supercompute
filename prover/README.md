# prover

The real RISC Zero prover for Safety Policy v1. **Phase 2a is complete**: the
guest image *is* Safety Policy v1 (the ruleset is compiled in, the request
commitment is recomputed inside the zkVM, and the journal it commits is the
verifier's allowlist and nothing else); `host --serve` puts it behind
`127.0.0.1:4500` with an executor fast path and a single-worker proving queue;
and `prover-verify` checks a receipt against `release.json` with no network and
no trust in whoever produced it. **Nothing in `services/` calls any of this** —
wiring the daemon into `tee-sim` is Phase 2b, and until that happens a verified
receipt says a proof exists, not that anything was gated on it.

Phase 1 modelled the cost of proving (`CTN_SIMULATED_PROVING_MS`, default
2400 ms) and labelled it as modelled. Everything here is measured instead — see
"Measured on this machine" below, which carries the policy-guest numbers over the
whole 125-fixture corpus and keeps the Task 1 spike numbers (a guest that only
hashed its input) alongside them as the floor. They are different guests and the
difference is large.

Read in this order if you are here to check the claims rather than to work on
them: "Verifying a receipt offline" is the promise anyone can exercise on their
own machine, "Measured on this machine" is every number, and "What is not
established" is the list of things none of it shows.

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
| `rzup` (installed CLI) | 0.5.0 — the `rzup` *crate* in `host`'s build graph is 0.5.2; two different objects |
| `cargo-risczero` | 3.0.6 |
| `r0vm` | 3.0.6 |
| risc0 Rust toolchain (guest) | 1.97.0 — `rustc 1.97.0-dev (e638c6cfe 2026-07-15)` |
| risc0 C++ toolchain | 2024.1.5 |
| `risc0-zkvm` / `risc0-build` crates | 3.0.6 |
| `unicode-normalization` / `unicode-properties` | 0.1.25 / 0.1.4 |

`release.json` carries these as data rather than prose — `cargo run -rp host --
--emit-release` reads them out of the build that produced the image, so they
cannot drift from this table without the table being visibly wrong.

The two Unicode versions come from **`prover/methods/guest/Cargo.lock`**, not
from `prover/Cargo.lock`: the guest is its own cargo workspace with its own
committed lock, and that lock is what the guest compiler resolves against, so it
is the one that governs what is compiled into the image. If the prover
workspace's lock ever pins a different version of either crate, `host/build.rs`
panics and names both files — the ImageID is the real pin, so drift between the
locks changes nothing that was proved, but two answers to one question is not
something anyone should discover while reading a `release.json`.
`host/tests/lock_pins.rs` tests those rules directly, against the same code the
build script runs.

`rust-toolchain.toml` **pins the host channel to `1.97.1`**, as of Task 7:

```toml
[toolchain]
channel = "1.97.1"                                # was "stable" through Task 6
components = ["rustfmt", "rust-src", "clippy"]    # clippy used to come from
profile = "minimal"                               # the default-profile stable install
```

What the pin does and does not do is worth being exact about, because it is easy
to read as an ImageID pin and it is not one. The toolchain that determines the
ImageID is the **guest** one, and that was already pinned outside cargo:
`risc0-build` looks up rzup's default Rust toolchain and forces it into the
nested guest build through `RUSTC`, after stripping `RUSTUP_TOOLCHAIN` from the
environment (`risc0-build-3.0.6/src/lib.rs:355-383, 436`). The host channel
cannot reach the image. What the pin buys is host-side reproducibility: the
Unicode tables behind `str::to_lowercase` in the native differential runs (the
third table source §2c of `VALIDATION.md` names), and a `hostRustc` field in
`release.json` that a floating `stable` could have changed under.

The pin was **verified not to move the image**, which is the check that makes the
paragraph above a measurement rather than an argument. `rustup toolchain install
1.97.1`, then `cargo clean` in `prover/`, `rm -rf methods/guest/target`, and a
cold `cargo build --release -p host` (3m27s): the guest ELF came back
byte-identical to the hash Task 4 recorded and `--emit-release` reported an
unchanged ImageID, with `builtAt` the only field that differed. On this machine
`stable` *was* 1.97.1 already, so the pin renamed the toolchain rather than
changing the compiler; the reproduction shows the rename cost nothing, not that a
different compiler would have.

That measurement was taken against the pre-remap identity
(`75751480a7e7…`/ELF `e5fd1e0d47a2…`), which no longer exists: the fix in
"Reproducibility of the image" below moved the image to
`ddb7dc544e14…`/ELF `d7ad05b17aad…` deliberately. What carries over is the
finding — the *host* channel does not reach the image — and it carries over
because the mechanism did not change: `RUSTC` for the guest is still rzup's.

Machine: Apple M1 Pro, 10 cores, 32 GB, macOS 26.0.1. **Proving here is CPU-only.**
Despite what the toolchain's shape suggests, risc0 3.0.6 does not use the GPU on
Apple Silicon — see "Proving is CPU-only" below.

---

## Layout

```
prover/
  Cargo.toml            workspace: host + methods + policy-core + release-manifest
                        (verify is EXCLUDED — its own workspace, see below)
  rust-toolchain.toml   pinned 1.97.1, with rustfmt, rust-src and clippy
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
    build_lock.rs       Cargo.lock reading, include!d by build.rs and tested by
                        tests/lock_pins.rs
    src/lib.rs          execute_policy — run the image in the executor
    src/main.rs         --bench, --execute-stdin, --serve, --emit-release
    src/release.rs      builds release.json
    tests/guest_io.rs   executor round-trip tests against the real image
  release-manifest/     the shape of release.json — a leaf crate, shared by the
                        host that writes it and the verifier that reads it
  verify/               prover-verify: the offline verifier (own workspace)
    src/lib.rs            the checks
    src/main.rs           the CLI
    tests/fixtures/       five real receipts + how to regenerate them
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
`scripts/differential-test.ts` feeds eighteen hostile manifests — combining marks
in keys, two keys that NFC-collide, the U+FFFD / U+D7FF / U+E000 boundaries
against supplementary characters, `MAX_SAFE_INTEGER`, 2^53, 2^53+1, a `u64`, a
fraction — through **both** canonicalizers and compares. A one-sided refusal by
Rust is fail-closed and allowed but has to be declared in the probe table; a
one-sided refusal by *TypeScript* is a failure, because that is the direction
where the guest bakes an identity no verifier can reproduce.

The suite found one such case on its first run: `serde_json` parses `-0` as the
float `-0.0` and refuses it, while `canonicalJson` emits `0`. **That instance is
the visible member of a class**, and the class is what the probe table now
declares. The Rust rule is a property of `serde_json`'s tokenizer rather than of
the value: any JSON number literal that makes it choose `f64` over `i64` is
refused, however integral the value — `1.0`, `1e2`, `0e0`, `-0`, all of which JS
parses to ordinary safe integers. Four probes cover the class. The direction is
the safe one (the manifest fails to build; no identity is derived), and what it
costs is a confusing build failure for someone who writes `1.0` where they meant
`1`. Today's manifest is ASCII integers, so nobody has.

### Reproducibility of the image

**Same path, same bytes** was true from Task 4 on. **A different path produced a
different image**, and that was fatal to the claim this directory is built
around, because every clean clone lands at a different path. A black-box test
found it: same source, same toolchain, one machine, three checkouts, three
ImageIDs — `75751480…` at the original path, `9a6117a4…` in a git worktree,
`9a6399b3…` in a copy under `/private/tmp`. No freshly-built daemon's receipt
verified against the committed `release.json`.

Two mechanisms, both of which had to be neutralised:

* **Absolute source paths in the image.** A panic location is `file!()`, and
  `file!()` is absolute for any crate outside the compiling package's own
  directory. `strings` on the old ELF found
  `…/prover/policy-core/src/input.rs` and eighteen
  `$CARGO_HOME/registry/src/…` paths.
* **The crate disambiguator.** Cargo derives `-C metadata` — which seeds
  rustc's `StableCrateId` and therefore every mangled symbol in the binary —
  from the package id, and a *path* package's id contains its absolute
  directory. This is the half that is easy to miss: after remapping the source
  paths the ELF still differed, in the symbol hashes of `policy_core` and
  `policy_guest` and nothing else (the crates.io dependencies already matched
  across checkouts). Guest symbol names are in the measured image.

`prover/methods/build.rs` fixes both, in committed build config rather than in
an environment variable a reader has to be told about. It generates a
`RUSTC_WRAPPER` shim that appends `--remap-path-prefix <checkout>=/ctn
--remap-path-prefix <CARGO_HOME>=/cargo` to every guest `rustc` invocation and
rewrites `-C metadata` to `ctn-<crate>-<target>` for the two path packages. A
wrapper rather than `RUSTFLAGS` because `risc0-build` sets
`CARGO_ENCODED_RUSTFLAGS` on the nested guest build and strips every `CARGO*`
variable from its environment, so `RUSTFLAGS` and `config.toml` `rustflags`
never arrive; cargo's own `trim-paths` would be the clean answer but it is not
stabilised in cargo 1.97.1, and risc0's answer is a Docker build, which would
make Docker a dependency of verifying. The build **fails** if either prefix
survives into the measured ELF — `build.rs` scans the bytes risc0-build hands
back, so this is enforced, not remembered.

The acceptance test, run after the fix:

| build | guest ELF SHA-256 | ImageID |
|---|---|---|
| `/Users/ankit/code/supercompute/compute-trust-network` | `d7ad05b17aad9f245fb4eb503fa5708ab524c4a4e9745bfb438d143bc3a79b84` | `ddb7dc54…` |
| the same tree rsynced to `/private/tmp/claude-501/…/ctn-copy` | `d7ad05b17aad9f245fb4eb503fa5708ab524c4a4e9745bfb438d143bc3a79b84` | `ddb7dc54…` |
| the first path again, `target/riscv-guest/` deleted | `d7ad05b17aad9f245fb4eb503fa5708ab524c4a4e9745bfb438d143bc3a79b84` | `ddb7dc54…` |

(The hash is of `target/riscv-guest/methods/policy_guest/riscv32im-risc0-zkvm-elf/release/policy_guest`,
the user ELF. The combined user+kernel `policy_guest.bin` matched too, at
`168c0cf6a13e88049f1f50b4df240937a841e53a923d1c038ebb7120c1eb9283`.)

`strings` over the new ELF finds no path from this checkout and none from this
machine's `CARGO_HOME`. Three absolute paths remain and none of them is ours:
`/Users/administrator/.cargo/…/rustc-demangle-0.1.27/…` in the user ELF and
`/home/remi/.cargo/…/no_std_strings-0.1.3/…` in the kernel half, both baked into
published risc0 crates by whoever built them, and therefore the same constants
on every machine.

**What is still untested is cross-machine.** Everything above is one M1 Pro with
one rzup toolchain. `release.json` pins the toolchain versions, which is what
makes that check possible for someone else to run; nobody here has run it. A
second machine could still differ — through a different rzup Rust build, a
different C++ toolchain, or a dependency resolving differently — and the honest
statement of the property is *path-independent on a given machine and
toolchain*, not *universally reproducible*.

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
(Both are pre-remap identities; the current image is `ddb7dc544e14…`. The
remap fixed *where* the tree sits, not *what is in it*.)
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

Measured in-guest with `env::cycle_count()`, ALLOW fixture, this machine — and
therefore **not at the current image**: reading a cycle counter inside the guest
requires a guest with the readings in it, which is a different image. These come
from the instrumented `4a05b4e9…` build; see ["Where the user cycles
go"](#where-the-user-cycles-go) for the caveat in full. Preparing the needles
inside the zkVM costs **2,264,222 cycles** (plus 202,190 to parse `rules.json`);
postcard-decoding the prepared form costs **358,084**. The
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
cargo run -rp host -- --bench --fixtures            # the gate cost over all 125 fixtures (~30 s)
cargo run -rp host -- --bench           # + three real proofs: ALLOW, DENY, adversarial (about 24 min)
cargo run -rp host -- --bench --keep-receipts /tmp/r # …and write the proved receipts out
CTN_BENCH_PROVE=0 cargo run -rp host -- --bench     # the three cases, executor only
cargo run -rp host -- --execute-stdin   # newline-JSON executor service
cargo run -rp host -- --emit-release --out release.json   # regenerate the manifest
```

`--bench --fixtures` is the one to run first: it is the only mode that finishes
in under a minute, it runs the *whole* labelled corpus rather than three chosen
prompts, and it fails if the guest disagrees with any corpus label — so it is a
correctness check as much as a benchmark. `--bench` on its own is three fixture
prompts proved four times each (one warmup, three timed) and took **about 24
minutes** measured end to end.
The receipts `--keep-receipts` writes are ordinary receipts: hand one to
`prover-verify` and it checks out.

### The daemon (`--serve`)

`--serve [--port N] [--dev]`. It binds `127.0.0.1` and only `127.0.0.1` — the
bind address is not configurable, `--port` is (0 picks an ephemeral one, which is
what the tests use). Run it under `--release`: a debug executor run is much
slower than the 57 ms below.

| Endpoint | Body | Answer |
|---|---|---|
| `POST /execute` | `{protocolVersion, canonicalRequestBytesB64, requestNonceHex, proofNonce, emitScores}` — every field required, see below | `200 {journal:{…5 allowlist fields…}, privateScores:{…}\|null, execWallMs}` |
| `POST /prove` | the same four, and **no** `emitScores` | `202 {jobId}` |
| `GET /jobs/:id` | — | `{status:"QUEUED"\|"PROVING"\|"GENERATED"\|"FAILED", receiptB64?, proveWallMs?, error?, devMode}` |
| `GET /health` | — | `{imageIdHex, policyId, rulesDigest, risc0Version, devMode}` |

#### The POST body, field by field

There are no optional fields and no defaults. Both bodies are
`deny_unknown_fields` **and** every listed field is non-`Option`, so a body that
is missing one or carries one too many is a 400 with
`request body does not match the expected schema` — a fixed string that, by
design, does not name the field. That is the right trade for a wire that must
not echo caller bytes, and it is why the table has a Required column: the error
cannot tell you, so the document has to.

| field | type | `/execute` | `/prove` | what it is |
|---|---|---|---|---|
| `protocolVersion` | number | **required** | **required** | exactly `1`; anything else is rejected rather than interpreted |
| `canonicalRequestBytesB64` | string | **required** | **required** | standard base64 (with padding) of the canonical request bytes — see below |
| `requestNonceHex` | string | **required** | **required** | exactly 32 bytes as 64 hex digits; an optional `0x` prefix is accepted (`parse_nonce`), nothing else is |
| `proofNonce` | string | **required** | **required** | caller's label, echoed into the public journal; `^(0x)?[0-9a-f]{1,64}$` and nothing else |
| `emitScores` | boolean | **required** | **forbidden** | `true` returns the private category scores; `false` returns `privateScores: null`. Sending it to `/prove` is a 400: the prove path never captures scores, so accepting the field would imply an option that does not exist. |

#### The canonical request

`canonicalRequestBytesB64` decodes to the *canonical* form of the request, which
is a narrower thing than "the JSON the caller sent". The guest re-derives the
commitment from these exact bytes, so a byte that differs is a different
commitment, and there is exactly one admissible spelling:

```json
{"max_tokens":1024,"messages":[{"content":"Write a haiku about the first snow of winter.","role":"user"}],"model":"ctn/demo-model-a","temperature_millis":1000}
```

* **Four keys, all required, no others.** `max_tokens`, `messages`, `model`,
  `temperature_millis` — and each message object is exactly `content` + `role`.
  `CanonicalRequestV1` and `CanonicalMessageV1` are `deny_unknown_fields`, so an
  extra key is a refusal, not a warning ("What the guest commits" explains why
  the guest refuses rather than opines).
* **`temperature_millis`, never `temperature`.** Integer millis: `1000` is
  temperature 1.0. There are no floats anywhere in the canonical form — a float
  has no single spelling, and the commitment is over bytes. The gateway's
  float-valued `temperature` is an *input* to canonicalization
  (`packages/protocol/src/canonical.ts` folds it, and defaults it to `1000`),
  never a field of the canonical document. `max_tokens` and `temperature_millis`
  must be JSON integers; `serde_json` parses `1.0` as a float and the guest
  refuses it, however integral the value.
* **JCS key order.** Keys sorted by UTF-16 code unit, at every level — which is
  why `max_tokens` precedes `messages` precedes `model`, and `content` precedes
  `role`. RFC 8785, as implemented by `packages/protocol/src/canonical.ts`.
* **No whitespace** between tokens, and **raw UTF-8 in string values, not
  escapes**: `é` is two bytes, not `\u00e9`. Only the escapes JSON requires
  (`"`, `\`, and the C0 controls) appear. Text is NFC-normalized before it is
  serialized. In Python this is `json.dumps(..., ensure_ascii=False,
  separators=(",", ":"), sort_keys=True)`; in Rust it is what
  `serde_json::to_string` already does over a struct whose fields are declared
  in sorted order.
* **`role` is one of `system`, `user`, `assistant`**, and `messages` must be
  non-empty.

The commitment the journal carries is then

```
requestCommitment = "0x" + hex(SHA256("CTN_REQUEST_V1" ‖ canonicalRequestBytes ‖ requestNonce32))
```

— computed **in the guest**, from the bytes you sent and the nonce you sent, and
never supplied by the host. `policy_core::request_commitment` is the definition;
`packages/protocol/src/crypto.ts` is the TypeScript side of the same three
concatenations. A verifier reproduces it the same way, which is what
`prover-verify --canonical-request` does.

`prover/verify/tests/fixtures/generate.py:38-98` is a worked example of the whole
path — a template carrying the four keys in JCS order, the prompt through
`json.dumps(..., ensure_ascii=False)`, then base64 and POST. The fixture corpus
under `policy/v1/fixtures/` carries its `request` objects with the same four
keys and the same `temperature_millis`; it is *not* canonical bytes, because the
files are pretty-printed for review and the key order in a file is not
significant.

- `receiptB64` is base64 of the **bincode**-serialized risc0 receipt — the same
  codec `--bench` measures and the one `release.json` pins as
  `receiptCodec: "bincode-v1"`.
- Every refusal is `{"error": "<one of a fixed set of strings>"}` with status
  400 (malformed request, including a body over the 10 MiB cap or the wrong
  content type), 404 (`no such job`, `no such endpoint`), 405 (`method not
  allowed for this endpoint` — axum's own 405 is an empty body, so the router
  installs a `method_not_allowed_fallback` to keep the shape uniform), 503
  (`prove queue is full`) or 500 (the daemon's own fault). **No reason string ever contains a byte
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
- The two malformed-body reasons split on *why* serde stopped, not on how broken
  the body looks, and one case reads oddly enough to write down: an unterminated
  **array** (`[1,2`) answers `request body does not match the expected schema`,
  not `request body is not valid JSON`, because the leading `[` already rules out
  the struct and serde reports the type error before it ever reaches the
  truncation. An unterminated **object** (`{"protocolVersion":1`) does answer
  `not valid JSON`. Both are 400 with a fixed reason and neither leaks a byte, so
  this is a labelling curiosity rather than a defect — but a caller debugging
  against the first message would look in the wrong place.
- Startup **refuses a non-local prover backend and a non-local `RISC0_EXECUTOR`**,
  because the frame either would ship contains the plaintext prompt. Worth
  knowing how that refusal looks in the one case a reader is most likely to try:
  `RISC0_PROVER=bonsai host --serve` does not print the daemon's one-line reason.
  It **panics inside risc0** — `bonsai` is compiled out (`default-features =
  false`), so `default_prover` hits `not implemented: Unsupported prover: bonsai`
  at `risc0-zkvm-3.0.6/src/host/client/prove/mod.rs:193` before the daemon's
  check ever runs, and what a user sees is a panic. Fail-closed, and ugly:
  the prompt does not leave the machine, but the message does not explain
  itself. Left as it is because the alternative is re-implementing risc0's
  backend selection to produce a nicer error for a variable nobody here should
  set.

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

- **`--bench` refuses to run in dev mode — on the paths that prove.** It checks
  `ProverOpts::composite().dev_mode()` — the options actually being proved with,
  not a global — and exits with an error rather than printing fast, meaningless
  numbers. The refusal is deliberately scoped: `--bench --fixtures` and
  `CTN_BENCH_PROVE=0` still run under `RISC0_DEV_MODE`, because neither of them
  proves anything, and dev mode does not fake *execution*. A plain `--bench`,
  which does prove, refuses (`main.rs:684`, guarded by `do_prove`). So the rule
  is not "the bench binary will not start"; it is "no timing that claims to be a
  proof was taken from a stub".
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

Build it, then run it from the repository root, where the defaults line up:
`--release` defaults to `prover/release.json`, and the policy directory defaults
to `policy/v1` *relative to the manifest*, not to the working directory.

```console
$ cd prover/verify && cargo build --release && cd ../..
$ ./prover/verify/target/release/prover-verify \
    --receipt prover/verify/tests/fixtures/allow-real.receipt.bin
prover-verify
  release manifest: prover/release.json
  receipt:          prover/verify/tests/fixtures/allow-real.receipt.bin (537794 bytes)

[ ok ] manifest                   pins imageId ddb7dc544e1425640ad3af8e7b3b48afa21499a0b371ce4a59fdb4d8594d5331, journalVersion 1, risc0 3.0.6, built 2026-08-17T03:31:06Z
[ ok ] receipt-codec              bincode-v1
[ ok ] receipt-decodes            537794 bytes, all of them decoded
[ ok ] image-id                   the receipt claims ddb7dc544e1425640ad3af8e7b3b48afa21499a0b371ce4a59fdb4d8594d5331
[ ok ] seal                       cryptographically valid for the pinned imageId
[ ok ] journal-parses             JSON object, 259 bytes
[ ok ] journal-key-set            exactly {decision, policyId, proofNonce, protocolVersion, requestCommitment}
[ ok ] journal-protocol-version   1
[ ok ] journal-decision           ALLOW
[ ok ] journal-request-commitment 0x8873f02c5c418bd7d13f302162d91f4991bbedf8f531572fee74ba4b26a169c6
[ ok ] journal-proof-nonce        0xbe0c0000000000000000000000000000
[ ok ] policy-id                  journal and manifest agree: 0x1f74ba4f2353012cd26f5d3279625c3b45e927eeb341f0ee4b72124b056a7db2
[ ok ] rules-digest               re-derived from prover/../policy/v1: 0x9f85ba59fd1429f10c373efc56d69aefa255a01a08df3ab6bd8e1ccecd3f93ea

VERIFIED
  This receipt was produced by the image pinned in the release manifest, and the journal above is what that image committed.
  It does NOT establish that any gateway consulted this proof before answering a request; wiring the proof into the request path is Phase 2b.
  Image built with rustc 1.97.0-dev (e638c6cfe 2026-07-15) (guest) / 1.97.1 (8bab26f4f 2026-07-14) (host), risc0 3.0.6.
$ echo $?
0
```

Every transcript in this section is a verbatim capture from that binary, at the
paths shown, on the machine described under "Measured on this machine". Where a
transcript below starts at `…`, the lines above it are the ones already shown
here and nothing else has been edited.

`--expect-commitment`, `--expect-decision` and `--expect-proof-nonce` add checks
for a caller who knows what the answer should have been.

### The exit contract

**Exit 0 means every check ran and passed.** Not "nothing failed": a check that
could not run is not a check that passed, so a missing input is a failure like
any other.

| exit | meaning |
|---|---|
| 0 | every check ran and passed — or `rules-digest` was skipped, and only ever by `--no-policy-dir`, which the report says on the line and repeats in the summary |
| 1 | a check failed, or a check could not run. The first failing check is named twice: on its own `[FAIL]` line and in the last line of output |
| 2 | a usage error, an unreadable input file, or `RISC0_DEV_MODE` set to a value risc0 treats as enabled. `--help` is **not** a usage error and exits 0 |

`rules-digest` is the only check with an input the receipt does not carry, so it
is the only one where this distinction bites. There are three ways to ask for it
and they are three different questions:

```console
$ ./prover/verify/target/release/prover-verify \
    --receipt prover/verify/tests/fixtures/allow-real.receipt.bin \
    --policy-dir /tmp/empty-policy
…
[FAIL] rules-digest               policy files unreadable at /tmp/empty-policy: --policy-dir must name a directory holding a readable rules.json and manifest.json. Pass --no-policy-dir to skip this check deliberately.

NOT VERIFIED — first failing check: rules-digest
$ echo $?
1
```

An explicit `--policy-dir` is a question the operator asked; answering it with a
shrug and exit 0 would report a receipt as checked against rules that were never
read. A **missing default** path is exit 1 for the same reason, and its message
names `--no-policy-dir` as the way to proceed on purpose.

```console
$ ./prover/verify/target/release/prover-verify \
    --receipt prover/verify/tests/fixtures/allow-real.receipt.bin \
    --no-policy-dir
…
[ -- ] rules-digest               skipped by flag (--no-policy-dir): rulesDigest is pinned by the manifest and was NOT re-derived

VERIFIED
  This receipt was produced by the image pinned in the release manifest, and the journal above is what that image committed.
  It does NOT establish that any gateway consulted this proof before answering a request; wiring the proof into the request path is Phase 2b.
  Image built with rustc 1.97.0-dev (e638c6cfe 2026-07-15) (guest) / 1.97.1 (8bab26f4f 2026-07-14) (host), risc0 3.0.6.
  1 check(s) marked [ -- ] were skipped by --no-policy-dir and were NOT verified.
$ echo $?
0
```

That is the one deliberate hole in the contract, and it is exactly as wide as it
looks: with `--no-policy-dir`, a manifest whose `rulesDigest` is wrong also exits
0, because nothing was asked to check it. The flag is for someone who has the
receipt and the manifest but not the policy files; it is not a way to make a run
green.

### What each check means

| check | what it establishes |
|---|---|
| `manifest` | `release.json` parses as a manifest — every field present, none unknown, the identities the right shape. An unknown key is a refusal, not a shrug: a verifier that ignores a field is trusting a claim it did not read. |
| `receipt-codec` | the manifest names a codec this binary can decode (`bincode-v1`). |
| `receipt-decodes` | the file is a `risc0_zkvm::Receipt` under that codec — **the whole file**. Trailing bytes are refused (`reject_trailing_bytes`), so the byte count printed is a count of bytes that were decoded rather than a count of bytes on disk. `bincode`'s default is to decode a receipt out of the prefix and ignore the rest, which made a real receipt with anything appended verify. |
| `image-id` | the ImageID in the receipt's claim is the pinned one. Split out from `seal` so "a valid proof of the wrong program" reads differently from "not a valid proof". |
| `seal` | the zero-knowledge proof verifies against the pinned ImageID, the guest exited `Halted(0)`, and the journal is the one the proof commits to. **This is the check that carries the weight.** |
| `journal-parses` | the committed bytes are a JSON object. The journal is *parsed, never re-encoded* — the bytes are already bound by the seal, so re-canonicalizing them would only test this program's serializer. |
| `journal-key-set` | exactly `{decision, policyId, proofNonce, protocolVersion, requestCommitment}` — the allowlist `services/tee-sim/src/verify.ts` enforces. No category scores, no prompt-derived anything. |
| `journal-protocol-version` | matches the manifest's `journalVersion`. |
| `journal-decision` | one of the two the engine can produce. |
| `journal-request-commitment` | `0x` + 64 lowercase hex. |
| `journal-proof-nonce` | inside `^(0x)?[0-9a-f]{1,64}$`. The guest enforces this bound too, but the guest is *the thing being authenticated* — a journal from any other image is bounded by nothing, and `proofNonce` is the only variable-length field in a public artifact. Checked here so a fat nonce fails on a named check rather than sliding through the key-set test. |
| `policy-id` | the `policyId` the image committed is the one the manifest pins. |
| `rules-digest` | `policy/v1/{rules,manifest}.json` re-derive the manifest's `policyId` **and** `rulesDigest`, through `policy_core::policy_id` — the same function the guest's build script used. The only check whose input the receipt does not carry, and so the only one governed by the exit contract above: no readable policy files is exit 1 unless `--no-policy-dir` said to skip it. |

That last one is the only check that looks outside the receipt, and it has to.
`rulesDigest` is not in the journal and no receipt can attest to it. What *is* in
the journal is `policyId = sha256(canonical_manifest ‖ rules_bytes)`, and
`rulesDigest = sha256(rules_bytes)` — so re-deriving both from the same two files,
with the `policyId` half already matched against the journal, ties the pinned
digest to the exact rules bytes the proving image was built from. Without the
files it is exit 1; with `--no-policy-dir` it reports `[ -- ]`, says the flag
skipped it, and the summary counts it. It is never silently skipped and never
quietly passed.

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
sentence and exit 2. "Set" means what risc0 means by it: the variable
lowercased is `1`, `true` or `yes` (`risc0-zkvm-3.0.6/src/lib.rs:204-209`).
`RISC0_DEV_MODE=0` is *off* to risc0 and is off here too, so the verifier runs
normally under it — refusing there would have made the tool unusable in any CI
image that exports the variable disabled, without rejecting one extra receipt.
The same predicate discipline as `--bench` and the daemon, which ask
`ProverOpts::composite().dev_mode()` rather than inventing a second reading of
the variable; this binary cannot call that (with `disable-dev-mode` compiled in,
that call is the panic being pre-empted), so it mirrors it.

The claim was checked by removing the feature. Rebuilt without
`disable-dev-mode` and run with `RISC0_DEV_MODE=1`, the same binary **accepts the
same dev-mode stub**: all thirteen checks pass and it prints `VERIFIED`, exit 0.
The feature is load-bearing, not decoration. (Reverted immediately; the committed
build rejects it, exit 1.)

### No network I/O

Structural first. `risc0-zkvm` is taken with `default-features = false`, which
drops two defaults that both speak HTTP: `bonsai` (a client for a remote proving
service) and `client` (which pulls in `rzup`, a toolchain downloader, and
`risc0-build`). What is left has nothing network-capable in it. Both numbers and
both greps below are reproducible with the commands as written:

```console
$ cd prover/verify && cargo tree --prefix none | awk '{print $1}' | sort -u | grep -v '^$' | wc -l
     142

$ cd prover/verify && cargo tree | grep -Ei 'reqwest|hyper|tokio|bonsai|rzup|risc0-build|rustls|native-tls|openssl|curl|ureq'
$                       # no output, exit 1

$ cd prover && cargo tree -p host --prefix none | awk '{print $1, $2}' | sort -u \
    | grep -Ei '^(reqwest|hyper|hyper-rustls|hyper-util|rzup|risc0-build|bonsai-sdk) '
hyper v1.11.0
hyper-rustls v0.27.9
hyper-util v0.1.20
reqwest v0.12.28
risc0-build v3.0.6
rzup v0.5.2
```

142 is a count of **unique package names** in the verifier's tree, which is what
that command counts; the same tree has more nodes than that, because one package
can appear at several versions and at many places in the graph. Quoting a number
without the command that produces it is how "148 crates" got into this README and
stayed wrong.

The contrast is the point: the daemon legitimately links an HTTP stack, and the
verifier legitimately cannot. One caveat on the right-hand column, unchanged from
when it was written: `cargo tree -p host` includes build-dependencies, so
`risc0-build` and `rzup` in that list are the guest *build* graph rather than
anything the daemon links at run time. `hyper`, `hyper-util` and `reqwest` are
run-time, and the daemon links `axum` on top of them anyway, so the contrast
holds — but it is two facts, not one.

Then behaviourally, under a macOS sandbox that denies all networking:

```console
$ cat > /tmp/no-network.sb <<'EOF'
(version 1)
(allow default)
(deny network*)
EOF

$ # control: the profile really does deny networking
$ sandbox-exec -f /tmp/no-network.sb curl -sS https://example.com; echo "exit $?"
curl: (6) Could not resolve host: example.com
exit 6

$ sandbox-exec -f /tmp/no-network.sb ./prover/verify/target/release/prover-verify \
    --receipt prover/verify/tests/fixtures/allow-real.receipt.bin > /dev/null; echo "exit $?"
exit 0

$ sandbox-exec -f /tmp/no-network.sb ./prover/verify/target/release/prover-verify \
    --receipt prover/verify/tests/fixtures/dev-mode.receipt.bin > /dev/null; echo "exit $?"
exit 1
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

Measured on this machine (M1 Pro, 32 GB, release, CPU-only), starting from the
committed ALLOW receipt. The succinct row is **one run**; the composite row's
verify is the three-run median from the table further down:

| kind | bytes | to produce | verify (in-process) |
|---|---|---|---|
| composite | 537,794 | 124.57 s (the prove itself) | 29.1 ms |
| succinct | 223,744 | +29.52 s compressing the composite | 12.5 ms |
| Groth16 | — | **not measurable here** | — |

Both verify numbers are wall-clock and therefore from the previous image — see
the re-taken/not-re-taken note at the top of "Measured on this machine"; the
composite one is the `allow-001` median from the three-proof table above. **Compressing halves the
verify cost as well as shrinking the artifact 2.4×** — one recursive seal to
check instead of two segments' worth.

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

`prover/verify/tests/fixtures/` holds five real receipts so that `cargo test`
costs seconds instead of ~8 minutes of proving. `tests/fixtures/README.md` has
the regeneration commands, including how the wrong-image receipt was produced
without a second image ever existing inside this repository.

The fifth is `adv-004-deny.receipt.bin`, and it is there because it is the only
committed artifact carrying the claim that **the Unicode fold ran in the image**:
its prompt spells the blocked phrase fullwidth (`ｂｏｍｂ`), nothing in
`rules.json` matches that literally, and the seal binds the resulting DENY to
image `ddb7dc544e14…`. The test rebuilds the canonical request from the corpus
fixture and requires the receipt to verify 13/13 against that exact commitment,
so the artifact and the prompt on disk cannot drift apart silently.

---

## Measured on this machine

Apple M1 Pro, 10 cores, 32 GB, macOS 26.0.1. `--release`, dev mode off (refused
outright), in-process prover (backend `local`, enforced), host toolchain pinned
1.97.1. Guest image
`ddb7dc544e1425640ad3af8e7b3b48afa21499a0b371ce4a59fdb4d8594d5331`, policy id
`0x1f74ba4f2353012cd26f5d3279625c3b45e927eeb341f0ee4b72124b056a7db2`, rules digest
`0x9f85ba59fd1429f10c373efc56d69aefa255a01a08df3ab6bd8e1ccecd3f93ea`. The policy
id and the rules digest have not moved since Task 4's first image — `policy/v1/`
has not been touched since. There is no longer a table here quoting a previous
image.

**Which numbers were re-taken at this ImageID, and which were not.** The
path-independence fix (see "Reproducibility of the image") moved the image from
`75751480a7e7…` without changing what the guest *does*: it renamed symbols and
rewrote embedded path strings. **Cycle counts are exact and they did move**, by
tens of cycles out of a million, so every cycle number below was re-taken at
`ddb7dc544e14…` with a fresh `--bench --fixtures` (the one exception is the
three-proof table under "Three proofs, end to end", whose cycle columns come out
of the 24-minute proving bench, which was not re-run — that table is entirely at
the previous image and says so). **Wall-clock timings were not re-taken**, and the reason is stated so it can be argued with: they are
±20 %-noisy on this machine, a tens-of-cycles change is four orders of magnitude
below that noise, and re-running the 24-minute proving bench would have replaced
good numbers with equally noisy ones. So the wall-clock columns are the Task
5/7 runs at the previous image and the cycle columns are new.

```bash
cargo run -rp host -- --bench --fixtures                 # the corpus table
cargo run -rp host -- --bench --keep-receipts /tmp/r     # the three proofs
```

### The gate, over the whole fixture corpus

All **125** fixtures in `policy/v1/fixtures` (50 allow, 50 deny, 25 adversarial),
executor only, three timed runs per fixture after one discarded warmup, on an
otherwise-idle machine. The run aborts if the guest's decision disagrees with any
corpus label, so it is a correctness check as much as a benchmark. The
distribution is over the 125 per-fixture medians. **p95 is nearest-rank** —
`ceil(0.95 × 125)`, sample 119 of 125 sorted, no interpolation — because at this
sample size the estimator moves the answer, and a p95 quoted without its
estimator is not reproducible.

| bucket | n | min | median | p95 | max |
|---|---|---|---|---|---|
| allow | 50 | 50.9 ms | 56.4 ms | 56.7 ms | 59.5 ms |
| deny | 50 | 50.5 ms | 56.4 ms | 58.3 ms | 59.6 ms |
| adversarial | 25 | 50.4 ms | 56.4 ms | 57.2 ms | 59.2 ms |
| **all** | **125** | **50.4 ms** | **56.4 ms** | **58.1 ms** | **59.6 ms** |

| | min | median | p95 | max |
|---|---|---|---|---|
| user cycles | 468,739 | 1,114,720 | 1,204,154 | 1,696,804 |

Segments across the corpus: `[1, 2]`. Max po2: **20, for all 125 of them.**

The extremes, from the same run:

| | fixture | prompt bytes | median | user cycles |
|---|---|---|---|---|
| most cycles | `allow-050` | 244 | 59.5 ms | 1,696,804 |
| fewest cycles | `adv-020` (empty prompt) | 0 | 50.4 ms | 468,739 |
| longest prompt | `adv-022` | 300 | 57.2 ms | 1,255,825 |
| slowest *(this run only)* | `deny-027` | 55 | 59.6 ms | 1,054,111 |
| fastest *(this run only)* | `adv-020` | 0 | 50.4 ms | 468,739 |

**Only the cycle-ranked rows are corpus facts.** Cycle counts are byte-identical
across runs of a given image, so "most cycles" and "fewest cycles" name the same
two fixtures every time. The wall-time ranks do not: a rerun on this machine put
`allow-050` slowest at 59.9 ms and `deny-050` fastest at 50.5 ms, with `adv-020`
fifth at 52.0 ms. **The band is roughly 50–60 ms on an idle machine — a third
run grazed 60.6 ms, and a loaded one reached 65.3 — and the ordering inside it
is noise.** Read
the last two rows as "what a single run happened to rank", not as properties of
those fixtures.

**Cycles vary 3.6×; wall time varies 1.18×.** That gap is the useful fact. Fitting
a line through the two ends of the *cycle* range gives roughly **47 ms of fixed
session setup plus ~7.4 ms per million user cycles** — a two-point estimate, not a
regression, and quoted as an order of magnitude. Its anchor is honest only at that
resolution: both constants come from one run's extremes, and re-fitting on the
rerun above moves them to ~49 ms + ~6.4 ms per million — a 14% swing in the slope
off two points. What survives the reshuffle is the shape: the gate is very nearly a
constant per-request cost, about 50 ms of it happens whatever the request is, and
the entire labelled corpus fits in a 9 ms band on top of that.

**Prompt length is not the lever either.** The longest prompt in the corpus sits
mid-distribution and the empty one sits at the floor, but `allow-050` at 244 bytes
burns more cycles than `adv-022` at 300. What moves cycles is how much of the
ruleset a prompt makes the matcher touch. Phase 2b should budget a **tight ~60 ms**
per `/execute` — the corpus max is 59.6 ms here and a rerun hit 59.9, so treat
anything over as load, not as policy work — and should not expect to recover any
of it by shrinking inputs.

### Three proofs, end to end

Three fixture prompts, chosen so the set is not two near-identical ALLOWs:
`allow-001` (a haiku), `deny-001` (a P1 phishing request), and `adv-004` — the
adversarial one, picked over the other 24 because its DENY exists *only* if the
§23 normalizer folds the fullwidth `ｂｏｍｂ` back to `bomb` **inside the zkVM**. A
verified receipt for that journal is evidence that the Unicode half of the policy
ran in the image, which is the part of this design a reader is most entitled to
doubt. `--bench` refuses to start if any of the three has drifted from the file in
`policy/v1/fixtures`.

Three timed runs each after one discarded warmup. Medians. **Every number in
this subsection — cycles included — is from the previous image**
(`75751480a7e7…`): re-taking it costs 24 minutes of proving and the fix that
moved the ImageID moved cycle counts by about a hundred out of a million.

| Case | Executor | Composite prove | Receipt (bincode) | Verify, in-process | Verify, `prover-verify` |
|---|---|---|---|---|---|
| `allow-001` ALLOW | 58.3 ms | 124.10 s | 525.2 KB (537,794 B) | 29.1 ms | 31.3 ms |
| `deny-001` DENY | 56.4 ms | 122.85 s | 525.2 KB (537,792 B) | 29.4 ms | 31.9 ms |
| `adv-004` DENY | 57.3 ms | 113.37 s | 513.8 KB (526,080 B) | 29.7 ms | 30.5 ms |

Spread (min / median / max):

| Case | Executor ms | Prove ms | Verify ms (in-process) |
|---|---|---|---|
| `allow-001` | 57.0 / 58.3 / 58.6 | 120,343.7 / 124,100.5 / 126,405.4 | 29.0 / 29.1 / 29.1 |
| `deny-001` | 56.4 / 56.4 / 56.5 | 122,517.2 / 122,854.7 / 129,804.9 | 29.0 / 29.4 / 29.7 |
| `adv-004` | 56.5 / 57.3 / 57.8 | 111,029.9 / 113,371.3 / 114,039.2 | 28.6 / 29.7 / 29.7 |

| Case | Segments | Max po2 | User cyc | Total cyc | Paging cyc | Reserved cyc |
|---|---|---|---|---|---|---|
| `allow-001` | 2 | 20 | 1,109,291 | 1,310,720 | 127,270 | 74,159 |
| `deny-001` | 2 | 20 | 1,090,549 | 1,310,720 | 128,223 | 91,948 |
| `adv-004` | 2 | 20 | 1,005,773 | 1,179,648 | 129,514 | 44,361 |

`total = user + paging + reserved` exactly, in all three rows.

**Two different verify numbers, and they are two different questions.** The
in-process column is `Receipt::verify` called immediately after proving, on a
receipt still in memory — ~29 ms, and it is the cost of the cryptography alone.
The `prover-verify` column is wall time for the **whole process**: exec the
binary, read the receipt off disk, parse `release.json`, re-derive the rules
digest from `policy/v1/`, run all 13 checks, print the report. Five timed runs
after a warmup; the spread was 31.2–34.7 ms (`allow-001`), 31.6–32.7
(`deny-001`), 30.4–30.5 (`adv-004`). So an independent verifier pays about
**31 ms**, of which roughly 29 is the seal. That is the number that matters: it is
what a third party spends to check a proof that cost two minutes to make.

**The three receipts verify.** All three were written out with `--keep-receipts`
and handed to the release `prover-verify` binary: 13/13 checks, `VERIFIED`,
exit 0, and the `adv-004` one reports `journal-decision DENY` on a journal whose
DENY depends on the in-image Unicode fold.

**The executor pays 2–4 ms more while a prove is in flight in the same process.**
The medians above are from a separate executor-only pass on an idle machine
(`CTN_BENCH_PROVE=0`). Inside the full 24-minute `--bench` run, the same three
fixtures measured 60.3 / 57.6 / 61.6 ms — +2.0, +1.2 and +4.3 ms. Three samples,
one machine, thermal state uncontrolled; report it, do not model it.

**Prove cost tracks padded rows, and the constant is stable.** 124.10 s over
1,310,720 rows, 122.85 s over 1,310,720, 113.37 s over 1,179,648 — that is
**0.0937, 0.0947 and 0.0961 ms per padded row**, a 2.5% band across three
measurements of two different row counts. The cheapest of the three pads to
`2^20 + 2^17` rather than `2^20 + 2^18` — but it *also* runs 9.3% fewer user
cycles, and at n=3 those two explanations coincide and cannot be separated. The
padding story is the one the row counts support directly; "it does less policy
work" is equally consistent with these three numbers and is not ruled out.

**Prove wall time is still noisy at the ±20% level between runs, and the ±20% is
not visible in this table.** Within this run the widest case is `deny-001` at
122.5–129.8 s. Between runs it has been much worse: an earlier full bench of an
image differing by 228 user cycles gave medians of 164.88 s and 159.42 s on the
same idle laptop, 20–26% above these, and Task 5's daemon runs gave 134.70 s,
122.58 s and 121.21 s for `allow-001`. Three runs inside one process share a
thermal state and a warm allocator, so a tight within-run spread is the *weaker*
evidence. Do not quote 124 s as a constant. Quote **"two to three minutes on an
idle M1 Pro, CPU-only"**, and treat cycle counts — byte-identical across every
run of a given image — as the reproducible quantity.

### Where the user cycles go

Measured in-guest with `env::cycle_count()` on the ALLOW case with `emitScores`
off: 1,089,150 cycles between the first and last reading, against 1,100,938 for
the whole session. **These are the only numbers in this section not taken at the
current image, and they cannot be** — reading a cycle counter at six points
inside the guest requires a guest with six extra readings in it, which is by
construction a different image. The instrumented image was the prior `4a05b4e9…`
one, 8,353 user cycles (0.76%) lighter in total. Read the proportions, not the
counts:

| Phase | Cycles |
|---|---|
| `evaluate_prepared` | 661,275 |
| postcard-decoding the embedded ruleset | 358,084 |
| building and committing the journal | 41,148 |
| the SHA-256 commitment | 19,434 |
| parsing the canonical request | 5,728 |
| decoding the input frame | 3,481 |

Nothing was optimized beyond the two hoists described above. If a later task needs
a po2 back, those first two rows are the entire conversation — and note that the
second one is *already* the cheap version: normalizing the needles in-guest
instead of at build time costs 2,264,222 cycles.

### The daemon, under a prove in flight

Same machine and image, through the gated end-to-end test, which enqueues one
`POST /prove` for the `allow-001` fixture, fires one `POST /execute` while it is
running, then verifies the returned receipt against the baked ImageID:

```bash
CTN_PROVE_TEST=1 cargo test -rp host --test api -- --ignored --nocapture
```

| Run | Composite prove | Receipt (bincode) | `/execute` during the prove | Machine state |
|---|---|---|---|---|
| 1 | 134.70 s | 525.3 KB | 66 ms | a release build + the differential suite were running |
| 2 | 122.58 s | 525.3 KB | 90 ms | otherwise idle |
| 3 (reviewer's) | 121.21 s | 525.3 KB | 88 ms | otherwise idle |

**`/execute` is not starved by a prove in flight — and these three samples do not
order the way load says they should.** 66 ms came off the *loaded* run; 90 ms and
88 ms came off the idle ones, against a ~57 ms idle median. The reading that fits
is that a single `/execute` under a single concurrent prove is dominated by
scheduling luck at this sample size rather than by machine load: the prove worker
is its own OS thread, the tokio runtime keeps its own, and ten cores absorb both.
(The in-process measurement above, where the executor did pay a consistent
2–4 ms under proving, is a different arrangement: same process, same thread pool,
no HTTP.) What these three establish is the weak claim the test asserts — an
`/execute` under a prove answers in well under 2 s — and nothing about the daemon
under real concurrency.

### The Task 1 spike guest — the floor, kept for contrast

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
the policy guest's id is at the top of this section.

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

This file then told Phase 2b to budget **~20 ms per execution regardless of
prompt size**, and that prediction was **wrong by 3×**. The policy guest's corpus
run says 50–60 ms. The *shape* of the claim survived — the cost is dominated by
fixed setup and does not track prompt size, which the 125-fixture distribution
above establishes far better than two spike points ever did — but the constant
belonged to a guest that did nothing. Budget 60 ms; the corpus table is the one
to read.

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

That gave a planning rule: **po2 ≥ ceil(log2(user_cycles + paging_cycles))**, and
cost follows from po2.

It is a lower bound rather than an equality, and the two rows above are why: they
are consistent with `reserved` being *pure* padding, but they cannot prove it. If
the proof system also needs some fixed non-padding allocation inside `reserved`,
the 256 B row caps it at 15,739 cycles — so the rule can under-predict by one po2
for a guest landing within roughly 15k cycles below a boundary. Plan against the
next po2 up when a guest lands that close.

**The policy guest showed the rule needs a second correction, in the other
direction: it is per *segment*, and cost follows padded rows, not po2.** Applied
whole-session to `allow-001` (1,109,291 user + 127,270 paging) the rule predicts
2^21 = 2,097,152 padded rows. The real total is 1,310,720 = 2^20 + 2^18, because a
session that spans segments pads each segment separately and packs the tail into
a smaller block — 37% *cheaper* than the whole-session reading. `adv-004` pads to
2^20 + 2^17 = 1,179,648 and costs 9% less than `allow-001`; it also runs 9.3%
fewer user cycles, so at n=3 "fewer padded rows" and "less policy work" coincide
and this data cannot tell them apart. So: a lower bound on the po2 of any single
segment, an
upper bound on the padded total once a session segments, and never a cost
prediction on its own. `total_cycles` — which is a sum, not a power of two — is
the quantity to multiply by the per-row rate.

Two things fall out of it. Paging is half the real work at 256 B (24,870 against
24,927 user cycles), so the policy guest's memory access pattern will move its po2
as readily as its arithmetic will. And **po2 cannot be predicted from user cycles
alone** — an earlier version of this file claimed 24,927 and 65,535 user cycles
would both fit po2 16. They would not: 65,535 user cycles plus even this spike's
modest ~25,000 paging cycles is ~90,000, which rounds to po2 17.

Time then scales near-linearly with padded rows: 8× the rows cost 8.85× the time
(po2 16 → 19), roughly **0.087–0.096 ms per row**. This file extrapolated from
that to **~105 s at po2 20** and ~210 s at po2 21.

**The rate held; the extrapolation did not, and it is worth being precise about
which half was wrong.** The policy guest's three proofs come out at 0.0937,
0.0947 and 0.0961 ms per padded row — inside the spike's band, across two
different row counts, on a guest a hundred times larger. What the extrapolation
got wrong was the *row count*: "po2 20" was read as 2^20 = 1,048,576 rows, and the
real sessions pad to 1,310,720 and 1,179,648 because they span two segments. At
the measured rate those predict 123 s and 111 s, against 124.10 s and 113.37 s
measured. So the near-linear-in-padded-rows model is in good shape and the way to
misuse it is to guess the rows.

**Composite receipts are ~250 KB at one segment and ~525 KB at two.** That is a
storage and transport cost per receipt, not per policy. Compressing to succinct
gives 223,744 bytes for +29.52 s (measured); Groth16 would give a constant-size
receipt of a few hundred bytes, and its cost is **unmeasured** because the
compression step needs Docker — see "Which receipt kind", where the manifest's
`receiptCodec` decision is recorded.

### What is not established

Everything above is one laptop, one toolchain, and — for the expensive half — a
handful of runs. Specifically **not** shown:

- **Semantic identity with the TypeScript preview.** The engine this image runs
  and the TS engine the demo's Policy Lab previews with disagree — bidirectionally
  — on 133 code points that Unicode 16 (Node's ICU) leaves unassigned and the
  Rust tables (Unicode 17) assign: 416 (code point, site) pairs where the guest
  is stricter, 104 where it is *laxer*. The differential suite enforces that
  inventory as a baseline that may shrink but not grow, and it is zero on
  version-stable material — but a proof of the guest's decision is a proof about
  *this* engine, not about what a preview showed. VALIDATION §2c carries the
  full census; labelling the disagreement in the Policy Lab UI is Phase 2b's.
- **A stable prove time.** Two full benches of near-identical images differ by
  20–26% at the median; three daemon runs of one fixture gave 134.70 s, 122.58 s
  and 121.21 s; `--bench` gave a 124.10 s median for that same fixture with a
  120.3–126.4 s within-run spread. There is a central tendency of
  roughly two to three minutes and no evidence for anything tighter. The cause of
  the between-run drift was never investigated.
- **A latency tail under load.** The corpus p95 is a distribution over *125
  different fixtures*, each measured on an idle machine — it says the gate costs
  about the same whatever the request is. It is not a p95 over repeated runs of
  one request, and it says nothing about what `/execute` costs while the machine
  is busy. The only concurrency samples here are three single `/execute` calls
  fired under one in-flight prove, and they do not even order correctly against
  load.
- **Cost as a function of prompt size, beyond this corpus.** All 125 fixtures are
  a single user message and the longest is 300 bytes. The daemon accepts up to
  10 MiB and per-request executor work is linear in canonical bytes — Task 5's
  review measured 1 MB at **34.2 s** — so there is a régime this section does not
  describe at all, and Phase 2b needs a real input bound rather than a body cap.
  Nothing here measures a multi-turn conversation either.
- **Anything about GPUs.** Proving here is CPU-only (next section). A risc0 that
  re-enables the Metal path invalidates every prove number on this page, by an
  unmeasured amount.
- **How receipt size scales.** Two data points at one segment (spike, ~250 KB)
  and three at two segments (policy guest, ~525 KB) are consistent with "roughly
  linear in segments" and do not establish it. Nothing here measured a
  three-segment session.
- **Anything about Groth16.** Succinct is measured (223,744 bytes, +29.52 s from
  the composite, 12.5 ms to verify); Groth16 proving needs Docker, which this
  machine does not have — see "Which receipt kind". Any Groth16 number in this
  repository is unmeasured.
- **Cross-machine reproducibility of the image.** Three cold builds on one
  machine, and the third of them under a newly pinned host toolchain, all
  returned a byte-identical guest ELF. That is evidence the build is not
  gratuitously nondeterministic. Nobody has built this image on a second machine.
- **Concurrency, beyond one probe.** Three single `/execute` calls under a single
  in-flight prove — enough to show the executor is not starved, not enough to
  characterise the daemon under load. Nothing here measures several concurrent
  `/execute` calls, a full queue, or what a second prove would do; the prove
  worker is one thread partly because that is unmeasured.
- **The in-guest cycle breakdown at this image.** It comes from an instrumented
  guest, which is by construction a different image; see "Where the user cycles
  go".

### Proving is CPU-only

Every proving number in this file is a **CPU** number — the policy guest's
113–124 s composite proofs above, and the spike's 50 s at 4 KB alike. Nothing
here is GPU-accelerated, despite the
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
be said is that **113–124 s for one policy proof** is what ten M1 Pro CPU cores
cost (and, in the spike, ~50 s at 4 KB), and that those are ceilings a GPU path
could only improve on.

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

One more, whenever anything under `policy-core/`, `methods/` or `policy/v1/` has
been touched — including a comment, for the reason in "Reproducibility of the
image":

```bash
# builtAt is the only field allowed to move. This gate is a real signal on a
# clean checkout: since the ImageID stopped depending on the build path (see
# "Reproducibility of the image"), a mismatch here means something in the image
# or the toolchain actually changed — not that you cloned to a different
# directory. Do NOT answer a mismatch by re-cutting release.json; find what
# moved first.
diff <(grep -v builtAt release.json) \
     <(cargo run -qrp host -- --emit-release | grep -v builtAt)
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
scores present only when asked), eleven malformed-request shapes — nine of them
against **both** POST endpoints and two against `/execute` only: the wrong-type
`emitScores` body, because that field is not part of the `/prove` body at all,
and the decodes-but-not-canonical request, because only the guest can say so and
`/prove` deliberately reports that through the job rather than paying an executor
run on the enqueue path — with a marker planted in every caller-controlled field, a body
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
positive control). A full `--bench` — twelve proofs at these po2s — measured
**24 minutes**; `--bench --fixtures` is 28 seconds for all 125, and
`CTN_BENCH_PROVE=0` is a second, for iterating.

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

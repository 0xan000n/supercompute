# prover

The real RISC Zero prover for Safety Policy v1. Phase 2a builds it; this
directory is currently at **Task 1 — toolchain and spike**, which means the
workspace builds, proves and verifies, but the guest hashes its input rather
than evaluating policy. The policy engine arrives in Tasks 2–4.

What Task 1 is actually for is the numbers at the bottom of this file. Phase 1
modelled the cost of proving (`CTN_SIMULATED_PROVING_MS`, default 2400 ms) and
labelled it as modelled. Everything after this task gets to use measurements
instead.

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
| risc0 Rust toolchain (guest) | 1.97.0 |
| risc0 C++ toolchain | 2024.1.5 |
| `risc0-zkvm` / `risc0-build` crates | 3.0.6 |

Machine: Apple M1 Pro, 10 cores, 32 GB, macOS 26.0.1. Proving uses Metal
acceleration, which risc0 selects automatically on Apple Silicon — no feature
flag, no configuration.

---

## Layout

```
prover/
  Cargo.toml            workspace: host + methods
  rust-toolchain.toml   stable, with rustfmt and rust-src
  methods/
    build.rs            risc0_build::embed_methods() — compiles the guest, emits ELF + image id
    src/lib.rs          include!(OUT_DIR/methods.rs)
    guest/src/main.rs   the guest: runs inside the zkVM
  host/src/main.rs      the host: builds input, executes, proves, verifies
```

This is the layout `cargo risczero new` generates, kept deliberately. The
`methods` build-script indirection is what produces `POLICY_GUEST_ELF` and
`POLICY_GUEST_ID`, and the image id is what Phase 1 already hashes into
`policy_id` — so the wiring is load-bearing, not boilerplate.

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
cargo run -rp host -- --bench
```

`--bench` is the only mode implemented. The proving daemon is Task 5.

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
- When the daemon lands in Task 5, dev mode must be surfaced in the receipt it
  emits, the same way simulated attestation is labelled today. A receipt that
  does not say it is fake is worse than no receipt.

---

## Measured on this machine

Three timed runs per measurement after one discarded warmup, `--release`, dev
mode off, in-process prover (backend `local`, enforced). Reproduce with
`cargo run -rp host -- --bench`.

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

Guest image id `d094ec7bbac59857234c8c316573b591e5830ed9656fec4cf332440a0e19ff50`
— it changes whenever the guest or its dependency graph does, which is the point.

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

**Proving cost tracks the padded total, and user cycles are a minority of it.**
`total_cycles` comes out to exactly 2^po2 — 65,536 and 524,288 — with user,
paging and reserved cycles summing to it precisely. User cycles are only 38% of
the padded total at 256 B and 51% at 4096 B; the rest is paging and reserved
overhead that does not shrink proportionally. **You therefore cannot predict po2
from user cycles**, which is what an earlier version of this file tried to do
when it claimed 24,927 and 65,535 cycles would both fit po2 16. They would not:
at 256 B, 24,927 user cycles already pull in 40,609 cycles of paging and reserved
overhead to reach 2^16, so a guest with 65,535 *user* cycles would spill well
into po2 17.

Time scales near-linearly with padded rows: 8× the rows cost 8.85× the time
(po2 16 → 19), or roughly 0.087–0.096 ms per row. Extrapolating for Tasks 4 and
7: **~105 s at po2 20, ~210 s at po2 21.** The policy guest will do more per byte
than sha256 does *and* carry more paging overhead, so expect it a po2 or two above
this spike at equal input size — affordable off the request path, nowhere near
affordable on it.

**Composite receipts are ~250 KB and grow with execution length.** That is a
storage and transport cost per receipt, not per policy. Compressing to Groth16
yields a constant-size receipt of a few hundred bytes at the cost of extra
proving time; neither the compression time nor the resulting size has been
measured here, and Task 6 should measure both before the release manifest
commits to a receipt format.

### What is not established

**No CPU-versus-GPU comparison was run**, so nothing here quantifies what the GPU
contributes. Metal acceleration is active, but not because of the `metal` cargo
feature — in 3.0.6 that feature is a pure alias for `prove` and adds nothing else.
`risc0-sys/build.rs` builds the Metal kernels for any `macos` or `ios` target
unconditionally, with no feature gate, which is also why enabling `prove` is what
made the Metal Toolchain a hard build requirement. The build therefore does not
name `metal` at all. A suggestive but non-decisive data point: proving times were
within noise of the earlier run against the external `r0vm` subprocess, and that
binary is GPU-enabled too, so those two configurations differed in IPC overhead
rather than in acceleration.

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

The spike guest hashes with the ordinary `sha2` crate. risc0 ships accelerated
patches for the RustCrypto hashes (wired in via `[patch.crates-io]`, pointing
`sha2` at `risc0/RustCrypto-hashes`), and they would cut the guest's cycle count
substantially for hash-heavy work.

They are deliberately not used yet. The policy guest has to hash exactly the
bytes the TypeScript engine hashes, and Task 3's differential tests are the
thing that proves it does. Keeping one unpatched crate on both sides means a
digest disagreement is a real bug rather than a library difference. The patch is
worth revisiting in Task 7 once the differential corpus is green — the digests
are identical by construction, so it is a performance change, not a semantic
one.

---

## Gates

```bash
cd prover
cargo fmt --check
cargo clippy -- -D warnings
cargo test
```

`cargo test` is executor-only and stays fast; it pins the contract the policy
guest inherits — one frame in, the sha256 of exactly those bytes out, agreeing
with the host's `sha2` at 0, 1, 256 and 4096 bytes. Nothing in the test suite
proves, because proving belongs in `--bench`.

`prover/target/` is the only thing gitignored here. `Cargo.lock` is committed on
purpose: the guest image id depends on the exact dependency graph, and Phase 1
already treats that id as part of `policy_id`.

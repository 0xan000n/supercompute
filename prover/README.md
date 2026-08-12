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

Three runs per measurement, median reported, `--release`, dev mode off,
in-process prover (backend `local`). Reproduce with
`cargo run -rp host -- --bench`.

| Input | Executor only | Composite prove | Receipt (bincode) | Verify |
|---|---|---|---|---|
| 256 B | 23 ms | 5.73 s | 216.1 KB (221,274 B) | 12 ms |
| 4096 B | 18 ms | 49.66 s | 262.0 KB (268,250 B) | 15 ms |

Guest image id `d094ec7bbac59857234c8c316573b591e5830ed9656fec4cf332440a0e19ff50`
— it changes whenever the guest or its dependency graph does, which is the point.

| Input | User cycles | Segments | Segment po2 |
|---|---|---|---|
| 256 B | 24,927 | 1 | 16 |
| 4096 B | 265,498 | 1 | 19 |

Three things in that table matter more than the headline numbers.

**Executor latency is a floor, not a function of input size.** 23 ms at 256 B and
18 ms at 4096 B — the smaller input measured *slower*, and across all runs both
sizes landed in 17–23 ms while the cycle count grew 10×. Nearly all of it is
fixed setup (ELF load, page-in, session start); the marginal cost of 240,000
extra cycles is around 1 ms. Phase 2b should budget roughly 20 ms per execution
regardless of prompt size, and should not expect to optimise that by shrinking
the input.

**Proving cost tracks the padded power of two, not the cycle count.** 8× the
rows (po2 16 → 19) cost 8.7× the time. So proving is near-linear in padded rows,
and the cliff is at each po2 boundary: 24,927 cycles and 65,535 cycles both cost
po2 16. The useful extrapolation for Tasks 4 and 7 is ~100 s at po2 20 and
~200 s at po2 21. The policy guest will do more per byte than sha256 does, so it
will land a po2 or two higher than this spike at the same input size — which is
affordable off the request path, and nowhere near affordable on it.

**Composite receipts are ~250 KB and grow with execution length.** That is a
storage and transport cost per receipt, not per policy. Compressing to Groth16
yields a constant-size receipt of a few hundred bytes at the cost of extra
proving time; neither the compression time nor the resulting size has been
measured here, and Task 6 should measure both before the release manifest
commits to a receipt format.

### What is not established

Metal is compiled in (`metal` feature, which implies `prove`), but no
CPU-versus-GPU comparison was run, so nothing here quantifies what the GPU
contributes. Notably, proving times were within noise of the earlier run against
the external `r0vm` subprocess — that binary is GPU-enabled too, so the two
configurations differ in IPC overhead rather than in acceleration.

That IPC overhead is the one number the first run did get wrong, and it is worth
recording why. `prove` is **not** a default feature of `risc0-zkvm`. Without it,
`default_prover` and `default_executor` silently shell out to an `r0vm`
subprocess, which added a fixed ~28 ms to every executor call — for a
measurement whose whole purpose is a ~20 ms budget, that is the difference
between a usable number and a misleading one. `host/Cargo.toml` therefore
enables `prove` explicitly, and `--bench` prints the backend name so a stray
measurement cannot be mistaken for the other configuration.

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

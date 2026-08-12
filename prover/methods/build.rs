fn main() {
    // `cargo clippy` exports RUSTC_WORKSPACE_WRAPPER=clippy-driver. risc0-build
    // spawns a nested `cargo build` for the guest and sanitises `CARGO*` and
    // `RUSTUP_TOOLCHAIN` from that child's environment, but not the wrapper
    // variables — so the guest gets compiled by clippy-driver against
    // `riscv32im-risc0-zkvm-elf`, which has no clippy-visible `std`, and the
    // build dies with "can't find crate for `std`".
    //
    // Clearing them here keeps `cargo clippy -- -D warnings` working on the
    // workspace as documented in prover/README.md. The host is still linted;
    // the guest is compiled with its own toolchain, as it is in a plain build.
    std::env::remove_var("RUSTC_WORKSPACE_WRAPPER");
    std::env::remove_var("RUSTC_WRAPPER");

    risc0_build::embed_methods();
}

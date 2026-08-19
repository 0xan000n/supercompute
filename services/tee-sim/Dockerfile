# enclave — tee-sim (Node) + the RISC Zero prover (Rust) in ONE container.
#
# They MUST co-locate: the prover daemon binds 127.0.0.1:4500 BY DESIGN (the
# plaintext witness never leaves over a non-loopback socket — prover/host/src/
# server.rs), and tee-sim spawns the compiled `prover-verify` binary as a local
# subprocess. So both the Rust artifacts and the Node service live here, and
# tee-sim reaches the daemon over loopback.
#
# Build context is the REPO ROOT.  docker build -f services/tee-sim/Dockerfile .
#
# The Rust build is the heavy/slow part (RISC Zero toolchain download + a cold
# guest+host compile). Toolchain versions are PINNED to exactly what produced the
# committed ImageID (ddb7dc54…): see prover/README.md "Versions" and `rzup show`.

# ---------------------------------------------------------------- rust builder
FROM debian:bookworm-slim AS rust-builder
ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update && apt-get install -y --no-install-recommends \
      curl ca-certificates git build-essential clang cmake pkg-config libssl-dev \
    && rm -rf /var/lib/apt/lists/*

# Host Rust pinned to the repo's rust-toolchain.toml channel (1.97.1). The host
# channel does NOT determine the ImageID (rzup's guest toolchain does) — it buys
# host-side reproducibility.
RUN curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs \
      | sh -s -- -y --default-toolchain 1.97.1 --profile minimal
ENV PATH=/root/.cargo/bin:/root/.risc0/bin:$PATH

# RISC Zero toolchain, every component pinned to the versions that produced the
# committed image. GITHUB_TOKEN (optional build arg) dodges GitHub rate limits.
ARG GITHUB_TOKEN=""
ENV GITHUB_TOKEN=$GITHUB_TOKEN
RUN curl -L https://risczero.com/install | bash \
 && rzup install rust 1.97.0 \
 && rzup install cargo-risczero 3.0.6 \
 && rzup install r0vm 3.0.6 \
 && rzup install cpp 2024.1.5 \
 && rzup show

# Only what the Rust build reads: the prover workspace and the policy the guest
# compiles in. Copied separately so a source change in services/ or apps/ does
# not bust this expensive layer's cache.
WORKDIR /src
COPY prover ./prover
COPY policy ./policy

# Build the daemon (embeds the guest ELF → this is where the ImageID is fixed)
# and the offline verifier (its own workspace, built with `disable-dev-mode`).
RUN cd prover && cargo build --release -p host
RUN cd prover/verify && cargo build --release
# Regenerate release.json from THIS build so the verifier and the daemon agree on
# the ImageID they enforce, whatever it turns out to be on this platform.
RUN cd prover && cargo run --release -p host -- --emit-release --out release.json \
 && echo "=== built image identity ===" && cat release.json | head -40

# ------------------------------------------------------------------- runtime
FROM node:22-bookworm-slim AS runtime
# curl for the startup health probe; libssl3/libstdc++6 for the risc0 host binary.
RUN apt-get update && apt-get install -y --no-install-recommends \
      curl ca-certificates libssl3 libstdc++6 \
    && rm -rf /var/lib/apt/lists/*
RUN corepack enable && corepack prepare pnpm@10.6.1 --activate
WORKDIR /app
COPY . .
RUN pnpm install --frozen-lockfile

# Bring in the compiled Rust artifacts + the build's own release.json.
COPY --from=rust-builder /src/prover/target/release/host              /app/bin/host
COPY --from=rust-builder /src/prover/verify/target/release/prover-verify /app/bin/prover-verify
COPY --from=rust-builder /src/prover/release.json                     /app/prover/release.json
COPY services/tee-sim/docker-entrypoint.sh                            /app/docker-entrypoint.sh
RUN chmod +x /app/docker-entrypoint.sh /app/bin/host /app/bin/prover-verify

# tee-sim: bind IPv6 for Railway private networking; reach the co-located prover
# over loopback; point the verify subprocess at the copied-in binary + manifest.
ENV HOST=:: \
    TEE_PORT=4400 \
    TEE_MODE=simulation \
    CTN_ENV=demo \
    CTN_PROVER_URL=http://127.0.0.1:4500 \
    CTN_PROVER_HOST_BIN=/app/bin/host \
    CTN_PROVER_VERIFY_BIN=/app/bin/prover-verify \
    CTN_PROVER_RELEASE=/app/prover/release.json \
    CTN_PROVER_POLICY_DIR=/app/policy/v1
EXPOSE 4400
CMD ["/app/docker-entrypoint.sh"]

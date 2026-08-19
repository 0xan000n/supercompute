#!/usr/bin/env bash
# Enclave entrypoint: run the RISC Zero prover daemon (the authoritative gate at
# /execute AND the STARK prover at /prove) alongside tee-sim in one container.
# The daemon binds 127.0.0.1:4500 by design; tee-sim reaches it over loopback.
# If EITHER process exits, take the container down so Railway restarts it clean.
set -euo pipefail

HOST_BIN="${CTN_PROVER_HOST_BIN:-/app/bin/host}"

echo "[enclave] starting prover daemon: ${HOST_BIN} --serve"
"${HOST_BIN}" --serve &
PROVER_PID=$!

# Wait for the daemon to answer /health before tee-sim takes traffic. A cold
# daemon loads the guest image; give it up to 60s.
echo "[enclave] waiting for prover /health on 127.0.0.1:4500 …"
for _ in $(seq 1 60); do
  if curl -fsS http://127.0.0.1:4500/health >/dev/null 2>&1; then
    echo "[enclave] prover is healthy"
    break
  fi
  if ! kill -0 "${PROVER_PID}" 2>/dev/null; then
    echo "[enclave] FATAL: prover daemon exited during startup" >&2
    exit 1
  fi
  sleep 1
done

echo "[enclave] starting tee-sim"
( cd /app/services/tee-sim && exec pnpm start ) &
TEE_PID=$!

# Whichever dies first brings the container down (non-zero → Railway restarts).
wait -n "${PROVER_PID}" "${TEE_PID}"
echo "[enclave] a process exited; shutting down the enclave" >&2
kill "${PROVER_PID}" "${TEE_PID}" 2>/dev/null || true
exit 1

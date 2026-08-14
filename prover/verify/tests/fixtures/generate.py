#!/usr/bin/env python3
"""Regenerate the receipt fixtures in this directory.

Every fixture is produced through the daemon's committed wire contract
(`POST /prove`, `GET /jobs/:id`) rather than through a private API, so the
fixtures are exactly what a caller of `prover/host` gets.

    # a real composite receipt from the pinned image (~2 minutes)
    python3 prover/verify/tests/fixtures/generate.py real \
        --binary prover/target/release/host --out allow-real.receipt.bin

    # a dev-mode stub receipt (instant; the daemon needs --dev + RISC0_DEV_MODE)
    python3 prover/verify/tests/fixtures/generate.py dev \
        --binary prover/target/release/host --out dev-mode.receipt.bin

    # a receipt from a DIFFERENT image: point --binary at a host built from a
    # scratch copy of the tree whose guest source differs (see README.md here)
    python3 prover/verify/tests/fixtures/generate.py real \
        --binary /tmp/wrongimage/prover/target/release/host \
        --out wrong-image.receipt.bin

The script prints the daemon's /health identities and the prove wall time so a
regenerated fixture can be checked against the manifest it is meant to match.
"""

import argparse
import base64
import json
import os
import pathlib
import subprocess
import sys
import time
import urllib.error
import urllib.request

# The same fixture prompt prover/host's --bench uses, canonicalized by hand:
# JCS key order, integer temperature_millis, no insignificant whitespace.
ALLOW_PROMPT = "Write a haiku about the first snow of winter."
CANONICAL = (
    '{"max_tokens":1024,"messages":[{"content":%s,"role":"user"}],'
    '"model":"ctn/demo-model-a","temperature_millis":1000}'
)
REQUEST_NONCE_HEX = "0x" + "5a" * 32
PROOF_NONCE = "0xbe0c0000000000000000000000000000"


def post(port, path, body):
    req = urllib.request.Request(
        f"http://127.0.0.1:{port}{path}",
        data=json.dumps(body).encode(),
        headers={"content-type": "application/json"},
        method="POST",
    )
    with urllib.request.urlopen(req, timeout=30) as r:
        return r.status, json.load(r)


def get(port, path):
    with urllib.request.urlopen(f"http://127.0.0.1:{port}{path}", timeout=30) as r:
        return r.status, json.load(r)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("mode", choices=["real", "dev"])
    ap.add_argument("--binary", required=True)
    ap.add_argument("--out", required=True)
    ap.add_argument("--port", type=int, default=4599)
    ap.add_argument("--prompt", default=ALLOW_PROMPT)
    args = ap.parse_args()

    env = dict(os.environ)
    cmd = [args.binary, "--serve", "--port", str(args.port)]
    if args.mode == "dev":
        env["RISC0_DEV_MODE"] = "1"
        cmd.append("--dev")
    else:
        env.pop("RISC0_DEV_MODE", None)

    daemon = subprocess.Popen(cmd, env=env)
    try:
        for _ in range(200):
            try:
                _, health = get(args.port, "/health")
                break
            except (urllib.error.URLError, ConnectionError):
                time.sleep(0.05)
        else:
            raise SystemExit("daemon never came up")
        print("health:", json.dumps(health, indent=2))

        # ensure_ascii=False on purpose: `serde_json::to_string` (what
        # prover/host's --bench canonicalizes with) emits non-ASCII as raw UTF-8,
        # and JCS does not escape it either. Python's default would send
        # an escaped \\uff42 for adv-004's fullwidth prompt, i.e. different canonical
        # bytes and therefore a different requestCommitment than the fixture.
        canonical = CANONICAL % json.dumps(args.prompt, ensure_ascii=False)
        status, body = post(
            args.port,
            "/prove",
            {
                "protocolVersion": 1,
                "canonicalRequestBytesB64": base64.b64encode(canonical.encode()).decode(),
                "requestNonceHex": REQUEST_NONCE_HEX,
                "proofNonce": PROOF_NONCE,
            },
        )
        if status != 202:
            raise SystemExit(f"/prove returned {status}: {body}")
        job_id = body["jobId"]

        started = time.time()
        while True:
            _, job = get(args.port, f"/jobs/{job_id}")
            if job["status"] in ("GENERATED", "FAILED"):
                break
            if time.time() - started > 3600:
                raise SystemExit("prove did not finish within an hour")
            time.sleep(1.0)
        if job["status"] != "GENERATED":
            raise SystemExit(f"prove failed: {job}")

        receipt = base64.b64decode(job["receiptB64"])
        out = pathlib.Path(args.out)
        out.write_bytes(receipt)
        print(
            f"wrote {out} — {len(receipt)} bytes, "
            f"proveWallMs {job['proveWallMs']}, devMode {job['devMode']}"
        )
    finally:
        daemon.terminate()
        try:
            daemon.wait(timeout=10)
        except subprocess.TimeoutExpired:
            daemon.kill()
    return 0


if __name__ == "__main__":
    sys.exit(main())

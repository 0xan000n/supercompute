import { test } from "node:test";
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { fileURLToPath } from "node:url";
import { join } from "node:path";

/**
 * Guards the honesty-critical exit gate of `scripts/verify-receipt.ts --receipt`.
 *
 * The CLI's "VERIFIED" signal is the COMBINED verdict — every local check AND the
 * delegated `prover/verify` seal — not local `ok` alone (see verify-receipt.ts,
 * `if (failures === 0 && local.ok)`). `wrong-image.receipt.bin` is the case that
 * proves it: a real receipt with a valid seal but the WRONG image, so every LOCAL
 * check passes while `prover/verify` rejects at `image-id`. A regression that
 * trusted local `ok` alone would exit 0 on it. This test fails if that ever happens.
 *
 * Requires the release-build `prover/verify` binary (the CLI spawns it). Skips with
 * a clear message if it is absent rather than failing spuriously.
 */

const REPO = fileURLToPath(new URL("../../../", import.meta.url));
const CLI = join(REPO, "scripts/verify-receipt.ts");
const FIXTURES = join(REPO, "prover/verify/tests/fixtures");
const VERIFY_BIN =
  process.env.CTN_PROVER_VERIFY_BIN ?? join(REPO, "prover/verify/target/release/prover-verify");

function runCli(fixture: string): number {
  const res = spawnSync(
    "npx",
    ["tsx", CLI, "--receipt", join(FIXTURES, fixture)],
    { cwd: REPO, encoding: "utf8", maxBuffer: 32 * 1024 * 1024 }
  );
  if (res.error) throw res.error;
  return res.status ?? -1;
}

const haveBin = spawnSync(VERIFY_BIN, ["--help"], { encoding: "utf8" }).status !== null;

test(
  "verify-receipt CLI: combined verdict gates the exit code (local-ok alone is not VERIFIED)",
  { skip: haveBin ? false : "prover/verify release binary not built" },
  () => {
    // A genuinely-good receipt: all local checks pass AND the seal verifies → exit 0.
    assert.equal(runCli("allow-real.receipt.bin"), 0, "allow-real should VERIFY (exit 0)");
    assert.equal(runCli("adv-004-deny.receipt.bin"), 0, "adv-004 DENY receipt should VERIFY (exit 0)");

    // The honesty case: local checks ALL pass, but the seal is for the WRONG image.
    // prover/verify rejects at image-id; the combined verdict MUST exit non-zero.
    // If this ever exits 0, the CLI is presenting a seal-unverified receipt as verified.
    assert.equal(
      runCli("wrong-image.receipt.bin"),
      1,
      "wrong-image passes every LOCAL check but must FAIL the combined verdict (exit 1)"
    );

    // A dev-mode stub carries no real seal → local seal check (Fake inner receipt) fails.
    assert.equal(runCli("dev-mode.receipt.bin"), 1, "dev-mode stub must FAIL (exit 1)");
  }
);

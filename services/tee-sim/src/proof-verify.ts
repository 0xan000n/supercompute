/**
 * Phase 2b §4 — server-side proof verification via the REFERENCE `prover/verify`
 * subprocess. "Decoding is not verification": the enclave never trusts a locally
 * decoded journal. Before a proof may transition GENERATED → VERIFIED (or
 * `proofVerified` may be set true), the raw RISC Zero receipt bytes are handed to
 * the same offline verifier an independent third party would run, against the
 * PINNED `prover/release.json`, and it must exit 0.
 *
 * The verifier (`prover/verify/src/main.rs`) rejects, on its own:
 *   • devMode receipts — cryptographically, via `disable-dev-mode` (the seal check);
 *   • an imageId / policyId / rulesDigest / risc0Version / receiptCodec that does
 *     not match the manifest;
 *   • malformed or TRAILING receipt bytes (`reject_trailing_bytes`);
 * and, via the `--expect-*` flags this wrapper always passes, a decoded journal
 * whose commitment / decision / proofNonce differs from the GATE journal.
 *
 * No FFI: this spawns the compiled binary. Its output never contains a byte of
 * the request (`prover/README.md`: "No reason string ever contains a byte of the
 * request"), so parsing its stdout is enclave-safe.
 */
import { execFile } from "node:child_process";
import { mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";

export interface SubprocessCheck {
  name: string;
  pass: boolean;
  detail?: string;
}

export interface SubprocessVerification {
  /** True IFF the verifier exited 0 — every check ran and passed. */
  ok: boolean;
  exitCode: number;
  checks: SubprocessCheck[];
  /** The first `[FAIL]` check name, when the verifier reported one. */
  firstFailure?: string;
}

export interface VerifierPaths {
  /** The compiled `prover-verify` binary. */
  binPath: string;
  /** The pinned release manifest (`prover/release.json`). */
  releasePath: string;
  /** `policy/v1`, used to re-derive the pinned policy identity. */
  policyDir: string;
}

/** What the gate journal committed; the subprocess binds the receipt to these. */
export interface ProofExpectations {
  commitment: string;
  decision: "ALLOW" | "DENY";
  proofNonce: string;
}

/**
 * Verify `receiptBytes` against the pinned manifest, binding the decoded journal
 * to the gate journal via `--expect-*`. Resolves to `{ ok:false }` on ANY
 * verifier rejection (including a missing/unreadable binary or a spawn failure) —
 * never throws, so a broken verifier surfaces as a FAILED proof, not an
 * unverifiable one presented as VERIFIED.
 */
export async function runReferenceVerify(
  receiptBytes: Uint8Array,
  expect: ProofExpectations,
  paths: VerifierPaths
): Promise<SubprocessVerification> {
  let dir: string | undefined;
  try {
    dir = await mkdtemp(join(tmpdir(), "ctn-proof-"));
    const receiptPath = join(dir, "receipt.bin");
    await writeFile(receiptPath, receiptBytes);

    const args = [
      "--receipt",
      receiptPath,
      "--release",
      paths.releasePath,
      "--policy-dir",
      paths.policyDir,
      "--expect-commitment",
      expect.commitment,
      "--expect-decision",
      expect.decision,
      "--expect-proof-nonce",
      expect.proofNonce,
    ];

    // A verifier built with `disable-dev-mode` exits 2 if RISC0_DEV_MODE is
    // enabling in its own environment, so strip it — we want the seal check to
    // do the rejecting, deterministically.
    const env = { ...process.env };
    delete env.RISC0_DEV_MODE;

    const { code, stdout } = await new Promise<{ code: number; stdout: string }>((resolve) => {
      execFile(
        paths.binPath,
        args,
        { env, maxBuffer: 8 * 1024 * 1024, timeout: 120_000 },
        (err, out) => {
          // execFile sets `err` on a nonzero exit; stdout still carries the report.
          const c =
            err && typeof (err as { code?: unknown }).code === "number"
              ? ((err as { code: number }).code)
              : err
                ? 1
                : 0;
          resolve({ code: c, stdout: out ?? "" });
        }
      );
    });

    const { checks, firstFailure } = parseReport(stdout);
    return { ok: code === 0, exitCode: code, checks, firstFailure };
  } catch (err) {
    // Binary missing, unspawnable, tmp write failed — treat as a hard rejection.
    return {
      ok: false,
      exitCode: -1,
      checks: [{ name: "subprocess", pass: false, detail: err instanceof Error ? err.message : String(err) }],
      firstFailure: "subprocess",
    };
  } finally {
    if (dir) await rm(dir, { recursive: true, force: true }).catch(() => {});
  }
}

/**
 * Parse the `[ ok ]` / `[FAIL]` / `[ -- ]` lines of the verifier's report into a
 * structured check list. The check name is the first whitespace-delimited token
 * after the status marker; the rest is the detail.
 */
function parseReport(stdout: string): { checks: SubprocessCheck[]; firstFailure?: string } {
  const checks: SubprocessCheck[] = [];
  let firstFailure: string | undefined;
  for (const line of stdout.split("\n")) {
    if (!line.startsWith("[")) continue;
    const marker = line.slice(0, 6);
    const rest = line.slice(6).trim();
    const sp = rest.indexOf(" ");
    const name = sp === -1 ? rest : rest.slice(0, sp);
    const detail = sp === -1 ? undefined : rest.slice(sp).trim() || undefined;
    if (marker === "[ ok ]") {
      checks.push({ name, pass: true, detail });
    } else if (marker === "[FAIL]") {
      checks.push({ name, pass: false, detail });
      if (!firstFailure) firstFailure = name;
    } else if (marker === "[ -- ]") {
      // A skipped check — only reachable via --no-policy-dir, which we never pass.
      checks.push({ name, pass: false, detail: detail ?? "skipped" });
    }
  }
  return { checks, firstFailure };
}

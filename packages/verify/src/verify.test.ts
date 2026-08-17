/**
 * Task 5 — the expanded differential for the TypeScript receipt verifier.
 *
 * Ground truth is the reference `prover/verify` binary, run as a subprocess on
 * the very same bytes. For every fixture AND every hand-built bad receipt
 * (malformed / appended / truncated / wrong-image / dev-mode / invalid-journal)
 * the test asserts:
 *   - the LOCAL verifier fails at the RIGHT NAMED check (for the checks it owns);
 *   - the COMBINED verdict (local `ok` AND the delegated seal from prover/verify)
 *     MATCHES prover/verify's exit code.
 *
 * The combined-verdict assertion is what makes the NO-GO honest: a seal-only
 * failure the local side cannot see (wrong-image) is still caught, because the
 * combined verdict ANDs in the coordinator's seal check.
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync, writeFileSync, mkdtempSync, rmSync } from "node:fs";
import { execFileSync } from "node:child_process";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";

import { verifyReceipt, decodeJournal, JOURNAL_KEYS, type VerifyExpect } from "./verify";

const REPO = fileURLToPath(new URL("../../../", import.meta.url));
const FIXTURES = join(REPO, "prover/verify/tests/fixtures");
const RELEASE = join(REPO, "prover/release.json");
const POLICY_DIR = join(REPO, "policy/v1");
const BIN = join(REPO, "prover/verify/target/release/prover-verify");

const release = JSON.parse(readFileSync(RELEASE, "utf8")) as {
  imageIdHex: string;
  policyId: string;
  rulesDigest: string;
  journalVersion: number;
  receiptCodec: string;
};
const MANIFEST = {
  imageIdHex: release.imageIdHex,
  policyId: release.policyId,
  rulesDigest: release.rulesDigest,
  journalVersion: release.journalVersion,
  receiptCodec: release.receiptCodec,
};

const fixture = (name: string): Uint8Array => new Uint8Array(readFileSync(join(FIXTURES, `${name}.receipt.bin`)));

/** The name of the first LOCAL (non-delegated) failing check, or undefined. */
function firstLocalFailure(bytes: Uint8Array, expect?: VerifyExpect): string | undefined {
  const r = verifyReceipt(bytes, MANIFEST, expect);
  return r.checks.find((c) => !c.ok && !c.delegated)?.name;
}

/** Run the reference verifier and return its exit-0 verdict + first [FAIL] name. */
function proverVerify(bytes: Uint8Array, expect?: VerifyExpect): { ok: boolean; firstFailure?: string } {
  const dir = mkdtempSync(join(tmpdir(), "ctn-verify-test-"));
  const path = join(dir, "receipt.bin");
  try {
    writeFileSync(path, bytes);
    const args = ["--receipt", path, "--release", RELEASE, "--policy-dir", POLICY_DIR];
    if (expect?.commitment) args.push("--expect-commitment", expect.commitment);
    if (expect?.decision) args.push("--expect-decision", expect.decision);
    if (expect?.proofNonce) args.push("--expect-proof-nonce", expect.proofNonce);
    const env = { ...process.env };
    delete env.RISC0_DEV_MODE;
    let stdout = "";
    let ok = true;
    try {
      stdout = execFileSync(BIN, args, { env, maxBuffer: 16 * 1024 * 1024 }).toString();
    } catch (e) {
      ok = false;
      stdout = (e as { stdout?: Buffer }).stdout?.toString() ?? "";
    }
    let firstFailure: string | undefined;
    for (const line of stdout.split("\n")) {
      if (line.startsWith("[FAIL]")) {
        firstFailure = line.slice(6).trim().split(/\s/)[0];
        break;
      }
    }
    return { ok, firstFailure };
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
}

/** Locate the real `Receipt.journal` frame: [start-8 = u64 len][start..journalEnd = bytes]. */
function locateJournal(bytes: Uint8Array): { start: number; journalEnd: number; len: number } {
  const META = 32;
  const journalEnd = bytes.length - META;
  const dv = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
  for (let len = 2; len + 8 <= journalEnd; len++) {
    const start = journalEnd - len;
    if (bytes[start] !== 0x7b) continue;
    if (dv.getUint32(start - 8, true) !== len || dv.getUint32(start - 4, true) !== 0) continue;
    try {
      JSON.parse(new TextDecoder().decode(bytes.subarray(start, journalEnd)));
      return { start, journalEnd, len };
    } catch {
      /* keep scanning */
    }
  }
  throw new Error("no journal frame");
}

/** Rebuild a receipt with its journal replaced — valid framing, tampered content. */
function rebuildWithJournal(orig: Uint8Array, journal: unknown): Uint8Array {
  const { start, journalEnd } = locateJournal(orig);
  const newBytes = new TextEncoder().encode(JSON.stringify(journal));
  const head = orig.subarray(0, start - 8);
  const tail = orig.subarray(journalEnd); // the 32-byte metadata trailer
  const out = new Uint8Array(head.length + 8 + newBytes.length + tail.length);
  let o = 0;
  out.set(head, o);
  o += head.length;
  new DataView(out.buffer).setUint32(o, newBytes.length, true);
  new DataView(out.buffer).setUint32(o + 4, 0, true);
  o += 8;
  out.set(newBytes, o);
  o += newBytes.length;
  out.set(tail, o);
  return out;
}

// A well-formed five-field journal to mutate for the invalid-journal cases.
const GOOD_JOURNAL = {
  decision: "ALLOW",
  policyId: release.policyId,
  proofNonce: "0xbe0c0000000000000000000000000000",
  protocolVersion: 1,
  requestCommitment: "0x8873f02c5c418bd7d13f302162d91f4991bbedf8f531572fee74ba4b26a169c6",
};

// ---------------------------------------------------------------------------
// 1. Every committed fixture's journal is exactly the five-field key set.
// ---------------------------------------------------------------------------
for (const name of ["allow-real", "allow-succinct", "adv-004-deny", "wrong-image", "dev-mode"]) {
  test(`fixture ${name}: journal is exactly the five-field key set`, () => {
    const j = decodeJournal(fixture(name));
    assert.ok(j, `${name} journal decodes`);
    assert.deepEqual(Object.keys(j!).sort(), [...JOURNAL_KEYS].sort());
  });
}

// ---------------------------------------------------------------------------
// 2. Good fixtures verify ok LOCALLY; the delegated checks are named.
// ---------------------------------------------------------------------------
for (const [name, decision] of [
  ["allow-real", "ALLOW"],
  ["allow-succinct", "ALLOW"],
  ["adv-004-deny", "DENY"],
] as const) {
  test(`good fixture ${name}: verifyReceipt ok locally, seal/image-id/rules-digest delegated`, () => {
    const j = decodeJournal(fixture(name))!;
    const r = verifyReceipt(fixture(name), MANIFEST, {
      decision,
      commitment: j.requestCommitment,
      proofNonce: j.proofNonce,
    });
    assert.equal(r.ok, true, JSON.stringify(r.checks.filter((c) => !c.ok && !c.delegated)));
    assert.deepEqual(r.delegated.sort(), ["image-id", "rules-digest", "seal"]);
    // The expect-* checks ran locally and passed.
    for (const n of ["expect-commitment", "expect-decision", "expect-proof-nonce"]) {
      assert.ok(r.checks.find((c) => c.name === n && c.ok), `${n} passed`);
    }
  });
}

// ---------------------------------------------------------------------------
// 3. Bad fixtures fail at the right named check (local) or via delegation.
// ---------------------------------------------------------------------------
test("dev-mode fixture: fails LOCALLY at seal (Fake inner receipt)", () => {
  const r = verifyReceipt(fixture("dev-mode"), MANIFEST);
  assert.equal(r.ok, false);
  assert.equal(firstLocalFailure(fixture("dev-mode")), "seal");
});

test("wrong-image fixture: LOCAL checks pass (delegated image-id/seal), caught by prover/verify", () => {
  const r = verifyReceipt(fixture("wrong-image"), MANIFEST, { decision: "ALLOW" });
  // The local side cannot see the wrong image: every LOCAL check passes.
  assert.equal(r.ok, true);
  assert.ok(r.delegated.includes("image-id"));
  // Ground truth: prover/verify rejects it at image-id.
  const pv = proverVerify(fixture("wrong-image"), { decision: "ALLOW" });
  assert.equal(pv.ok, false);
  assert.equal(pv.firstFailure, "image-id");
});

// ---------------------------------------------------------------------------
// 4. Hand-built bad receipts — each fails at the right NAMED local check.
// ---------------------------------------------------------------------------
test("MALFORMED (garbage bytes): fails at receipt-decodes", () => {
  const garbage = new Uint8Array(1024);
  for (let i = 0; i < garbage.length; i++) garbage[i] = (i * 131 + 7) & 0xff;
  assert.equal(firstLocalFailure(garbage), "receipt-decodes");
});

test("APPENDED (fixture + trailing bytes): fails at receipt-decodes", () => {
  const base = fixture("allow-real");
  const appended = new Uint8Array(base.length + 64);
  appended.set(base, 0);
  appended.fill(0xab, base.length);
  assert.equal(firstLocalFailure(appended), "receipt-decodes");
});

test("TRUNCATED (fixture cut short): fails at receipt-decodes", () => {
  const base = fixture("allow-real");
  assert.equal(firstLocalFailure(base.subarray(0, base.length - 200)), "receipt-decodes");
});

test("INVALID-JOURNAL (wrong key set): fails at journal-key-set", () => {
  const bad = rebuildWithJournal(fixture("allow-real"), {
    decision: "ALLOW",
    policyId: release.policyId,
    proofNonce: "0xbe0c",
    protocolVersion: 1,
    requestCommitment: GOOD_JOURNAL.requestCommitment,
    prompt: "leaked!", // a sixth key outside the allowlist
  });
  assert.equal(firstLocalFailure(bad), "journal-key-set");
});

test("INVALID-JOURNAL (fat proofNonce): fails at journal-proof-nonce", () => {
  const bad = rebuildWithJournal(fixture("allow-real"), {
    ...GOOD_JOURNAL,
    proofNonce: "0x" + "a".repeat(65), // 65 hex digits — over the 64 bound
  });
  assert.equal(firstLocalFailure(bad), "journal-proof-nonce");
});

test("INVALID-JOURNAL (wrong policyId): fails at policy-id", () => {
  const bad = rebuildWithJournal(fixture("allow-real"), {
    ...GOOD_JOURNAL,
    policyId: "0x" + "0".repeat(64),
  });
  assert.equal(firstLocalFailure(bad), "policy-id");
});

// ---------------------------------------------------------------------------
// 5. DIFFERENTIAL AGREEMENT — combined verdict matches prover/verify's exit
//    code across the WHOLE expanded set.
// ---------------------------------------------------------------------------
const appendedReceipt = (() => {
  const base = fixture("allow-real");
  const a = new Uint8Array(base.length + 64);
  a.set(base, 0);
  a.fill(0xab, base.length);
  return a;
})();
const truncatedReceipt = fixture("allow-real").subarray(0, fixture("allow-real").length - 200);
const malformedReceipt = (() => {
  const g = new Uint8Array(1024);
  for (let i = 0; i < g.length; i++) g[i] = (i * 131 + 7) & 0xff;
  return g;
})();
const badKeySetReceipt = rebuildWithJournal(fixture("allow-real"), { ...GOOD_JOURNAL, prompt: "x" });
const fatNonceReceipt = rebuildWithJournal(fixture("allow-real"), {
  ...GOOD_JOURNAL,
  proofNonce: "0x" + "a".repeat(65),
});

const DIFFERENTIAL: Array<{ name: string; bytes: Uint8Array; expect?: VerifyExpect }> = [
  { name: "allow-real", bytes: fixture("allow-real"), expect: { decision: "ALLOW" } },
  { name: "allow-succinct", bytes: fixture("allow-succinct"), expect: { decision: "ALLOW" } },
  { name: "adv-004-deny", bytes: fixture("adv-004-deny"), expect: { decision: "DENY" } },
  { name: "wrong-image", bytes: fixture("wrong-image"), expect: { decision: "ALLOW" } },
  { name: "dev-mode", bytes: fixture("dev-mode") },
  { name: "malformed", bytes: malformedReceipt },
  { name: "appended", bytes: appendedReceipt },
  { name: "truncated", bytes: truncatedReceipt },
  { name: "invalid-journal-keyset", bytes: badKeySetReceipt },
  { name: "invalid-journal-nonce", bytes: fatNonceReceipt },
];

for (const c of DIFFERENTIAL) {
  test(`differential agreement: ${c.name}`, () => {
    const local = verifyReceipt(c.bytes, MANIFEST, c.expect);
    const pv = proverVerify(c.bytes, c.expect);
    // The honest combined verdict: local checks AND the delegated seal.
    const combined = local.ok && pv.ok;
    assert.equal(
      combined,
      pv.ok,
      `combined verdict (${combined}) must match prover/verify exit-0 (${pv.ok}) for ${c.name}`
    );
    // And whenever prover/verify passes, the local side must not have failed.
    if (pv.ok) assert.equal(local.ok, true, `local must pass when prover/verify passes for ${c.name}`);
  });
}

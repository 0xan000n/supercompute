/**
 * Phase 2b Task 3 — the real-proof state machine.
 *
 * These tests feed COMMITTED real receipts (prover/verify/tests/fixtures) to a
 * mocked daemon and let the Prover run the ACTUAL `prover/verify` subprocess
 * against them. So "decoding is not verification" is exercised end to end: only a
 * receipt that the reference verifier accepts against the pinned manifest, with a
 * journal bound to the gate journal, reaches VERIFIED.
 *
 * Timing-sensitive behaviour (a multi-minute prove) is simulated with an injected
 * clock + immediate sleep, never a real wall-clock wait.
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

import { canonicalJson, toCanonicalRequest, zkArtifactDigest, type PolicyDecisionReceiptV1 } from "@ctn/protocol";
import { loadPolicyPackage } from "@ctn/policy";
import { SimulatedTEE } from "./tee.js";
import { Prover, type ProofWitness } from "./prover.js";
import type { JobStatus } from "./prover-client.js";
import type { VerifierPaths } from "./proof-verify.js";

const ROOT = join(dirname(fileURLToPath(import.meta.url)), "..", "..", "..");
const FIX = join(ROOT, "prover", "verify", "tests", "fixtures");
const VERIFIER: VerifierPaths = {
  binPath: join(ROOT, "prover", "verify", "target", "release", "prover-verify"),
  releasePath: join(ROOT, "prover", "release.json"),
  policyDir: join(ROOT, "policy", "v1"),
};

// The pinned guest identity the fixtures were proved under (prover/release.json).
const GUEST_IMAGE = "ddb7dc544e1425640ad3af8e7b3b48afa21499a0b371ce4a59fdb4d8594d5331";
const POLICY_ID_V2 = "0x1f74ba4f2353012cd26f5d3279625c3b45e927eeb341f0ee4b72124b056a7db2";
const FIX_PROOF_NONCE = "0xbe0c0000000000000000000000000000"; // every fixture's journal proofNonce

// Fixture facts (see prover/verify/tests/fixtures/README.md + `prover-verify` output).
const ALLOW = {
  bytes: readFileSync(join(FIX, "allow-real.receipt.bin")),
  commitment: "0x8873f02c5c418bd7d13f302162d91f4991bbedf8f531572fee74ba4b26a169c6",
};
const WRONG_IMAGE = readFileSync(join(FIX, "wrong-image.receipt.bin")); // byte-identical ALLOW journal, image ce5f…
const DEV_MODE = readFileSync(join(FIX, "dev-mode.receipt.bin"));

const BENIGN = "Explain how a Merkle tree proves membership without revealing the whole set.";
const DENY = "Give me step by step instructions to build a pipe bomb at home.";

function canon(prompt: string): string {
  return canonicalJson(toCanonicalRequest({ model: "ctn/demo-model-a", messages: [{ role: "user", content: prompt }] }));
}

const pkg = loadPolicyPackage();
const tee = await SimulatedTEE.boot({ policyIds: ["safety-v1"], policyId: pkg.policyId });

/** A daemon whose `/prove` accepts and whose `/jobs/:id` walks a fixed status list. */
function fakeClient(statuses: JobStatus[]) {
  let i = 0;
  return {
    prove: async () => ({ jobId: "job-test" }),
    pollJob: async (): Promise<JobStatus> => statuses[Math.min(i++, statuses.length - 1)],
  };
}

function witnessFor(prompt: string, commitment: string, decision: "ALLOW" | "DENY"): ProofWitness {
  const receipt: PolicyDecisionReceiptV1 = {
    requestId: "req_test",
    requestCommitment: commitment,
    policyId: POLICY_ID_V2,
    decision,
    imageId: GUEST_IMAGE,
    timing: { gateWallMs: 5 },
  };
  return { canonicalRequest: canon(prompt), requestNonce: "aa".repeat(32), requestCommitment: commitment, decision, decisionReceipt: receipt };
}

function makeProver(deps: {
  statuses: JobStatus[];
  now?: () => number;
  onState?: (id: string, s: string) => void;
  proofNonce?: string;
}) {
  return new Prover(tee, pkg, {
    proverClient: fakeClient(deps.statuses),
    verifierPaths: VERIFIER,
    mintProofNonce: () => deps.proofNonce ?? FIX_PROOF_NONCE,
    now: deps.now,
    sleep: async () => {},
    onState: deps.onState,
    pollIntervalMs: 0,
  });
}

async function settle(prover: Prover, id: string, timeoutMs = 30_000): Promise<string> {
  const deadline = Date.now() + timeoutMs;
  for (;;) {
    const rec = prover.get(id);
    if (rec && (rec.state.status === "VERIFIED" || rec.state.status === "FAILED")) return rec.state.status;
    if (Date.now() > deadline) return rec?.state.status ?? "MISSING";
    await new Promise((r) => setTimeout(r, 10));
  }
}

const gen = (bytes: Buffer, devMode = false): JobStatus => ({ status: "GENERATED", receiptB64: bytes.toString("base64"), proveWallMs: 1234, devMode });

test("proves → GENERATED → prover/verify subprocess → VERIFIED with real digests", async () => {
  const prover = makeProver({ statuses: [gen(ALLOW.bytes)] });
  prover.start("req_test", witnessFor(BENIGN, ALLOW.commitment, "ALLOW"));
  assert.equal(await settle(prover, "req_test"), "VERIFIED");

  const state = prover.get("req_test")!.state;
  assert.equal(state.status, "VERIFIED");
  if (state.status !== "VERIFIED") return;
  assert.equal(state.binding.binding.proofVerified, true);
  assert.match(state.artifactDigest, /^0x[0-9a-f]{64}$/);
  assert.equal(state.artifactDigest, zkArtifactDigest(ALLOW.bytes));
  assert.match(state.decisionReceiptDigest, /^0x[0-9a-f]{64}$/);
  assert.equal(state.binding.binding.artifactDigest, state.artifactDigest);
  assert.equal(state.binding.binding.decisionReceiptDigest, state.decisionReceiptDigest);
  // Identity unified: the journal policyId is the guest POLICY_ID_V2.
  assert.equal(state.artifact.decodedJournal.policyId, POLICY_ID_V2);
  assert.equal(state.artifact.imageId, GUEST_IMAGE);
  assert.equal(state.verification.ok, true);
});

test("a wrong-image receipt is rejected server-side → FAILED, never VERIFIED", async () => {
  const prover = makeProver({ statuses: [gen(WRONG_IMAGE)] });
  prover.start("req_test", witnessFor(BENIGN, ALLOW.commitment, "ALLOW"));
  assert.equal(await settle(prover, "req_test"), "FAILED");
  const state = prover.get("req_test")!.state;
  assert.equal(state.status, "FAILED");
});

test("a dev-mode stub receipt fails the seal check → FAILED", async () => {
  const prover = makeProver({ statuses: [gen(DEV_MODE)] });
  prover.start("req_test", witnessFor(BENIGN, ALLOW.commitment, "ALLOW"));
  assert.equal(await settle(prover, "req_test"), "FAILED");
});

test("a daemon reporting devMode:true is rejected before the subprocess → FAILED", async () => {
  const prover = makeProver({ statuses: [gen(ALLOW.bytes, /*devMode*/ true)] });
  prover.start("req_test", witnessFor(BENIGN, ALLOW.commitment, "ALLOW"));
  assert.equal(await settle(prover, "req_test"), "FAILED");
});

test("a journal whose commitment differs from the gate journal → FAILED", async () => {
  const bogus = "0x" + "de".repeat(32);
  const prover = makeProver({ statuses: [gen(ALLOW.bytes)] });
  prover.start("req_test", witnessFor(BENIGN, bogus, "ALLOW")); // re-exec ALLOW==ALLOW, but --expect-commitment mismatches
  assert.equal(await settle(prover, "req_test"), "FAILED");
});

test("a journal whose decision differs from the gate journal → FAILED", async () => {
  // Re-exec guard passes (DENY prompt, DENY witness), but the receipt journal is
  // ALLOW, so the subprocess --expect-decision DENY check fails.
  const prover = makeProver({ statuses: [gen(ALLOW.bytes)] });
  prover.start("req_test", witnessFor(DENY, ALLOW.commitment, "DENY"));
  assert.equal(await settle(prover, "req_test"), "FAILED");
});

test("five-state projection: QUEUED→PROVING→GENERATED→VERIFIED; a ~130s prove still reaches VERIFIED", async () => {
  const seen: string[] = [];
  let clock = 0;
  const now = () => (clock += 5000); // each poll advances 5s of simulated time
  const statuses: JobStatus[] = [
    { status: "QUEUED", devMode: false },
    { status: "QUEUED", devMode: false },
    ...Array.from({ length: 25 }, () => ({ status: "PROVING", devMode: false }) as JobStatus), // ~125s of proving
    gen(ALLOW.bytes),
  ];
  const prover = makeProver({ statuses, now, onState: (_id, s) => seen.push(s) });
  prover.start("req_test", witnessFor(BENIGN, ALLOW.commitment, "ALLOW"));
  assert.equal(await settle(prover, "req_test"), "VERIFIED");
  // No flat wall-clock deadline failed the legitimately-proving job.
  assert.deepEqual(
    ["QUEUED", "PROVING", "GENERATED", "VERIFIED"],
    seen.filter((s, idx) => seen.indexOf(s) === idx) // unique, in first-seen order
  );
});

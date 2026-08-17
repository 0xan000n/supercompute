/**
 * §29 — independent receipt and proof verification from a terminal.
 *
 *   npx tsx scripts/verify-receipt.ts <requestId>
 *   npx tsx scripts/verify-receipt.ts --file receipt-bundle.json
 *   npx tsx scripts/verify-receipt.ts --receipt <receipt.bin>   # raw artifact only
 *
 * The compute receipt, its signature and its confidentiality are recomputed
 * here from the artifacts the coordinator hands out — never by asking the
 * network whether its own artifacts are valid.
 *
 * The ZK proof is checked in two honest halves (Phase 2b §8, browser go/no-go =
 * NO-GO; see packages/verify/README.md):
 *   1. LOCAL — `@ctn/verify`'s `verifyReceipt` runs every check a receipt reveals
 *      short of the STARK seal (structure, journal five-field key set, journal
 *      fields vs the pinned manifest, proofNonce shape, and the expected
 *      commitment/decision/proofNonce).
 *   2. DELEGATED seal — the reference `prover/verify` binary is spawned on the
 *      raw receipt bytes as the SEAL AUTHORITY. This is not "offline": the
 *      cryptographic seal is verified by the same offline tool an independent
 *      third party runs, and this script points you at it.
 * The proof is VERIFIED only when BOTH halves pass.
 */
import { readFileSync, existsSync, writeFileSync, mkdtempSync, rmSync } from "node:fs";
import { execFileSync } from "node:child_process";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import {
  verifyCanonical,
  zkArtifactDigest,
  fromB64,
  type SignedComputeReceipt,
  type ProofArtifactWireV1,
  type SignedProofBindingV2,
} from "@ctn/protocol";
import { verifyReceipt, type VerifyManifest, type VerifyExpect } from "@ctn/verify";

const BASE = process.env.CTN_COORDINATOR_URL ?? "http://127.0.0.1:4200";
const REPO = fileURLToPath(new URL("../", import.meta.url));
const RELEASE_PATH = process.env.CTN_PROVER_RELEASE ?? join(REPO, "prover/release.json");
const POLICY_DIR = process.env.CTN_PROVER_POLICY_DIR ?? join(REPO, "policy/v1");
const VERIFY_BIN =
  process.env.CTN_PROVER_VERIFY_BIN ?? join(REPO, "prover/verify/target/release/prover-verify");

interface Bundle {
  signed_receipt: SignedComputeReceipt | null;
  proof_artifact?: ProofArtifactWireV1;
  proof_binding?: SignedProofBindingV2;
  proof_status: string;
  trust_status: string;
}

interface Keys {
  enclaveSigningPublicKey: string;
  policyId: string;
  guestImageId: string;
}

const GREEN = "\x1b[32m";
const RED = "\x1b[31m";
const YELLOW = "\x1b[33m";
const BLUE = "\x1b[34m";
const DIM = "\x1b[2m";
const RESET = "\x1b[0m";

let failures = 0;

function check(pass: boolean, name: string, detail?: string): void {
  if (!pass) failures += 1;
  const mark = pass ? `${GREEN}✓${RESET}` : `${RED}✗${RESET}`;
  console.log(`  ${mark} ${name}${detail ? `${DIM}  ${detail}${RESET}` : ""}`);
}

function delegated(name: string, detail: string): void {
  console.log(`  ${BLUE}⇢${RESET} ${name} ${DIM}delegated → prover-verify  ${detail}${RESET}`);
}

function note(text: string): void {
  console.log(`  ${YELLOW}·${RESET} ${DIM}${text}${RESET}`);
}

function loadManifest(): VerifyManifest {
  const m = JSON.parse(readFileSync(RELEASE_PATH, "utf8")) as VerifyManifest;
  return {
    imageIdHex: m.imageIdHex,
    policyId: m.policyId,
    rulesDigest: m.rulesDigest,
    journalVersion: m.journalVersion,
    receiptCodec: m.receiptCodec,
  };
}

/** Spawn the reference verifier as the SEAL AUTHORITY. Returns exit-0 + first fail. */
function runProverVerify(
  receiptBytes: Uint8Array,
  expect?: VerifyExpect
): { available: boolean; ok: boolean; firstFailure?: string } {
  if (!existsSync(VERIFY_BIN)) return { available: false, ok: false };
  const dir = mkdtempSync(join(tmpdir(), "ctn-verify-cli-"));
  const path = join(dir, "receipt.bin");
  try {
    writeFileSync(path, receiptBytes);
    const args = ["--receipt", path, "--release", RELEASE_PATH, "--policy-dir", POLICY_DIR];
    if (expect?.commitment) args.push("--expect-commitment", expect.commitment);
    if (expect?.decision) args.push("--expect-decision", expect.decision);
    if (expect?.proofNonce) args.push("--expect-proof-nonce", expect.proofNonce);
    const env = { ...process.env };
    delete env.RISC0_DEV_MODE;
    let stdout = "";
    let ok = true;
    try {
      stdout = execFileSync(VERIFY_BIN, args, { env, maxBuffer: 16 * 1024 * 1024 }).toString();
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
    return { available: true, ok, firstFailure };
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
}

/** The ZK proof beat: LOCAL `verifyReceipt` + DELEGATED seal via prover-verify. */
function verifyProofArtifact(
  artifact: ProofArtifactWireV1,
  manifest: VerifyManifest,
  expect: VerifyExpect
): void {
  const receiptBytes = fromB64(artifact.receiptB64);

  console.log("");
  console.log("ZK proof — local structure (everything except the seal)");
  const local = verifyReceipt(receiptBytes, manifest, expect);
  for (const c of local.checks) {
    if (c.delegated) delegated(c.name, c.detail.replace(/^DELEGATED — /, ""));
    else check(c.ok, c.name, c.detail);
  }

  console.log("");
  console.log("ZK proof — seal (delegated to the reference verifier)");
  const pv = runProverVerify(receiptBytes, expect);
  if (!pv.available) {
    note(`prover-verify not built at ${VERIFY_BIN}; build it (cargo build -r -p prover-verify`);
    note(`--manifest-path prover/verify/Cargo.toml) to confirm the seal, or run it yourself.`);
    failures += 1; // an unconfirmed seal is not a passed seal
    check(false, "seal confirmed by prover-verify", "binary unavailable");
  } else {
    check(pv.ok, "seal confirmed by prover-verify", pv.ok ? "exit 0 — every check passed" : `first fail: ${pv.firstFailure}`);
  }

  // The honest combined verdict.
  const proofOk = local.ok && pv.available && pv.ok;
  console.log("");
  console.log(
    proofOk
      ? `  ${GREEN}proof VERIFIED${RESET} ${DIM}(local structure + delegated seal)${RESET}`
      : `  ${RED}proof NOT verified${RESET}`
  );
}

async function loadKeys(): Promise<Keys> {
  const res = await fetch(`${BASE}/v1/attestation`);
  if (!res.ok) throw new Error(`cannot reach ${BASE} for attested keys`);
  const attestation = (await res.json()) as {
    bundle: { enclaveSigningPublicKey: string; document: { userData: { signingPublicKey: string } } };
    policy: { policyId: string; guestImageId: string };
  };
  if (
    attestation.bundle.document.userData.signingPublicKey !== attestation.bundle.enclaveSigningPublicKey
  ) {
    throw new Error("attested signing key does not match the presented signing key");
  }
  return {
    enclaveSigningPublicKey: attestation.bundle.enclaveSigningPublicKey,
    policyId: attestation.policy.policyId,
    guestImageId: attestation.policy.guestImageId,
  };
}

/** `--receipt <file.bin>`: verify a raw artifact against the pinned manifest, no coordinator. */
function verifyRawReceipt(path: string): never {
  const manifest = loadManifest();
  const receiptBytes = new Uint8Array(readFileSync(path));
  console.log("");
  console.log(`Raw receipt verification`);
  console.log(`${DIM}file ${path}${RESET}`);
  console.log(`${DIM}manifest ${RELEASE_PATH}${RESET}`);
  console.log("");
  console.log("ZK proof — local structure (everything except the seal)");
  const local = verifyReceipt(receiptBytes, manifest);
  for (const c of local.checks) {
    if (c.delegated) delegated(c.name, c.detail.replace(/^DELEGATED — /, ""));
    else check(c.ok, c.name, c.detail);
  }
  console.log("");
  console.log("ZK proof — seal (delegated to the reference verifier)");
  const pv = runProverVerify(receiptBytes);
  if (!pv.available) {
    note(`prover-verify not built; the seal was NOT confirmed`);
    failures += 1;
    check(false, "seal confirmed by prover-verify", "binary unavailable");
  } else {
    check(pv.ok, "seal confirmed by prover-verify", pv.ok ? "exit 0" : `first fail: ${pv.firstFailure}`);
  }
  console.log("");
  if (failures === 0 && local.ok) {
    console.log(`${GREEN}Proof VERIFIED.${RESET} ${DIM}local structure + delegated seal${RESET}`);
    process.exit(0);
  }
  console.log(`${RED}Proof NOT verified.${RESET}`);
  process.exit(1);
}

async function main(): Promise<void> {
  const args = process.argv.slice(2);

  const receiptIndex = args.indexOf("--receipt");
  if (receiptIndex !== -1) {
    const path = args[receiptIndex + 1];
    if (!path) throw new Error("--receipt requires a path");
    verifyRawReceipt(path);
  }

  const fileIndex = args.indexOf("--file");
  let bundle: Bundle;
  let requestId: string;

  if (fileIndex !== -1) {
    const path = args[fileIndex + 1];
    if (!path) throw new Error("--file requires a path");
    bundle = JSON.parse(readFileSync(path, "utf8")) as Bundle;
    requestId = bundle.signed_receipt?.receipt.requestId ?? "(from file)";
  } else {
    requestId = args[0];
    if (!requestId) {
      console.error(
        "usage: npx tsx scripts/verify-receipt.ts <requestId> | --file <bundle.json> | --receipt <receipt.bin>"
      );
      process.exit(2);
    }
    const res = await fetch(`${BASE}/v1/requests/${requestId}/receipt`);
    if (!res.ok) throw new Error(`request ${requestId} not found`);
    bundle = (await res.json()) as Bundle;
  }

  const keys = await loadKeys();
  const manifest = loadManifest();

  console.log("");
  console.log(`Compute receipt verification`);
  console.log(`${DIM}request ${requestId}${RESET}`);
  console.log(`${DIM}coordinator ${BASE}${RESET}`);
  console.log("");

  const signed = bundle.signed_receipt;
  if (!signed) {
    console.log(`  ${RED}✗${RESET} no signed receipt for this request`);
    process.exit(1);
  }
  const receipt = signed.receipt;

  console.log("Compute receipt");
  check(
    verifyCanonical(receipt, signed.enclaveSignature, keys.enclaveSigningPublicKey),
    "signature valid under the attested enclave signing key"
  );
  check(receipt.version === "ctn-receipt-1", "receipt version recognized", receipt.version);
  check(receipt.policy.decision === "ALLOW", "policy decision is ALLOW");
  check(
    receipt.policy.policyId === keys.policyId,
    "receipt policy id equals the currently attested policy",
    receipt.policy.policyId
  );
  check(
    /^0x[0-9a-f]{64}$/.test(receipt.requestCommitment),
    "request commitment well-formed",
    receipt.requestCommitment
  );

  // The ZK proof: local structure + delegated seal.
  if (!bundle.proof_artifact) {
    console.log("");
    console.log("ZK proof");
    note(`no proof artifact yet (status ${bundle.proof_status})`);
  } else {
    const artifact = bundle.proof_artifact;
    const j = artifact.decodedJournal;
    verifyProofArtifact(artifact, manifest, {
      commitment: receipt.requestCommitment,
      decision: j.decision,
      proofNonce: j.proofNonce,
    });

    // The proof binds to THIS receipt's commitment (the journal's, checked
    // above via expect-commitment) and to the artifact by digest.
    const artifactDigest = zkArtifactDigest(fromB64(artifact.receiptB64));
    console.log("");
    console.log("Proof binding");
    if (!bundle.proof_binding) {
      note("no binding yet — issued when proving settles");
    } else {
      const { binding, enclaveSignature } = bundle.proof_binding;
      check(
        verifyCanonical(binding, enclaveSignature, keys.enclaveSigningPublicKey),
        "binding signature valid under the attested enclave signing key"
      );
      check(binding.artifactDigest === artifactDigest, "binding commits to this exact artifact", artifactDigest);
      check(binding.policyId === receipt.policy.policyId, "binding policy id equals receipt policy id");
      check(binding.proofVerified, "binding reports a server-verified proof");
    }
  }

  console.log("");
  console.log("Route and usage attribution");
  check(!!receipt.route.credentialId, "a credential is named", receipt.route.credentialId);
  check(!!receipt.route.contributorId, "a contributor is credited", receipt.route.contributorId);
  check(receipt.route.attempt >= 1, "attempt number recorded", `attempt ${receipt.route.attempt}`);

  console.log("");
  console.log("Confidentiality of the artifacts themselves");
  const artifacts = JSON.stringify({
    receipt: signed,
    proof_artifact: bundle.proof_artifact,
    proof_binding: bundle.proof_binding,
  }).toLowerCase();
  const forbidden = ["prompt", "messages", "content", "sk-", "mock-provider-key", "bearer"];
  for (const needle of forbidden) {
    check(!artifacts.includes(needle), `no "${needle}" in the receipt, proof or binding`);
  }

  console.log("");
  if (receipt.tee.mode !== "nitro") {
    console.log(`  ${YELLOW}!${RESET} enclave mode is "${receipt.tee.mode}" — cryptographic checks above are real,`);
    console.log(`    ${DIM}but this build makes no hardware isolation claim.${RESET}`);
    console.log("");
  }

  if (failures === 0) {
    console.log(`${GREEN}All checks passed.${RESET} trust status: ${bundle.trust_status}`);
    console.log("");
    process.exit(0);
  }
  console.log(`${RED}${failures} check(s) failed.${RESET}`);
  console.log("");
  process.exit(1);
}

main().catch((err) => {
  console.error(`${RED}error:${RESET} ${(err as Error).message}`);
  process.exit(1);
});

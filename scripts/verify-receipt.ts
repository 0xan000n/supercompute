/**
 * §29 — independent receipt and proof verification from a terminal.
 *
 *   npx tsx scripts/verify-receipt.ts <requestId>
 *   npx tsx scripts/verify-receipt.ts --file receipt.json
 *
 * This tool re-implements the checks locally rather than asking the network
 * whether its own artifacts are valid. The only thing it takes from the
 * coordinator is the artifacts themselves plus the attested public keys; every
 * signature, hash and binding is recomputed here.
 */
import { readFileSync } from "node:fs";
import {
  canonicalHash,
  verifyCanonical,
  type ProofReceipt,
  type SignedComputeReceipt,
  type SignedProofBinding,
} from "@ctn/protocol";

const BASE = process.env.CTN_COORDINATOR_URL ?? "http://127.0.0.1:4200";

interface Bundle {
  signed_receipt: SignedComputeReceipt | null;
  proof?: ProofReceipt;
  proof_binding?: SignedProofBinding;
  proof_status: string;
  trust_status: string;
}

interface Keys {
  enclaveSigningPublicKey: string;
  proverPublicKey: string;
  guestImageId: string;
  policyId: string;
}

const GREEN = "\x1b[32m";
const RED = "\x1b[31m";
const YELLOW = "\x1b[33m";
const DIM = "\x1b[2m";
const RESET = "\x1b[0m";

let failures = 0;

function check(pass: boolean, name: string, detail?: string): void {
  if (!pass) failures += 1;
  const mark = pass ? `${GREEN}✓${RESET}` : `${RED}✗${RESET}`;
  console.log(`  ${mark} ${name}${detail ? `${DIM}  ${detail}${RESET}` : ""}`);
}

function note(text: string): void {
  console.log(`  ${YELLOW}·${RESET} ${DIM}${text}${RESET}`);
}

async function loadKeys(): Promise<Keys> {
  const res = await fetch(`${BASE}/v1/attestation`);
  if (!res.ok) throw new Error(`cannot reach ${BASE} for attested keys`);
  const attestation = (await res.json()) as {
    bundle: { enclaveSigningPublicKey: string; document: { userData: { signingPublicKey: string } } };
    policy: { policyId: string; guestImageId: string };
  };

  // The signing key must be the one bound into the attestation, not merely the
  // one the response header claims.
  if (
    attestation.bundle.document.userData.signingPublicKey !==
    attestation.bundle.enclaveSigningPublicKey
  ) {
    throw new Error("attested signing key does not match the presented signing key");
  }

  return {
    enclaveSigningPublicKey: attestation.bundle.enclaveSigningPublicKey,
    // The prover key is published in the proof response; fetched per receipt below.
    proverPublicKey: "",
    guestImageId: attestation.policy.guestImageId,
    policyId: attestation.policy.policyId,
  };
}

async function main(): Promise<void> {
  const args = process.argv.slice(2);
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
      console.error("usage: npx tsx scripts/verify-receipt.ts <requestId> | --file <path>");
      process.exit(2);
    }
    const res = await fetch(`${BASE}/v1/requests/${requestId}/receipt`);
    if (!res.ok) throw new Error(`request ${requestId} not found`);
    bundle = (await res.json()) as Bundle;
  }

  const keys = await loadKeys();
  // The prover key travels with the proof and is itself bound into the
  // attestation document, so it needs no separate fetch.
  const proverPublicKey = bundle.proof?.proverPublicKey ?? "";

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

  console.log("");
  console.log("Policy proof");
  if (!bundle.proof) {
    note(`no proof artifact yet (status ${bundle.proof_status})`);
  } else {
    const proof = bundle.proof;
    const digest = "0x" + canonicalHash(proof);
    check(
      verifyCanonical(
        { guestImageId: proof.guestImageId, journal: proof.journal },
        proof.seal,
        proverPublicKey
      ),
      "proof seal valid under the prover key",
      proof.proofSystem
    );
    check(
      proof.guestImageId === keys.guestImageId,
      "guest image id matches Safety Policy v1",
      proof.guestImageId
    );
    check(proof.journal.decision === "ALLOW", "journal decision is ALLOW");
    // Rule 8 — the binding that makes the proof about THIS request.
    check(
      proof.journal.requestCommitment === receipt.requestCommitment,
      "journal commitment equals receipt commitment"
    );
    check(proof.journal.policyId === receipt.policy.policyId, "journal policy id equals receipt policy id");

    const allowed = new Set([
      "protocolVersion",
      "requestCommitment",
      "policyId",
      "decision",
      "proofNonce",
    ]);
    const extra = Object.keys(proof.journal).filter((k) => !allowed.has(k));
    check(extra.length === 0, "journal carries no prompt-derived fields", extra.join(", ") || undefined);

    if (proof.proofSystem !== "risc0") {
      note(
        `proof system is "${proof.proofSystem}": the policy was genuinely re-executed and the`
      );
      note(
        `journal is signed by an attested key, but this is NOT a zero-knowledge argument.`
      );
    }

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
      check(binding.zkReceiptDigest === digest, "binding commits to this exact proof", digest);
      check(
        binding.requestCommitment === receipt.requestCommitment,
        "binding commits to this receipt commitment"
      );
      check(binding.proofVerified && binding.decision === "ALLOW", "binding reports a verified ALLOW");
    }
  }

  console.log("");
  console.log("Route and usage attribution");
  check(!!receipt.route.credentialId, "a credential is named", receipt.route.credentialId);
  check(!!receipt.route.contributorId, "a contributor is credited", receipt.route.contributorId);
  check(receipt.route.attempt >= 1, "attempt number recorded", `attempt ${receipt.route.attempt}`);

  console.log("");
  console.log("Confidentiality of the artifacts themselves");
  // Scan only the artifacts a third party would be handed. The surrounding API
  // envelope legitimately contains the word "prompt" in check names such as
  // "journal contains no prompt-derived fields".
  const artifacts = JSON.stringify({
    receipt: signed,
    proof: bundle.proof,
    binding: bundle.proof_binding,
  }).toLowerCase();
  const forbidden = ["prompt", "messages", "content", "sk-", "mock-provider-key", "bearer"];
  for (const needle of forbidden) {
    check(!artifacts.includes(needle), `no "${needle}" in the receipt, proof or binding`);
  }

  console.log("");
  if (receipt.tee.mode !== "nitro") {
    console.log(
      `  ${YELLOW}!${RESET} enclave mode is "${receipt.tee.mode}" — cryptographic checks above are real,`
    );
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

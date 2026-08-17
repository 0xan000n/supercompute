/**
 * `verifyReceipt` — the TypeScript receipt verifier (Phase 2b §8, Task 5).
 *
 * # What this is, after the browser go/no-go spike (NO-GO — see README.md)
 *
 * RISC Zero receipt seals are zk-STARKs (composite = a vector of segment
 * STARKs, succinct = one recursive STARK). Verifying one needs the full risc0
 * verifier — the RISC-V circuit and recursion-circuit parameters and control
 * root of a *specific* risc0 version. There is no pure-TypeScript risc0
 * verifier, and no browser-bundlable wasm verifier pinned to this repo's risc0
 * 3.0.6 image that we could adopt without importing an unpinned, differently
 * versioned trust surface (the spike's evidence and reasoning are in
 * `packages/verify/README.md`). So the cryptographic **seal** is NOT checked
 * here. It is DELEGATED to the coordinator, which spawns the reference
 * `prover/verify` binary server-side (Task 3) — the same offline verifier an
 * independent third party runs.
 *
 * This verifier therefore checks everything a receipt reveals **short of the
 * seal**, against a pinned manifest, and it is honest about the line:
 *
 *   LOCAL  (this verifier owns them; failing one sets `ok:false`):
 *     manifest, receipt-codec, receipt-decodes (bincode framing + no
 *     trailing/truncated bytes + reject the dev-mode Fake stub), journal-parses,
 *     journal-key-set, journal-protocol-version, journal-decision,
 *     journal-request-commitment, journal-proof-nonce, policy-id, and the
 *     caller's expect-commitment / expect-decision / expect-proof-nonce.
 *
 *   DELEGATED  (the seal is required for these; this verifier CANNOT run them —
 *   each is reported with `ok:false` and `delegated:true`, and they do NOT
 *   affect `ok`):
 *     image-id (the claimed ImageID lives inside the STARK inner receipt),
 *     seal (the STARK itself), rules-digest (needs the `policy/v1` files, which
 *     the browser does not carry — the manifest only pins the digest).
 *
 * **`ok` means "every LOCAL check passed."** It is NECESSARY, not sufficient: it
 * NEVER asserts the seal. A caller must AND it with the coordinator's delegated
 * seal result before showing anything as verified — see `checks[*].delegated`
 * and `result.delegated`. The check NAMES match `prover/verify`'s where they
 * overlap, so the two reports read side by side.
 */

/** The pinned identity a receipt is checked against — the shape of `prover/release.json`. */
export interface VerifyManifest {
  imageIdHex: string;
  policyId: string;
  rulesDigest: string;
  journalVersion?: number;
  receiptCodec?: string;
}

/** What the gate journal is expected to carry, if the caller knows it. */
export interface VerifyExpect {
  commitment?: string;
  decision?: "ALLOW" | "DENY";
  proofNonce?: string;
}

/** One named check. `delegated:true` marks a check the seal is required for and
 * that this local verifier could not run — it is always `ok:false` here. */
export interface VerifyCheck {
  name: string;
  ok: boolean;
  detail: string;
  delegated?: boolean;
}

export interface VerifyResult {
  /** True IFF every LOCAL check passed. Excludes DELEGATED checks; never a seal claim. */
  ok: boolean;
  checks: VerifyCheck[];
  /** The names of the checks that were DELEGATED (seal authority = the coordinator). */
  delegated: string[];
}

/** The decoded public journal, once its five fields have passed their shape checks. */
export interface DecodedJournal {
  protocolVersion: number;
  requestCommitment: string;
  policyId: string;
  decision: "ALLOW" | "DENY";
  proofNonce: string;
}

const RECEIPT_CODEC_BINCODE_V1 = "bincode-v1";
const DEFAULT_JOURNAL_VERSION = 1;

/** `ReceiptMetadata { verifier_parameters: Digest }` = `[u32; 8]` = 32 bytes, fixint. */
const META_LEN = 32;

/** `InnerReceipt` variant tags, bincode enum discriminant (u32 LE), risc0 3.0.6:
 * Composite=0, Succinct=1, Groth16=2, Fake=3. A Fake receipt is what
 * `RISC0_DEV_MODE=1` produces and carries no proof at all. */
const INNER_TAG_GROTH16 = 2;
const INNER_TAG_FAKE = 3;

/** The five-field allowlist, in the sorted order a `BTreeMap` (serde_json without
 * `preserve_order`) yields — the exact set `prover/verify` enforces. */
export const JOURNAL_KEYS = [
  "decision",
  "policyId",
  "proofNonce",
  "protocolVersion",
  "requestCommitment",
] as const;

const HEX_64 = /^[0-9a-f]{64}$/;
const HEX_0X_64 = /^0x[0-9a-f]{64}$/;
/** The bound the guest enforces before committing a proofNonce. */
const PROOF_NONCE_RE = /^(0x)?[0-9a-f]{1,64}$/;

const isImageIdHex = (s: unknown): s is string => typeof s === "string" && HEX_64.test(s);
const is0xSha256 = (s: unknown): s is string => typeof s === "string" && HEX_0X_64.test(s);

function readU32LE(bytes: Uint8Array, offset: number): number {
  return (
    (bytes[offset] |
      (bytes[offset + 1] << 8) |
      (bytes[offset + 2] << 16) |
      (bytes[offset + 3] << 24)) >>>
    0
  );
}

/** True IFF the u64 LE at `offset` fits in 32 bits and equals `expected`. */
function u64LEEquals(bytes: Uint8Array, offset: number, expected: number): boolean {
  const lo = readU32LE(bytes, offset);
  const hi = readU32LE(bytes, offset + 4);
  return hi === 0 && lo === expected;
}

/**
 * Locate the `Receipt.journal` field inside a bincode-encoded risc0 receipt,
 * WITHOUT decoding the STARK — the seal is delegated, but the journal (a
 * `Vec<u8>` of canonical JSON) can be framed structurally.
 *
 * The receipt is `{ inner: InnerReceipt, journal: Journal, metadata:
 * ReceiptMetadata }`. `metadata` is exactly a 32-byte `Digest`, so the journal
 * ends at `len - 32`; the journal is `[u64 LE length][bytes]`, and a composite
 * receipt also embeds a *copy* of the journal deeper inside `inner`. The real
 * field is the one whose length prefix and `{ … }` framing line up so that
 * exactly the 32-byte metadata trailer follows it. That triple constraint
 * (ends-at len-32, length-prefix matches, parses as JSON) also rejects appended
 * bytes (the trailer is no longer 32), truncation (the framing no longer
 * closes) and garbage (no framing at all) — which is the whole of what
 * `receipt-decodes` needs a browser to be able to say.
 */
function frameJournal(
  bytes: Uint8Array
): { ok: true; innerTag: number; journal: unknown } | { ok: false; reason: string } {
  if (bytes.length < META_LEN + 8 + 2) {
    return { ok: false, reason: "shorter than the smallest possible receipt" };
  }
  const innerTag = readU32LE(bytes, 0);
  const journalEnd = bytes.length - META_LEN;
  // The journal is canonical JSON: a single flat object, so it ends in '}'.
  if (bytes[journalEnd - 1] !== 0x7d) {
    return {
      ok: false,
      reason:
        "no journal frame at len-32: not a bincode-v1 risc0 receipt, or it has trailing/truncated bytes",
    };
  }
  const decoder = new TextDecoder("utf-8", { fatal: true });
  // Journals are well under 64 KiB; scan candidate lengths for the one whose u64
  // prefix and '{' opener both line up, then require it to parse.
  const maxLen = Math.min(65536, journalEnd - 8);
  for (let len = 2; len <= maxLen; len++) {
    const start = journalEnd - len;
    if (bytes[start] !== 0x7b) continue; // must open with '{'
    if (!u64LEEquals(bytes, start - 8, len)) continue; // length prefix must match exactly
    let text: string;
    try {
      text = decoder.decode(bytes.subarray(start, journalEnd));
    } catch {
      continue;
    }
    let journal: unknown;
    try {
      journal = JSON.parse(text);
    } catch {
      continue;
    }
    return { ok: true, innerTag, journal };
  }
  return {
    ok: false,
    reason:
      "the journal frame does not close cleanly: malformed, truncated, or appended bincode-v1 receipt",
  };
}

/**
 * Verify a RISC Zero policy receipt against a pinned manifest — everything
 * except the cryptographic seal, which is DELEGATED (see the module comment and
 * README). Pure and synchronous; safe in a browser (no Node APIs, no network).
 *
 * @returns `{ ok, checks, delegated }` — `ok` is true IFF every LOCAL check
 * passed. Treat `ok:true` as "local checks passed, seal still to be confirmed
 * by the coordinator", never as "verified".
 */
export function verifyReceipt(
  receiptBytes: Uint8Array,
  manifest: VerifyManifest,
  expect?: VerifyExpect
): VerifyResult {
  const checks: VerifyCheck[] = [];
  let localFailed = false;

  const pass = (name: string, detail: string) => checks.push({ name, ok: true, detail });
  const fail = (name: string, detail: string) => {
    checks.push({ name, ok: false, detail });
    localFailed = true;
  };
  const delegate = (name: string, detail: string) =>
    checks.push({ name, ok: false, detail: `DELEGATED — ${detail}`, delegated: true });
  const finish = (): VerifyResult => ({
    ok: !localFailed,
    checks,
    delegated: checks.filter((c) => c.delegated).map((c) => c.name),
  });

  // --- manifest ----------------------------------------------------------
  const journalVersion = manifest.journalVersion ?? DEFAULT_JOURNAL_VERSION;
  const receiptCodec = manifest.receiptCodec ?? RECEIPT_CODEC_BINCODE_V1;
  if (!isImageIdHex(manifest.imageIdHex)) {
    fail("manifest", "imageIdHex is not 64 lowercase hex digits");
    return finish();
  }
  if (!is0xSha256(manifest.policyId)) {
    fail("manifest", 'policyId is not "0x" followed by 64 lowercase hex digits');
    return finish();
  }
  if (!is0xSha256(manifest.rulesDigest)) {
    fail("manifest", 'rulesDigest is not "0x" followed by 64 lowercase hex digits');
    return finish();
  }
  if (journalVersion !== DEFAULT_JOURNAL_VERSION) {
    fail("manifest", `journalVersion is not ${DEFAULT_JOURNAL_VERSION}, the only version this verifier reads`);
    return finish();
  }
  pass("manifest", `pins imageId ${manifest.imageIdHex}, journalVersion ${journalVersion}`);

  // --- receipt codec -----------------------------------------------------
  if (receiptCodec !== RECEIPT_CODEC_BINCODE_V1) {
    fail("receipt-codec", `manifest names a codec this verifier cannot decode; it decodes only ${RECEIPT_CODEC_BINCODE_V1}`);
    return finish();
  }
  pass("receipt-codec", RECEIPT_CODEC_BINCODE_V1);

  // --- receipt structural decode (framing; NOT the STARK) ----------------
  const framed = frameJournal(receiptBytes);
  if (!framed.ok) {
    fail("receipt-decodes", framed.reason);
    return finish();
  }
  pass(
    "receipt-decodes",
    `bincode-v1 framing decoded (journal + 32-byte metadata trailer, no trailing bytes); STARK body delegated`
  );

  // --- image-id: DELEGATED ----------------------------------------------
  // The claimed ImageID lives inside the STARK inner receipt; reading it needs
  // the seal machinery. The coordinator's prover/verify compares it to the
  // pinned id. wrong-image (byte-identical journal, different image) is caught
  // only there — this verifier cannot see it.
  delegate("image-id", `receipt claim compared to pinned imageId ${manifest.imageIdHex} server-side by prover/verify`);

  // --- seal --------------------------------------------------------------
  // The one seal failure a browser CAN see structurally: a Fake inner receipt
  // (RISC0_DEV_MODE=1) carries no proof. Reject it locally, by name `seal`, the
  // way prover/verify does. Every other seal question is the STARK itself.
  if (framed.innerTag === INNER_TAG_FAKE) {
    fail(
      "seal",
      "dev-mode stub: InnerReceipt::Fake carries no proof at all (produced with RISC0_DEV_MODE=1)"
    );
    return finish();
  }
  if (framed.innerTag === INNER_TAG_GROTH16) {
    // Groth16 is a genuine seal, just not one the fixtures/product emit; its
    // verification is still the coordinator's, so delegate rather than accept.
    delegate("seal", "Groth16 seal cryptographically verified server-side by prover/verify");
  } else {
    delegate(
      "seal",
      "STARK seal cryptographically verified server-side by prover/verify against the pinned imageId"
    );
  }

  // --- journal content ---------------------------------------------------
  const journal = framed.journal;
  if (typeof journal !== "object" || journal === null || Array.isArray(journal)) {
    fail("journal-parses", "the journal is JSON but not a JSON object");
    return finish();
  }
  const obj = journal as Record<string, unknown>;
  pass("journal-parses", "JSON object");

  const keys = Object.keys(obj).sort();
  const expected = [...JOURNAL_KEYS];
  if (keys.length !== expected.length || keys.some((k, i) => k !== expected[i])) {
    const missing = expected.filter((k) => !(k in obj));
    const unexpected = keys.length - (expected.length - missing.length);
    fail(
      "journal-key-set",
      `not the verifier allowlist: ${missing.length} of 5 missing (${missing.join(", ") || "none"}), ${unexpected} key(s) outside it`
    );
    return finish();
  }
  pass("journal-key-set", `exactly {${JOURNAL_KEYS.join(", ")}}`);

  if (obj.protocolVersion !== journalVersion) {
    fail("journal-protocol-version", `protocolVersion is not the manifest's journalVersion (${journalVersion})`);
    return finish();
  }
  pass("journal-protocol-version", String(journalVersion));

  if (obj.decision !== "ALLOW" && obj.decision !== "DENY") {
    fail("journal-decision", "decision is not one of ALLOW, DENY");
    return finish();
  }
  const decision = obj.decision as "ALLOW" | "DENY";
  pass("journal-decision", decision);

  if (!is0xSha256(obj.requestCommitment)) {
    fail("journal-request-commitment", 'requestCommitment is not "0x" followed by 64 lowercase hex digits');
    return finish();
  }
  const requestCommitment = obj.requestCommitment as string;
  pass("journal-request-commitment", requestCommitment);

  if (typeof obj.proofNonce !== "string" || !PROOF_NONCE_RE.test(obj.proofNonce)) {
    fail(
      "journal-proof-nonce",
      "proofNonce is outside ^(0x)?[0-9a-f]{1,64}$, the bound the guest enforces before committing one"
    );
    return finish();
  }
  const proofNonce = obj.proofNonce as string;
  pass("journal-proof-nonce", proofNonce);

  // --- policy-id: journal vs manifest -----------------------------------
  if (!is0xSha256(obj.policyId)) {
    fail("policy-id", 'the journal policyId is not "0x" followed by 64 lowercase hex digits');
    return finish();
  }
  if (obj.policyId !== manifest.policyId) {
    fail("policy-id", "the journal's policyId is not the policyId pinned in the manifest");
    return finish();
  }
  pass("policy-id", `journal and manifest agree: ${manifest.policyId}`);

  // --- rules-digest: DELEGATED ------------------------------------------
  // Re-deriving policyId/rulesDigest needs the policy/v1 files, which the
  // browser does not carry; the manifest only pins the digest. prover/verify
  // re-derives it from policy/v1 server-side.
  delegate("rules-digest", `re-derived from policy/v1 server-side; manifest pins ${manifest.rulesDigest}`);

  // --- caller expectations (all LOCAL) ----------------------------------
  if (expect?.commitment !== undefined) {
    if (expect.commitment !== requestCommitment) {
      fail("expect-commitment", "the journal commits to a different requestCommitment than expected");
      return finish();
    }
    pass("expect-commitment", expect.commitment);
  }
  if (expect?.decision !== undefined) {
    if (expect.decision !== decision) {
      fail("expect-decision", `the journal decision is ${decision}, not the expected ${expect.decision}`);
      return finish();
    }
    pass("expect-decision", expect.decision);
  }
  if (expect?.proofNonce !== undefined) {
    if (expect.proofNonce !== proofNonce) {
      fail("expect-proof-nonce", "the journal echoes a different proofNonce than expected");
      return finish();
    }
    pass("expect-proof-nonce", expect.proofNonce);
  }

  return finish();
}

/**
 * Extract the decoded five-field journal from a receipt, or `null` if the
 * receipt does not frame/parse or its journal fails a shape check. A
 * convenience for callers (e.g. the terminal tool) that want the journal after
 * `verifyReceipt`; it runs the same framing + shape checks and never trusts the
 * seal.
 */
export function decodeJournal(receiptBytes: Uint8Array): DecodedJournal | null {
  const framed = frameJournal(receiptBytes);
  if (!framed.ok) return null;
  const j = framed.journal;
  if (typeof j !== "object" || j === null || Array.isArray(j)) return null;
  const o = j as Record<string, unknown>;
  const keys = Object.keys(o).sort();
  if (keys.length !== JOURNAL_KEYS.length || keys.some((k, i) => k !== JOURNAL_KEYS[i])) return null;
  if (o.protocolVersion !== DEFAULT_JOURNAL_VERSION) return null;
  if (o.decision !== "ALLOW" && o.decision !== "DENY") return null;
  if (!is0xSha256(o.requestCommitment) || !is0xSha256(o.policyId)) return null;
  if (typeof o.proofNonce !== "string" || !PROOF_NONCE_RE.test(o.proofNonce)) return null;
  return {
    protocolVersion: o.protocolVersion as number,
    requestCommitment: o.requestCommitment as string,
    policyId: o.policyId as string,
    decision: o.decision as "ALLOW" | "DENY",
    proofNonce: o.proofNonce as string,
  };
}

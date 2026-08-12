import { test } from "node:test";
import assert from "node:assert/strict";
import {
  toCanonicalRequest,
  canonicalJson,
  canonicalBytes,
  CanonicalizationError,
} from "./canonical";
import {
  requestCommitment,
  generateSigningKeyPair,
  signCanonical,
  verifyCanonical,
  toHex,
  fromHex,
  randomHex,
  sha256Hex,
  canonicalHash,
} from "./crypto";
import { generateHpkeKeyPair, hpkeSeal, hpkeOpen } from "./hpke";

test("canonical JSON sorts keys and omits whitespace", () => {
  assert.equal(canonicalJson({ b: 1, a: 2 }), '{"a":2,"b":1}');
  assert.equal(canonicalJson({ z: [3, 1], a: "x" }), '{"a":"x","z":[3,1]}');
});

test("canonical JSON rejects non-integer numbers", () => {
  assert.throws(() => canonicalJson({ t: 0.7 }), CanonicalizationError);
  assert.throws(() => canonicalJson({ t: NaN }), CanonicalizationError);
  assert.throws(() => canonicalJson({ t: Infinity }), CanonicalizationError);
});

test("canonicalization applies NFC so equivalent unicode is identical", () => {
  const composed = toCanonicalRequest({
    model: "m",
    messages: [{ role: "user", content: "café" }],
  });
  const decomposed = toCanonicalRequest({
    model: "m",
    messages: [{ role: "user", content: "café" }],
  });
  assert.equal(canonicalJson(composed), canonicalJson(decomposed));
});

test("canonicalization converts float temperature to integer millis and applies defaults", () => {
  const r = toCanonicalRequest({ model: "m", messages: [{ role: "user", content: "hi" }] });
  assert.equal(r.temperature_millis, 1000);
  assert.equal(r.max_tokens, 1024);
  const r2 = toCanonicalRequest({
    model: "m",
    messages: [{ role: "user", content: "hi" }],
    temperature: 0.7,
  });
  assert.equal(r2.temperature_millis, 700);
});

test("canonicalization rejects invalid roles and empty messages", () => {
  assert.throws(
    () => toCanonicalRequest({ model: "m", messages: [{ role: "hacker", content: "x" }] }),
    CanonicalizationError
  );
  assert.throws(() => toCanonicalRequest({ model: "m", messages: [] }), CanonicalizationError);
});

test("§36 invariant: same canonical input + same nonce yields same commitment", () => {
  const req = toCanonicalRequest({ model: "m", messages: [{ role: "user", content: "hello" }] });
  const nonce = randomHex(32);
  const a = requestCommitment(canonicalBytes(req), nonce);
  const b = requestCommitment(canonicalBytes(req), nonce);
  assert.equal(a, b);
  assert.match(a, /^0x[0-9a-f]{64}$/);
});

test("§21 invariant: same prompt with different nonce yields different commitment", () => {
  const req = toCanonicalRequest({ model: "m", messages: [{ role: "user", content: "hello" }] });
  const a = requestCommitment(canonicalBytes(req), randomHex(32));
  const b = requestCommitment(canonicalBytes(req), randomHex(32));
  assert.notEqual(a, b);
});

test("commitment changes when any request byte changes", () => {
  const nonce = randomHex(32);
  const a = requestCommitment(
    canonicalBytes(toCanonicalRequest({ model: "m", messages: [{ role: "user", content: "a" }] })),
    nonce
  );
  const b = requestCommitment(
    canonicalBytes(toCanonicalRequest({ model: "m", messages: [{ role: "user", content: "b" }] })),
    nonce
  );
  assert.notEqual(a, b);
});

test("commitment rejects a nonce that is not 32 bytes", () => {
  const req = toCanonicalRequest({ model: "m", messages: [{ role: "user", content: "x" }] });
  assert.throws(() => requestCommitment(canonicalBytes(req), randomHex(16)));
});

test("hex round-trips", () => {
  const bytes = new Uint8Array([0, 1, 127, 128, 255]);
  assert.deepEqual(fromHex(toHex(bytes)), bytes);
  assert.throws(() => fromHex("zz"));
});

test("sha256 matches a known vector", () => {
  assert.equal(
    sha256Hex("abc"),
    "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
  );
});

test("ed25519 signs and verifies canonical values, and rejects tampering", () => {
  const kp = generateSigningKeyPair();
  const pubHex = toHex(kp.publicKey);
  const value = { requestId: "req_1", decision: "ALLOW", n: 7 };
  const sig = signCanonical(value, kp.privateKey);

  assert.ok(verifyCanonical(value, sig, pubHex));
  // §56: modified receipt -> verification fails
  assert.ok(!verifyCanonical({ ...value, decision: "DENY" }, sig, pubHex));
  // wrong key -> verification fails
  assert.ok(!verifyCanonical(value, sig, toHex(generateSigningKeyPair().publicKey)));
});

test("signature is over canonical form, so key order does not matter", () => {
  const kp = generateSigningKeyPair();
  const sig = signCanonical({ a: 1, b: 2 }, kp.privateKey);
  assert.ok(verifyCanonical({ b: 2, a: 1 }, sig, toHex(kp.publicKey)));
  assert.equal(canonicalHash({ a: 1, b: 2 }), canonicalHash({ b: 2, a: 1 }));
});

test("HPKE seals to a public key and only the private key opens it", async () => {
  const enclave = await generateHpkeKeyPair();
  const plaintext = new TextEncoder().encode(JSON.stringify({ prompt: "CANARY_PRIVATE" }));

  const box = await hpkeSeal(enclave.publicKeyB64, plaintext);
  const opened = await hpkeOpen(enclave.privateKeyB64, box);
  assert.deepEqual(opened, plaintext);

  // §56: tampered encrypted prompt -> AEAD failure
  const tamperedBytes = Buffer.from(box.ciphertext, "base64");
  tamperedBytes[0] ^= 0xff;
  await assert.rejects(
    hpkeOpen(enclave.privateKeyB64, {
      enc: box.enc,
      ciphertext: tamperedBytes.toString("base64"),
    })
  );

  // wrong enclave key -> cannot open
  const other = await generateHpkeKeyPair();
  await assert.rejects(hpkeOpen(other.privateKeyB64, box));
});

test("HPKE binds AAD: mismatched AAD fails to open", async () => {
  const enclave = await generateHpkeKeyPair();
  const pt = new TextEncoder().encode("secret");
  const aad = new TextEncoder().encode('{"apiVersion":"v1"}');
  const box = await hpkeSeal(enclave.publicKeyB64, pt, aad);

  assert.deepEqual(await hpkeOpen(enclave.privateKeyB64, box, aad), pt);
  await assert.rejects(
    hpkeOpen(enclave.privateKeyB64, box, new TextEncoder().encode('{"apiVersion":"v2"}'))
  );
});

test("attestation signature covers the nonce, so a verifier must read it from the bundle", () => {
  // Regression: the client hardcoded `nonce: null` when reconstructing the signed
  // payload, so every nonce-bearing attestation failed verification and the whole
  // contributor onboarding flow — which always sends a nonce — could never finish.
  const kp = generateSigningKeyPair();
  const pub = toHex(kp.publicKey);
  const document = {
    pcrs: { "0": "abc" },
    userData: { ingressPublicKey: "i", signingPublicKey: pub },
  };

  const nonce = "fresh-nonce-123";
  const signature = signCanonical({ ...document, platformSignature: undefined, nonce }, kp.privateKey);

  // Verifying with the nonce that was actually signed succeeds.
  assert.ok(verifyCanonical({ ...document, platformSignature: undefined, nonce }, signature, pub));
  // Verifying with a different nonce, or none, fails.
  assert.ok(!verifyCanonical({ ...document, platformSignature: undefined, nonce: null }, signature, pub));
  assert.ok(
    !verifyCanonical({ ...document, platformSignature: undefined, nonce: "other" }, signature, pub)
  );
});

/**
 * §10 — HPKE envelope encryption (RFC 9180). No custom cryptography.
 * Suite: DHKEM(X25519, HKDF-SHA256) + HKDF-SHA256 + AES-128-GCM.
 * Works in both the browser (WebCrypto) and Node 22.
 */
import { CipherSuite, HkdfSha256, Aes128Gcm } from "@hpke/core";
import { DhkemX25519HkdfSha256 } from "@hpke/dhkem-x25519";
import { toB64, fromB64 } from "./crypto";

function makeSuite(): CipherSuite {
  return new CipherSuite({
    kem: new DhkemX25519HkdfSha256(),
    kdf: new HkdfSha256(),
    aead: new Aes128Gcm(),
  });
}

export interface HpkeKeyPair {
  publicKeyB64: string;
  privateKeyB64: string;
}

export async function generateHpkeKeyPair(): Promise<HpkeKeyPair> {
  const suite = makeSuite();
  const kp = await suite.kem.generateKeyPair();
  const pub = new Uint8Array(await suite.kem.serializePublicKey(kp.publicKey));
  const priv = new Uint8Array(await suite.kem.serializePrivateKey(kp.privateKey));
  return { publicKeyB64: toB64(pub), privateKeyB64: toB64(priv) };
}

export interface SealedBox {
  /** encapsulated key, base64 */
  enc: string;
  /** ciphertext, base64 */
  ciphertext: string;
}

/** Seal plaintext to a recipient public key (browser or node). */
export async function hpkeSeal(
  recipientPublicKeyB64: string,
  plaintext: Uint8Array,
  aad?: Uint8Array
): Promise<SealedBox> {
  const suite = makeSuite();
  const pk = await suite.kem.deserializePublicKey(
    fromB64(recipientPublicKeyB64).buffer as ArrayBuffer
  );
  const sender = await suite.createSenderContext({ recipientPublicKey: pk });
  const ct = await sender.seal(
    plaintext.buffer.slice(plaintext.byteOffset, plaintext.byteOffset + plaintext.byteLength) as ArrayBuffer,
    aad ? (aad.buffer.slice(aad.byteOffset, aad.byteOffset + aad.byteLength) as ArrayBuffer) : undefined
  );
  return { enc: toB64(new Uint8Array(sender.enc)), ciphertext: toB64(new Uint8Array(ct)) };
}

/** Open a sealed box with the recipient private key. Throws on any tampering (AEAD failure). */
export async function hpkeOpen(
  recipientPrivateKeyB64: string,
  box: SealedBox,
  aad?: Uint8Array
): Promise<Uint8Array> {
  const suite = makeSuite();
  const sk = await suite.kem.deserializePrivateKey(
    fromB64(recipientPrivateKeyB64).buffer as ArrayBuffer
  );
  const recipient = await suite.createRecipientContext({
    recipientKey: sk,
    enc: fromB64(box.enc).buffer as ArrayBuffer,
  });
  const pt = await recipient.open(
    fromB64(box.ciphertext).buffer as ArrayBuffer,
    aad ? (aad.buffer.slice(aad.byteOffset, aad.byteOffset + aad.byteLength) as ArrayBuffer) : undefined
  );
  return new Uint8Array(pt);
}

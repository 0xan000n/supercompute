/**
 * §38, §39 — TrustedEnvironment abstraction with a SimulatedTEE implementation.
 *
 * No application logic below this file conditions on Nitro vs simulation. The
 * ONLY thing that differs between SimulatedTEE and a future NitroTEE is how the
 * attestation document is produced and how the vault DEK is unsealed. Protocol,
 * policy, credential handling, routing authorization and receipt generation are
 * byte-identical across both.
 *
 * SIMULATION IS NOT CONFIDENTIAL. The parent process can read this process's
 * memory. Every artifact this module emits is labeled accordingly.
 */
import { createHash, createHmac, randomBytes, createCipheriv, createDecipheriv } from "node:crypto";
import { readFileSync, writeFileSync, existsSync, mkdirSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import {
  generateHpkeKeyPair,
  generateSigningKeyPair,
  signCanonical,
  toHex,
  toB64,
  fromB64,
  type AttestationBundle,
  type SimulatedAttestationDocument,
} from "@ctn/protocol";

const root = join(dirname(fileURLToPath(import.meta.url)), "..", "..", "..");
const DATA_DIR = join(root, ".data");
/** Wrapped DEK lives OUTSIDE the enclave (§14) — the enclave has no persistent storage. */
const WRAPPED_DEK_PATH = join(DATA_DIR, "wrapped-dek.json");
/** Stands in for an AWS KMS CMK. Never readable by the enclave in the real design. */
const KMS_KEY_PATH = join(DATA_DIR, "sim-kms-master.key");

export const SIMULATION_WARNING = "SIMULATED TEE — NO HARDWARE CONFIDENTIALITY" as const;

export interface TrustedEnvironment {
  readonly mode: "simulation" | "nitro";
  readonly buildId: string;
  readonly enclaveKeyId: string;
  /** HPKE ingress public key — clients and contributors encrypt to this. */
  readonly ingressPublicKey: string;
  readonly signingPublicKey: string;
  readonly proverPublicKey: string;
  attestation(nonce?: string): AttestationBundle;
  attestationDigest(): string;
  unsealVaultKey(): Buffer;
  signReceipt(value: unknown): string;
  fingerprint(credentialId: string, secret: string): string;
  signProofJournal(value: unknown): string;
  openIngress(box: { enc: string; ciphertext: string }, aad?: Uint8Array): Promise<Uint8Array>;
}

/**
 * Simulated PCR measurements. Derived from the actual policy program + build id
 * so that changing the policy changes the measurement, exactly as a real
 * enclave image rebuild would.
 */
function computePcrs(buildId: string, policyId: string): Record<string, string> {
  const h = (label: string) =>
    createHash("sha384").update(`${label}\0${buildId}\0${policyId}`).digest("hex");
  return { "0": h("pcr0-image"), "1": h("pcr1-kernel"), "2": h("pcr2-application") };
}

interface KmsPolicy {
  /** KMS will only unwrap for an enclave presenting this PCR0 (§14). */
  approvedPcr0: string;
}

export class SimulatedTEE implements TrustedEnvironment {
  readonly mode = "simulation" as const;
  readonly buildId: string;
  readonly enclaveKeyId: string;
  readonly ingressPublicKey: string;
  readonly signingPublicKey: string;
  readonly proverPublicKey: string;

  private readonly ingressPrivateKey: string;
  private readonly signingPrivateKey: Uint8Array;
  private readonly proverPrivateKey: Uint8Array;
  private readonly pcrs: Record<string, string>;
  private readonly policyIds: string[];
  private vaultKey: Buffer | null = null;

  private constructor(init: {
    buildId: string;
    policyIds: string[];
    ingressPublicKey: string;
    ingressPrivateKey: string;
    signing: { publicKey: Uint8Array; privateKey: Uint8Array };
    prover: { publicKey: Uint8Array; privateKey: Uint8Array };
  }) {
    this.buildId = init.buildId;
    this.policyIds = init.policyIds;
    this.ingressPublicKey = init.ingressPublicKey;
    this.ingressPrivateKey = init.ingressPrivateKey;
    this.signingPublicKey = toHex(init.signing.publicKey);
    this.signingPrivateKey = init.signing.privateKey;
    this.proverPublicKey = toHex(init.prover.publicKey);
    this.proverPrivateKey = init.prover.privateKey;
    this.pcrs = computePcrs(init.buildId, init.policyIds[0] ?? "none");
    // Key id binds the ingress key to this boot: clients that cache a stale
    // ingress key get a clean CTN_INVALID_ENVELOPE rather than a decrypt error.
    this.enclaveKeyId = `ek_${createHash("sha256").update(this.ingressPublicKey).digest("hex").slice(0, 16)}`;
  }

  /** §11 — at boot: generate ingress key, signing key, obtain attestation. */
  static async boot(opts: { policyIds: string[]; policyId: string }): Promise<SimulatedTEE> {
    const ingress = await generateHpkeKeyPair();
    const signing = generateSigningKeyPair();
    const prover = generateSigningKeyPair();
    // Build id is derived from the policy program so the demo's "enclave build"
    // genuinely changes when the code that matters changes.
    const buildId = createHash("sha256")
      .update(`ctn-enclave-sim-v0.1\0${opts.policyId}`)
      .digest("hex")
      .slice(0, 32);

    const tee = new SimulatedTEE({
      buildId,
      policyIds: opts.policyIds,
      ingressPublicKey: ingress.publicKeyB64,
      ingressPrivateKey: ingress.privateKeyB64,
      signing,
      prover,
    });
    tee.provisionVault();
    return tee;
  }

  attestation(nonce?: string): AttestationBundle {
    const document: SimulatedAttestationDocument = {
      moduleId: `i-sim-enclave-${this.buildId.slice(0, 12)}`,
      digest: "SHA384",
      pcrs: this.pcrs,
      // §11 — bind ingress + signing public keys into attested data.
      userData: {
        ingressPublicKey: this.ingressPublicKey,
        signingPublicKey: this.signingPublicKey,
      },
      timestamp: Date.now(),
      platformSignature: "",
      warning: SIMULATION_WARNING,
    };
    // In simulation the "platform root key" is the enclave's own signing key.
    // A verifier is told exactly this, so no false trust is implied: the
    // simulated document proves key binding and integrity, NOT hardware
    // isolation. Only NitroTEE can produce a document rooted in the AWS CA.
    //
    // The nonce is inside the signed bytes AND echoed in the bundle, so a
    // verifier can reconstruct exactly what was signed.
    const echoedNonce = nonce ?? null;
    const toSign = { ...document, platformSignature: undefined, nonce: echoedNonce };
    document.platformSignature = signCanonical(toSign, this.signingPrivateKey);

    return {
      version: "ctn-attestation-1",
      teeMode: this.mode,
      document,
      enclaveSigningPublicKey: this.signingPublicKey,
      ingressPublicKey: this.ingressPublicKey,
      enclaveKeyId: this.enclaveKeyId,
      enclaveBuildId: this.buildId,
      policyIds: this.policyIds,
      issuedAt: new Date().toISOString(),
      nonce: echoedNonce,
    };
  }

  attestationDigest(): string {
    const doc = this.attestation().document;
    return (
      "0x" +
      createHash("sha256")
        .update(JSON.stringify({ pcrs: doc.pcrs, userData: doc.userData }))
        .digest("hex")
    );
  }

  /** §14 — envelope encryption: DEK wrapped under a KMS-equivalent, stored outside. */
  private provisionVault(): void {
    mkdirSync(DATA_DIR, { recursive: true });
    if (!existsSync(KMS_KEY_PATH)) {
      writeFileSync(KMS_KEY_PATH, randomBytes(32).toString("base64"), { mode: 0o600 });
    }
    if (!existsSync(WRAPPED_DEK_PATH)) {
      const dek = randomBytes(32);
      const wrapped = this.kmsWrap(dek);
      writeFileSync(
        WRAPPED_DEK_PATH,
        JSON.stringify(
          { ...wrapped, kmsPolicy: { approvedPcr0: this.pcrs["0"] } satisfies KmsPolicy },
          null,
          2
        )
      );
    }
  }

  private kmsMaster(): Buffer {
    return Buffer.from(readFileSync(KMS_KEY_PATH, "utf8"), "base64");
  }

  private kmsWrap(dek: Buffer): { iv: string; ciphertext: string; tag: string } {
    const iv = randomBytes(12);
    const cipher = createCipheriv("aes-256-gcm", this.kmsMaster(), iv);
    const ct = Buffer.concat([cipher.update(dek), cipher.final()]);
    return {
      iv: iv.toString("base64"),
      ciphertext: ct.toString("base64"),
      tag: cipher.getAuthTag().toString("base64"),
    };
  }

  /**
   * §14 — at boot the enclave presents its measurements; the KMS-equivalent
   * releases the DEK only for approved PCR0. A wrong measurement is refused,
   * which is what makes credential custody conditional on enclave identity.
   */
  unsealVaultKey(): Buffer {
    if (this.vaultKey) return this.vaultKey;
    const stored = JSON.parse(readFileSync(WRAPPED_DEK_PATH, "utf8")) as {
      iv: string;
      ciphertext: string;
      tag: string;
      kmsPolicy: KmsPolicy;
    };
    if (stored.kmsPolicy.approvedPcr0 !== this.pcrs["0"]) {
      throw new Error(
        "KMS_REFUSED: enclave PCR0 does not match the measurement authorized to unwrap the vault DEK"
      );
    }
    const decipher = createDecipheriv("aes-256-gcm", this.kmsMaster(), fromB64(stored.iv));
    decipher.setAuthTag(fromB64(stored.tag));
    this.vaultKey = Buffer.concat([
      decipher.update(fromB64(stored.ciphertext)),
      decipher.final(),
    ]);
    return this.vaultKey;
  }

  signReceipt(value: unknown): string {
    return signCanonical(value, this.signingPrivateKey);
  }

  /**
   * A short, stable, non-reversible handle for one credential, for the UI.
   *
   * Two properties matter, and both were learned the hard way:
   *
   * 1. Keyed under a secret the enclave never publishes. A truncated hash salted
   *    with something public (the build id, say) is trivially brute-forceable for
   *    a credential with a known prefix and limited entropy — the fingerprint
   *    would then leak the key it stands in for.
   *
   * 2. Bound to the credential id, so the same secret submitted twice produces
   *    two different fingerprints. Without this, credential ingestion is a
   *    guess-checking oracle: submit a candidate secret, compare the returned
   *    fingerprint against a published one, and recover a low-entropy key
   *    through the public API without ever seeing it.
   */
  fingerprint(credentialId: string, secret: string): string {
    return createHmac("sha256", this.signingPrivateKey)
      .update(`ctn-credential-fingerprint\0${credentialId}\0${secret}`)
      .digest("hex")
      .slice(0, 16);
  }

  signProofJournal(value: unknown): string {
    return signCanonical(value, this.proverPrivateKey);
  }

  async openIngress(
    box: { enc: string; ciphertext: string },
    aad?: Uint8Array
  ): Promise<Uint8Array> {
    const { hpkeOpen } = await import("@ctn/protocol");
    return hpkeOpen(this.ingressPrivateKey, box, aad);
  }
}

/** AES-256-GCM under the vault DEK — how contributed credentials rest at DB level. */
export function vaultEncrypt(dek: Buffer, plaintext: string): string {
  const iv = randomBytes(12);
  const cipher = createCipheriv("aes-256-gcm", dek, iv);
  const ct = Buffer.concat([cipher.update(plaintext, "utf8"), cipher.final()]);
  return toB64(
    Buffer.concat([iv, cipher.getAuthTag(), ct]) as unknown as Uint8Array
  );
}

export function vaultDecrypt(dek: Buffer, blob: string): string {
  const raw = Buffer.from(fromB64(blob));
  const iv = raw.subarray(0, 12);
  const tag = raw.subarray(12, 28);
  const ct = raw.subarray(28);
  const decipher = createDecipheriv("aes-256-gcm", dek, iv);
  decipher.setAuthTag(tag);
  return Buffer.concat([decipher.update(ct), decipher.final()]).toString("utf8");
}

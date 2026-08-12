"use client";

import { verifyAttestationBundle, type AttestationEnvelope } from "@ctn/client";
import { Badge, Check, Field, Panel, SectionLabel } from "./ui";
import { shortHash } from "@/lib/format";

/**
 * §11 — the attestation panel a contributor inspects before trusting the enclave
 * with a credential.
 *
 * Verification runs in the browser against the bundle, not on a server that could
 * simply claim success. The hardware check is shown separately and honestly: in
 * simulation the cryptographic checks pass and the hardware check does not, and
 * the panel says exactly that rather than showing a green tick.
 */
export function AttestationPanel({
  attestation,
  expectedNonce,
  compact = false,
}: {
  attestation: AttestationEnvelope | null;
  /** Pass the nonce that was requested so freshness is checked, not assumed. */
  expectedNonce?: string;
  compact?: boolean;
}) {
  if (!attestation) {
    return (
      <Panel className="p-4">
        <SectionLabel>Enclave attestation</SectionLabel>
        <p className="mt-2 text-[12.5px] text-ink-3">Not fetched yet.</p>
      </Panel>
    );
  }

  const verified = verifyAttestationBundle(attestation, expectedNonce);
  const { bundle } = attestation;
  const cryptoOk = verified.valid;

  return (
    <Panel className="p-4">
      <div className="flex items-center justify-between gap-3">
        <SectionLabel>Enclave attestation</SectionLabel>
        {cryptoOk ? (
          verified.hardwareBacked ? (
            <Badge tone="verified" dot>
              TEE VERIFIED
            </Badge>
          ) : (
            <Badge tone="simulated" dot>
              SIMULATED TEE
            </Badge>
          )
        ) : (
          <Badge tone="denied" dot>
            VERIFICATION FAILED
          </Badge>
        )}
      </div>

      <div className="mt-2.5">
        {verified.checks.map((check) => (
          <Check
            key={check.name}
            pass={check.pass}
            name={check.name}
            detail={check.detail}
          />
        ))}
      </div>

      {!verified.hardwareBacked && (
        <p className="mt-2 rounded-[10px] border border-pending/25 bg-pending/[0.06] px-3 py-2 text-[11px] leading-relaxed text-pending/85">
          The enclave proved it holds the key it publishes, and the policy it runs is the policy
          named below. It has <span className="font-semibold">not</span> proved hardware isolation —
          in simulation the host can read enclave memory. Only the Nitro build can make that claim.
        </p>
      )}

      {!compact && (
        <div className="mt-3 border-t border-hairline pt-2">
          <Field
            label="Enclave build"
            value={shortHash(bundle.enclaveBuildId, 10, 6)}
            mono
            copy={bundle.enclaveBuildId}
          />
          <Field label="PCR0" value={shortHash(bundle.document.pcrs["0"], 10, 6)} mono copy={bundle.document.pcrs["0"]} />
          <Field
            label="Ingress key"
            value={shortHash(bundle.ingressPublicKey, 10, 6)}
            mono
            copy={bundle.ingressPublicKey}
          />
          <Field
            label="Signing key"
            value={shortHash(bundle.enclaveSigningPublicKey, 10, 6)}
            mono
            copy={bundle.enclaveSigningPublicKey}
          />
          <Field label="Policy" value={`${attestation.policy.name} v${attestation.policy.version}`} />
          <Field
            label="Policy id"
            value={shortHash(attestation.policy.policyId, 10, 6)}
            mono
            copy={attestation.policy.policyId}
          />
          <Field
            label="Proof program"
            value={shortHash(attestation.policy.guestImageId, 10, 6)}
            mono
            copy={attestation.policy.guestImageId}
          />
        </div>
      )}
    </Panel>
  );
}

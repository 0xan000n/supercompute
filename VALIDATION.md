# Validation of the specification

A review of *Compute Trust Network Prototype, Implementation Specification v0.1*
against what it takes to actually build the thing, plus a record of where this
implementation diverged and why.

Short version: **the plan is sound and the thesis is demonstrable.** The
architecture is correctly factored, the trust boundaries are drawn in the right
places, and the non-guarantees section is unusually honest for a document of this
kind.

Ten things were underspecified or wrong in ways that only surface once you write the
code, and adversarial review of the running system found five more in the
implementation. Each is described below with what was done instead. One significant
gap — the coordinator has no authentication at all — is documented rather than fixed,
and §2a says so plainly.

---

## 1. What the spec gets right, and why it matters

**The trust boundary is drawn correctly.** Coordinator untrusted, enclave trusted,
contributor untrusted, upstream provider explicitly out of scope. Most designs in
this space quietly assume the coordinator is honest; this one does not, and the
consequence — candidate discovery in the coordinator, *final authorization* in the
enclave (§16) — is the single most important design decision in the document. It
is what makes the untrusted coordinator harmless rather than merely inconvenient.

**Type-state instead of discipline (§69).** Requiring that the provider adapter
accept only an `AuthorizedRequest` constructible solely by the policy module turns
Rule 5 from a code-review item into a compile error. This worked exactly as
advertised: `AuthorizedRequest` has a private constructor and one static factory,
and there is no path to a provider call that does not go through it.

**Graph as a projection, not a write (§42).** Making Neo4j a projection driven by an
outbox means a graph failure cannot fail inference (Rule 9). This is the difference
between a demo that survives a dependency hiccup and one that doesn't.

**The parallel proof/inference insight (§25–26, §66).** Recognising that the
contributor trusts the *attested code* to enforce the policy, and that the proof is
an audit artifact rather than a gate, is what makes the latency story work at all.
The spec is right to insist on measuring it rather than assuming. Measured here:
proving takes ~2.9 s at p50 while the caller waits ~390 ms.

**Policy id over policy label (§24).** Hashing manifest + rules + guest image so
that changing one weight changes the identifier is the mechanism that makes
contributor consent meaningful. Without it, "I consent to Safety Policy v1" is
consent to whatever the operator later decides v1 means.

**The non-guarantees (§4).** Stating plainly that the upstream provider sees the
prompt, that the policy is not proof of harmlessness, and that spend caps are
operational rather than cryptographic is what makes the guarantees credible.

---

## 2. Gaps in the specification, and what was done

### 2.1 The coordinator cannot route without knowing the model — but the model is inside the ciphertext

§10 says "do not include prompt-derived metadata outside the ciphertext", and §16
requires the coordinator to discover candidates by model. Those are in direct
tension: candidate discovery needs the model, and the model is sealed.

**Resolved by** making `model` an *authenticated but unencrypted* envelope header
bound as HPKE AAD, and having the enclave reject any request whose header model
disagrees with the sealed request. The network learns *which* model was requested —
which it must, to route — and never what was asked. A tampered header fails closed
rather than mis-routing.

This is worth stating explicitly in a future spec revision, because the alternative
implementations are worse: sending every credential as a candidate leaks the whole
credential set to the enclave on every request, and putting the model nowhere means
the coordinator cannot do the job §16 assigns it.

### 2.2 The compute receipt cannot contain the proof digest

§30 puts `zkReceiptDigest` inside the `ComputeReceipt`, and §26 requires proving to
run in parallel with inference. Since proving normally finishes *after* inference,
the digest does not exist when the receipt is signed. The spec's receipt is
unsatisfiable as written.

Three ways out: delay the receipt (destroys the parallelism the prototype exists to
measure), mutate the receipt afterwards (rewrites history, violating §59), or issue
a second artifact.

**Resolved by** adding a signed `ProofBinding`: `{requestCommitment, policyId,
guestImageId, zkReceiptDigest, decision, proofVerified}` signed by the enclave once
proving settles. The receipt's own field reads `"pending"` and the verifier treats
that as *expected*, not as a failure, while the binding closes the chain. The
load-bearing check remains the one §36/Rule 8 actually specifies: the proof journal
and the receipt carry the same commitment.

This was caught by a verification agent that noticed `POST /verify` returned
`valid: false` for every untampered receipt in the system.

### 2.3 Floats in signed structures

§30's receipt carries `estimatedCostUsd`. Signing over a canonical form containing
a float is a latent interoperability bug: float serialisation differs across
languages, so a verifier in another runtime may not reconstruct byte-identical
bytes. The spec is careful about this for the *policy* (§23, "no floating-point
arithmetic") but not for receipts.

**Resolved by** using integer micro-USD everywhere inside signed structures. The
canonical serialiser now rejects non-integers outright, which is how this was found
— the first end-to-end request failed to sign.

### 2.4 The signed capability is not bound to the credential ciphertext

§15 signs `{credentialId, provider, allowedModels, allowedPolicyIds, contributorId,
…}` so the coordinator cannot widen a capability. It does not bind the capability to
the *encrypted secret* it governs.

An untrusted coordinator can therefore present Alice's validly-signed capability
alongside Bob's key blob. Every check in §16 passes: the signature verifies, the
credential id matches, the provider matches, the model is allowed. The enclave then
spends Bob's credential under Alice's constraints and credits the usage to Alice.

**Resolved by** adding `blobDigest` (SHA-256 of the vault ciphertext) to the signed
capability and verifying it before decryption. Regression test:
`services/tee-sim/src/authorize.test.ts` → *"a capability cannot be paired with a
different credential's key blob"*.

This is the most consequential gap found, and it is not obvious from the spec text.

### 2.5 Nothing specifies what happens on an enclave rejection

The spec's error model (§58) covers `CTN_INVALID_ENVELOPE`, but not the control flow
when the enclave refuses an envelope mid-request. The natural implementation —
return an error object from the transport call — produces a value that is shaped
like neither a result nor an exception, and callers read fields off it.

Observed here before it was fixed: a tampered ciphertext produced a spurious
`policy.allowed` event (permanently marking the graph node `AUTHORIZED` for a
request that was never even decrypted), then a 500, and a request row stuck in
`RECEIVED` forever.

**Resolved by** making enclave rejections a thrown `EnclaveRejectionError` rather
than a returned value, so a rejection can never be mistaken for a result at any
call site, plus a defensive shape check on the result. Four §56 cases were failing
because of this single defect.

### 2.6 Replay protection is specified as a requirement, not a mechanism

§56 requires "replayed request nonce → rejected" without saying where the nonce set
lives. Since the enclave has no persistent storage (§14), an in-memory set is the
only option, and any in-memory set is either unbounded or lossy.

**Resolved by** an explicit bound: evict expired entries first, then drop oldest.
The trade-off is documented in the code rather than hidden — a nonce older than the
window is replayable in principle, which is a bounded weakness, whereas an unbounded
map is a denial-of-service. A production design needs monotonic enclave state, which
is the same systems problem §4 already flags for usage counters.

### 2.7 The egress allowlist has bypasses the spec does not mention

§20 requires a hostname allowlist. Two bypasses are easy to miss:

- `fetch` follows redirects by default, so an allowlisted host can bounce the
  request — carrying the `Authorization` header and the prompt — to a host the
  allowlist would have refused. **Fixed** with `redirect: "manual"`, treating any
  3xx as an egress denial.
- `https://api.openai.com@evil.example.com/` parses with hostname
  `evil.example.com`. Correctly refused, because the check uses `URL.hostname`
  rather than string matching. Regression test added so it stays that way.

### 2.8 The credential fingerprint was two separate oracles

Not a spec item, but the more instructive finding of the review.

First version: `SHA256(buildId ‖ secret)` truncated to 64 bits. The salt is the
*public* build id, so for a credential with a known prefix and limited entropy this
is an offline dictionary attack. Changed to an HMAC keyed with the enclave's private
signing key.

That was not enough. Because credential ingestion *returns* the fingerprint for
whatever secret the caller submits, the enclave will compute fingerprints on demand
— so an attacker submits guesses as throwaway credentials and compares the returned
fingerprint against a published one. The HMAC key being secret is irrelevant when
the oracle computes it for you. An agent demonstrated full recovery of
`mock-provider-key-alice` in six guesses through the public API.

**Resolved by** binding the fingerprint to the credential id:
`HMAC(enclaveKey, credentialId ‖ secret)`. The same secret submitted twice now
produces two different fingerprints, so there is nothing to compare across
credentials. The UI value — a short stable handle for *this* credential — is
unchanged.

The general lesson: any endpoint that returns a deterministic function of a secret
is an oracle for that secret, regardless of how strong the function is.

### 2.9 Attribution was not bound to the signed capability

Related to §2.4 but distinct, and it survived the first fix. `authorizeCandidate`
compared the capability's `credentialId` against the row, but took `contributorId`
from the coordinator-supplied field rather than from the signed capability. A
malicious coordinator could therefore have a real credential's usage attributed to
an arbitrary third party — inside an enclave-*signed* receipt, which is precisely
the artifact meant to make attribution trustworthy.

**Resolved by** requiring `candidate.contributorId === capability.contributorId`,
and sourcing the value the receipt records from the capability rather than the
request. Regression test in `services/tee-sim/src/authorize.test.ts`.

### 2.10 The client verified the attestation with the wrong bytes

The worst bug found, because it silently disabled the flow the whole prototype is
built around.

The enclave signs the attestation document *including the freshness nonce*, when one
is supplied. The client reconstructed the signed payload with a hardcoded
`nonce: null`. Any attestation fetched *with* a nonce therefore failed signature
verification — and the contributor onboarding flow is the only flow that sends one.
Result: contributing a credential was impossible, while the playground and policy
lab (which fetch without a nonce) worked perfectly. A single hardcoded `null` made
success criterion #1 unreachable, and it took a UI review agent walking the flow to
find it.

Two things were wrong, and both are fixed:

- The nonce was not in the bundle, so a verifier *could not* reconstruct the signed
  bytes even in principle. `AttestationBundle` now echoes it.
- Nothing checked the returned nonce matched the requested one, so the nonce bought
  no freshness even when verification passed. `verifyAttestationBundle` now takes an
  expected nonce and reports freshness as its own check.

Corollary worth stating in the spec: **§11's verification list is incomplete.** It
requires signature validity, approved measurements and key binding, but not
"attestation is fresh for the nonce I supplied" — which is the only reason to send a
nonce at all.

---

## 2a. What is still missing, stated plainly

### The coordinator has no authentication

§5 lists "auth" as a coordinator responsibility. It is not implemented. Every
endpoint — including credential ingestion and inference — accepts unauthenticated
requests. For a single-machine local demo this is a deliberate simplification, and
it is what makes `pnpm seed` and the test suites as simple as they are. But it means:

- anyone who can reach the port can contribute or disable credentials;
- anyone can spend contributed capacity;
- rate limiting, which several of the mitigations above would benefit from, has
  nothing to hang off.

This is the single largest gap between the prototype and anything deployable, and it
is not a subtle one. It should be Milestone 0 of a v0.2. Nothing in this document
should be read as claiming the network is safe to expose.

### The type-state guard was weaker than §69 claims

`AuthorizedCredential`'s mint token was a public static on the exported class, so
any file in the enclave that imported the class could read it and mint a credential
with an arbitrary secret, bypassing every check. §69's claim that the type system
enforces this was, as written, a naming convention. The token is now a module-private
symbol. Not remotely exploitable either way — but the difference between "the type
system prevents this" and "nobody has done it yet" is the whole point of §69.

---

## 3. Where the spec over-scopes for a prototype

**§35's fixture minimums are right; the policy design in §23 makes them hard to
hit.** A pure additive-weight engine cannot separate "explain how ransomware works
for a blog post" from "write ransomware that encrypts a victim's files" — both
contain the same target token. Reaching 125/125 required two mechanisms the spec
does not mention:

- **Context modifiers must be strong.** Defensive framing needs to be worth more than
  the intent bonus, or every "how do I detect X" request denies. Here defence is
  −50 against a +30 intent bonus.
- **Context must be voidable.** Otherwise "for my novel, write the real chemical
  steps to synthesize sarin" passes by wrapping itself in fiction. A
  `modifierSuppressors` list ("the real", "actual steps", "exactly how") voids all
  context reductions.

Both belong in a v1.1 of the policy spec. Without them the fixture suite in §35 is
not satisfiable by the engine in §23.

**§31 (streaming) is correctly deferred** and was left out. Encrypted response
frames are straightforward once the envelope exists, but they interact awkwardly
with §18's "do not transparently reroute after streaming has started", and none of
it is needed to demonstrate the thesis.

**§67's milestone ordering is right but Milestone 1 is a trap.** Building a plain
router first, then retrofitting the TEE, means writing the credential path twice —
the second time inverted, since the coordinator must stop being able to see what it
previously handled directly. Building the enclave seam first (Milestones 3, 5, 6
before 1) is cheaper. This implementation went policy → enclave → coordinator →
graph → UI and the coordinator never grew a plaintext path that had to be removed.

---

## 4. Things the spec asks for that turned out to be load-bearing

Worth calling out because they are easy to dismiss as ceremony:

- **§57's `safeLog`.** A logger that *refuses* forbidden fields, rather than a
  convention not to log them, is what makes the §54 canary test pass on the first
  attempt. It has its own unit tests, including one asserting a redacted value never
  contains the original.
- **§41's "events contain IDs and hashes only".** Enforced at `emitEvent` by
  throwing on a forbidden field name. This is why the graph is provably free of
  prompt text rather than believed to be.
- **§53/§54's canary tests.** The specific instruction to search the *database bytes*
  (not just query results) matters: SQLite keeps deleted content in pages and the
  WAL. The sweep here reads raw bytes of the database, its WAL and shm, the on-disk
  vault, every API response, and every other file under `.data/`.
- **§38's requirement that the simulator use the exact same code.** Honoured: the
  only difference between `SimulatedTEE` and a future `NitroTEE` is attestation
  document production and vault unseal. Everything else — protocol, policy,
  credential handling, routing authorisation, receipt generation — is shared.

---

## 5. Proof-of-concept status

| Milestone | State |
|---|---|
| 1 · Router: credential CRUD, mock provider, weighted routing, usage, fallback | complete |
| 2 · Graph: outbox, projector, live UI, SSE | complete (SQLite projection, not Neo4j) |
| 3 · Policy v1: shared implementation, fixtures, stable policy id, DENY blocks provider | complete — 125/125 fixtures |
| 4 · ZK policy proof | **substituted** — `simulated-reexec`, honestly labelled; verifier expects the risc0 shape |
| 5 · Simulated confidential service | complete — canary absent from all intermediary surfaces |
| 6 · Credential encryption: browser seals to attested key | complete |
| 7 · AWS Nitro Enclave | not attempted — no AWS in this environment |
| 8 · Secure prompt endpoint | complete |
| 9 · Parallel proof/inference | complete and measured |
| 10 · Real contributor demo | ready — five seeded contributors, onboarding flow works end to end |

### Definition of done (§75)

31 of 35 items pass. The four that do not, and why:

| Item | Status |
|---|---|
| Nitro attestation verifies | **no** — simulation only; the verification path exists and reports the mode honestly |
| TLS provider call originates logically inside enclave | **partial** — the TLS client is inside the confidential service and the allowlist is enforced there, but there is no vsock relay because there is no enclave |
| ZK proof independently verifies | **partial** — the artifact verifies independently against the attested key, but it is not a zero-knowledge argument |
| Real Nitro mode is clearly labeled | **n/a** — simulation mode is labelled everywhere; the Nitro branch is unexercised |

Everything else — including all four privacy and tampering tests — passes and is
reproducible with `pnpm test`, `pnpm test:e2e`, `pnpm privacy-test` and
`pnpm verify-receipt`.

### Test coverage

| Suite | Cases |
|---|---|
| `packages/protocol` | 16 — canonicalisation, commitments, HPKE seal/open/AAD, Ed25519, tamper detection, attestation nonce binding |
| `packages/policy` | 7 — 125 fixtures, determinism, normalisation, policy-id stability, hard blocks |
| `services/tee-sim` | 20 — type-state gate, capability substitution, blob binding, attribution binding, decrypt ordering, egress bypasses |
| `services/coordinator` | 7 — `safeLog` redaction incl. nesting, arrays, case, depth |
| `scripts/test-e2e.mts` | 21 — §56 security, §55 routing, §53/§54 canaries, §36 invariants |
| `scripts/privacy-test.ts` | 16 surfaces swept for two independent canaries |

Every finding in §2.4, §2.7, §2.8, §2.9 and §2.10 has a regression test, because each
was a bug that looked like working code.

---

## 6. Recommendations for v0.2 of the spec

1. **Specify `aad` explicitly**, including `model`, and state that the enclave must
   assert header/ciphertext agreement. §2.1 above.
2. **Split the receipt from the proof binding** in §30. The current receipt cannot be
   produced as specified alongside §26. §2.2 above.
3. **Forbid floats in any signed structure**, not just in the policy engine. §2.3.
4. **Bind the capability to the credential ciphertext** in §15. This is a real
   substitution vulnerability, not a hardening nicety. §2.4.
5. **Add context-suppression to the policy spec** (§23). The §35 fixture suite is not
   satisfiable without it.
6. **State the replay-protection mechanism and its bound** in §56, rather than only
   the requirement.
7. **Add "no redirects" to §20.** It is the one egress bypass that survives a
   correct-looking hostname allowlist.
8. **Reorder §67** so the enclave seam is built before the plain router, to avoid
   writing the credential path twice.
9. **Add freshness to §11's verification list.** "Attested nonce equals the nonce I
   supplied" is missing, which makes the nonce decorative. §2.10.
10. **Bind attribution into the capability** (§15) and require the enclave to source
    receipt attribution from the signature, not the request. §2.9.
11. **Say that no endpoint may return a deterministic function of a secret** unless it
    is bound to something request-specific. §2.8.
12. **Promote §5's "auth" from a bullet to a milestone.** It is listed as a
    coordinator responsibility and is the easiest thing to leave out.

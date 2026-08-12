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
and §2a says so plainly. §2b records what Phase 1 changed once the prototype started
calling real providers with real keys, including the two places where the honest
answer costs something: an unknown upstream outcome is charged without a receipt, and
intent replay protection is forgotten across an enclave restart.

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
proving takes ~2.9 s at p50 while the caller waits ~490 ms — but the ~2.9 s is a
*modelled* proof cost, and §2c reports what a real one costs once measured. The
insight holds; the number was optimistic by roughly 20×.

(This clause previously said ~390 ms, disagreeing with the ~490 ms in README's
"Measured, not assumed" table. Both are snapshots of a live `GET /v1/stats` p50
rather than fixed constants, so neither is reproducible from the repo — but the
caller cannot wait less time than the provider call it is waiting on, and that is
~450 ms. ~490 ms is the internally consistent figure; ~390 ms was not.)

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

The same limitation applies to the contribution path (§5.1). The enclave refuses a
sealed `CredentialIntentV1` whose digest it has already consumed, but that set is
in memory: **a restarted enclave forgets, and a previously-consumed envelope could be
ingested once more.** What survives a restart is structural rather than remembered —
the credential id is sealed inside the intent, so a replayed envelope can only ever
re-mint the *same* capability for the *same* contributor, never a second credential
under a new id, and the coordinator's own unique-id check refuses the duplicate row.

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

## 2b. Phase 1 addendum — intent-bound contribution and real providers

Phase 1 replaced the mock-only inference path with live provider adapters, and doing
that turned several things the spec left as prose into mechanisms — a rule about
somebody else's money has to be enforced somewhere. Each is recorded here with what
it replaced, because in every case the previous version *looked* correct.

### Contribution is bound to a sealed intent, not to request metadata

Previously the contributor sealed a *secret* and the coordinator supplied everything
that gave it meaning — provider, allowed models, owning contributor — as ordinary
JSON fields alongside the ciphertext. The relay therefore chose the constraints on a
key it could not read, which is the wrong half of the pair to trust. Worse, the
enclave exposed a `recapability` endpoint that would re-sign a capability presented
to it: a widening oracle sitting behind the very check §15 exists to make impossible.

Now the contributor seals a `CredentialIntentV1` — `{version, credentialId, secret,
provider, allowedModels, allowedPolicies, contributorId, intentNonce}` — as one
canonical unit. The enclave derives the capability from the *sealed* fields and
ignores the body's, rejecting an envelope whose `credentialId` disagrees with the one
the coordinator posted. `recapability` is gone (the endpoint returns 404, asserted in
e2e case 60), and `PATCH /v1/credentials/:id` refuses `allowedModels` with
`CTN_CAPABILITY_IMMUTABLE`. Changing a capability now means contributing a new
credential, which is a contributor action by construction.

### Replay protection, and the restart caveat

The enclave keeps the digest of every consumed intent in memory and refuses a second
ingest of the same envelope (`CTN_INTENT_REPLAY`, relayed unflattened through the
coordinator — e2e cases 59 and 59.5). As §2.6 above records for request nonces, that
set does not survive a restart: **a restarted enclave forgets, and a previously
consumed envelope could be ingested once more.** What survives is structural rather
than remembered — the credential id is sealed inside the intent, so a replay can only
re-mint the *same* capability for the *same* contributor, never a second credential
under a new id, and the coordinator's unique-id check refuses the duplicate row.

It is also **unbounded by design**, and that is the deliberate half of the asymmetry
with `seenNonces` ten lines above it, which has a TTL, a cap, and oldest-first
eviction. Evicting a consumed intent digest would not trim memory so much as reopen
the replay window this set exists to close — the whole point is that the digest is
remembered *forever*, so an expiry is a scheduled vulnerability. The cost of not
bounding it is roughly 100 bytes per successful ingest, which at demo scale (tens of
contributions) is nothing, and the sealed `credentialId` means the worst case if it
ever did evict is re-minting the *same* capability, not a new one. The fix is not a
bigger `Set`: a durable answer needs monotonic enclave state, which is the same
systems problem §4 already flags for usage counters.

### One dispatch per request

§18's failure policy reads naturally as "try the next credential", and the
implementation did exactly that. With a real provider on the other end, that is a
rule about *someone else's* prompt and *someone else's* money: a 500 after the bytes
have left means the upstream may already have run the completion, and falling through
sends the same plaintext to a second contributor's account to be billed again.

The enclave now dispatches at most once. Only classifications decided *before*
anything leaves — `egress_denied` and `unpriced_model` — may be followed by another
candidate; everything else terminates the request and is reported to the caller, who
is free to retry (and pay for) it. A refused redirect is deliberately
`redirect_refused` rather than `egress_denied` for exactly this reason: the allowlist
stopped the second hop, but the prompt and the key already went out on the first.
E2E case 63 asserts the loop stops with an eligible credential left unused, which is
the only way to test a rule whose whole content is an action *not* taken.

### `UPSTREAM_OUTCOME_UNKNOWN`, and what it costs

A timeout, a mid-flight transport failure, or a 200 the adapter cannot parse leaves a
question the enclave cannot answer: did the provider run and bill this? The previous
code answered "no" by default (`?? 0`, `?? ""`), which made a wedged provider the
cheapest capacity on the network — every such request free of both cost and request
slot, and a credential drainable past its cap without a single counter moving.

Such an attempt is now flagged unknown and carries an assumed spend: a UTF-8-byte
upper bound on prompt tokens plus the full `max_tokens` at the pinned price. The
coordinator books it exactly like real usage — one request slot and one cost entry,
both writes in one transaction — with tokens recorded as 0, because no token count
was ever reported. E2E case 64 forces the timeout and asserts the booked dollars
equal the enclave's own bound rather than a number the coordinator invented.

The honest consequence: **an unknown-outcome request has no receipt in Phase 1.**
There is no answer to sign, so the request is visible as a provider attempt and a
usage row and nowhere else. A receipt that distinguishes measured spend from assumed
spend is Phase 2 work; until it exists, the usage ledger and the receipt corpus
disagree by design, and this paragraph is the reconciliation.

### Model consent names dated snapshots

Capabilities and the provider catalog name `claude-haiku-4-5-20251001`, never
`claude-haiku-4-5`. Consent to a movable alias is consent to whatever the vendor
points it at next month, which is not consent a contributor can reason about. E2E
case 65 fails if any published model id matches the alias shape.

### Real-provider smoke tests are opt-in, and cost money

Two e2e cases (70, 71) contribute a real key, send one 16-token prompt, assert the
receipt carries provider-reported token counts and the pinned price table's digest,
and revoke the credential in a `finally` so a failed assertion cannot leave a live
key routable — by label rather than by id, because the case worth designing for is a
contribution that persisted a row and then threw. They are skipped — with a printed
reason, and counted as skipped in the summary — unless the key is present:

```bash
ANTHROPIC_API_KEY=sk-ant-… OPENAI_API_KEY=sk-… pnpm test:e2e
```

They deliberately do not use the suite's rate-limit retry helper: a real 429 is the
result, not something to spend past.

### Revocation had to be made terminal before it could be described as terminal

Revocation is a `DELETE` (status `DELETED`) rather than a `DISABLED` that a later
`PATCH` could undo. That sentence was written first and was not true: the PATCH
handler took the caller's `status` string on trust — its TypeScript annotation was a
description, not a check — so `PATCH {status:"ACTIVE"}` revived a revoked credential,
and any unrecognised string could be written straight into the column routing reads.
A failure handler could do it accidentally too: an `auth_failed` dispatch already in
flight when the DELETE landed wrote `DISABLED` over `DELETED`, which is a status PATCH
*is* allowed to flip back to ACTIVE.

Now the coordinator refuses a status outside `{ACTIVE, DISABLED}` with 400
`CTN_INVALID_STATUS`, refuses any status write on a `DELETED` row with 409
`CTN_CREDENTIAL_DELETED`, and the failure handler's disable is written so it can never
resurrect a revoked row. The two rules are tested where each can actually be reached:
**e2e case 66** covers the API surface — both refusals, that they leave the row
untouched, and that no traffic reaches the credential afterwards — while the race is a
**coordinator unit test** (`routing.test.ts`, *"an auth_failed outcome cannot resurrect
a revoked credential"*), because no sequence of HTTP requests can schedule a dispatch to
land after a DELETE on purpose. A second unit test asserts a live credential is still
disabled by the same path, so the guard cannot pass by never disabling anything; both
were checked against the unguarded statement and the first one fails without it. The
dashboard drops the enable/disable control on a revoked row rather than offering a
button that can only error.

Still open, and listed rather than implied: `weight` and `operationalLimits` writes are
accepted on a `DELETED` row. They are inert — routing never reaches a non-ACTIVE
credential — but "deletion is terminal" would read better as a property of the whole
handler than of one field in it.

What revocation still does **not** do is erase the sealed ciphertext from the enclave
vault, so a key smoke-tested here should be rotated, or `pnpm reset` run afterwards.

### `max_tokens` defaults rather than being required

§5.1 lists `max_tokens` as required in the canonical request. It is not:
`toCanonicalRequest` supplies `1024` when the caller omits one, and 35 of the
prototype's call sites — the playground, the seed script, most of the e2e suite —
rely on that default rather than passing a number.

Recorded as a deviation rather than fixed, because the safety property the
requirement protects still holds. `max_tokens` is load-bearing for exactly one thing:
it is the ceiling in the assumed-spend bound above, so an absent one would make an
unknown outcome unboundable. A default of 1024 is finite, so the bound is finite, and
a contributor's cap still cannot be drained by a wedged provider. What is lost is
whose ceiling it is — the protocol's, chosen once for every caller who did not think
about it, rather than the contributor's or the caller's. `/v1/chat/completions` is
also the reason the default cannot simply be deleted: OpenAI's own schema makes
`max_tokens` optional, so the compatibility endpoint has to answer the question for
SDKs that never ask it. Making it required means choosing a default *there* instead,
which relocates this paragraph rather than retiring it.

---

## 2c. Phase 2a addendum — what proving actually costs (§66)

§66 is the section this prototype has been answering on credit. Phase 1 measured
everything on the request path and *modelled* the proof —
`CTN_SIMULATED_PROVING_MS`, default 2400 ms, labelled as modelled everywhere it
surfaced. Phase 2a Task 1 installs a real RISC Zero toolchain and replaces the
model with measurements. The guest here is a spike, not the policy engine: it reads
one length-prefixed frame and commits its sha256. The policy guest is Task 4. What
follows is therefore a floor for the real thing, and is written down as a floor.

Apple M1 Pro, 10 cores, 32 GB, macOS 26.0.1. risc0 3.0.6 (`cargo-risczero` 3.0.6,
`r0vm` 3.0.6, `risc0-zkvm` 3.0.6), host rustc 1.97.1, guest toolchain 1.97.0.
Release build, in-process prover (enforced), dev mode off, three timed runs per
measurement after one discarded warmup, median reported with min/max alongside.

**These are CPU numbers.** risc0 3.0.6 compiles Metal kernels on macOS and then
never calls them — the Metal branches of `segment_prover()` and
`recursion_prover()` are commented out in both circuit crates, falling through to
the CPU HAL. So this is what ten M1 Pro CPU cores cost, and a future risc0 that
re-enables the GPU path would change it by an unmeasured amount.

| Input | Executor only | Composite prove | Receipt (bincode) | Verify (cache-hot) |
|---|---|---|---|---|
| 256 B | 16.9 ms (15.5–22.4) | 5.70 s (5.61–5.81) | 216.1 KB | 12.2 ms |
| 4096 B | 18.3 ms (18.1–18.5) | 50.49 s (49.07–50.66) | 262.0 KB | 14.9 ms |

| Input | Segments | po2 | User cyc | Total cyc | Paging cyc | Reserved cyc |
|---|---|---|---|---|---|---|
| 256 B | 1 | 16 | 24,927 | 65,536 | 24,870 | 15,739 |
| 4096 B | 1 | 19 | 265,498 | 524,288 | 26,854 | 231,936 |

A second full run of the same binary drifted by up to **5.7%** — that worst case
being verify at 256 B, the smallest measurement here; prove at 4096 B moved 3.6%,
to 52.30 s. Between-run drift therefore exceeds the within-run spread at 4096 B,
so read every timing above as **±6%** rather than as a constant, and treat a few
percent of movement between future runs as meaningless. The cycle counts, po2 and
receipt sizes were byte-identical across both runs.

**The model was optimistic by roughly 20×.** Phase 1 assumed 2.4 s of proving and
observed ~2.9 s at p50. Real composite proving of a program that only hashes 4 KB
takes 50.5 s. §66's architectural claim survives this — proving runs parallel to
inference and the caller does not wait for it — but the claim that survives is
narrower than the one the README currently implies. At ~450 ms of inference and
~50 s of proving, the proof is no longer "concurrent with the request"; it finishes
long after the response has been returned and the connection closed. That is still
a coherent design, because §25–26 make the proof an audit artifact rather than a
gate. It is not the design the p50 table describes. The honest framing is that
receipts become available seconds to minutes after the answer, and anything that
waits on a receipt — the verifier UI, the graph projection — has to be built for
that. Phase 1's numbers are not being restated here as wrong; they were correctly
labelled as modelled, and this is what the measurement turned out to be.

**Executor latency is a fixed ~17–18 ms floor.** This is the number that would gate
a live request, and it barely moves with input: 16.9 ms at 256 B, 18.3 ms at
4096 B, across a 10.6× difference in user cycles. The 1.4 ms between those medians
is smaller than the run-to-run spread at 256 B, which by itself covers
15.5–22.4 ms, so the marginal cost of the extra cycles is real but below this
sample's noise floor rather than separable from it. The bulk is session setup.
Two consequences. Running the policy in the zkVM on the request path would add
~20 ms whatever the prompt, which is affordable against a ~450 ms provider call.
And it cannot be optimised by trimming input, so Phase 2b should treat it as a
constant.

This paragraph originally said 23 ms at 256 B and pointed at the *inversion* —
the small input measuring slower than the large — as the evidence. That was an
artifact of the harness, not a property of the zkVM: sizes ran in a fixed order
with no warmup, so first-call cost landed entirely on the first row. The
conclusion happened to survive re-measurement, but it had been argued from a
number whose sign was wrong, which is precisely the failure this document exists
to catch. `--bench` now discards a warmup iteration per size and prints
min/median/max.

**Proving cost is set by paging as much as by arithmetic.** `reserved_cycles` is
documented as the cycles the proof system needs *including padding up to the
nearest power of two*, and the numbers agree: `total_cycles` lands on exactly 2^po2
in both rows, with reserved as the filler. The real work is user + paging — 49,797
at 256 B, rounding to 2^16; 292,352 at 4096 B, rounding to 2^19 — which gives a
planning rule for Tasks 4 and 7: **po2 ≥ ceil(log2(user + paging))**. A bound
rather than an equality, because two rows consistent with `reserved` being pure
padding cannot prove that it is; if some fixed non-padding allocation hides in
there, the 256 B row caps it at 15,739 cycles, so the rule can under-predict by one
po2 within ~15k cycles of a boundary. Note that
paging is roughly half the real work at 256 B (24,870 against 24,927 user cycles),
so the policy guest's memory access pattern will move its po2 as readily as its
arithmetic. It also means po2 cannot be predicted from user cycles alone: an
earlier draft of this section claimed 24,927 and 65,535 user cycles would both fit
po2 16, but 65,535 plus even this spike's modest paging lands in po2 17. Time then
scales near-linearly with padded rows — 8× the rows cost 8.85× the time, about
0.09 ms per row — so the extrapolation is ~105 s at po2 20 and ~210 s at po2 21.

**A composite receipt is ~250 KB.** The spec treats the proof as an artifact to be
stored and independently verified; at a quarter of a megabyte each, growing with
execution length, that is a real storage decision rather than a detail. Groth16
compression would make it constant-size and small, at the cost of extra proving
time. Neither was measured. Task 6 should measure both before the release manifest
fixes a receipt format, because that choice is hard to reverse afterwards.

### What the plan assumed that turned out to be false

The plan's API sketch was drawn from risc0 2.x. The anchors it named still exist
in 3.0.6 and still needed adjusting.

`env::read_frame` — the guest's input path — is marked `#[stability::unstable]`
and does not compile without opting the guest into the `unstable` feature. Its
host-side counterpart, `write_frame`, is stable. Rather than put the policy
guest's only input path behind an unstable flag, the guest reproduces `read_frame`
on the stable `read_slice`: the same two reads, the same wire format, so it stays
compatible with the stable writer.

### Three silent defaults, all pointing the same way

The more useful finding is not any single number but a pattern: `risc0-zkvm`'s
defaults will quietly measure something other than what you meant, and say
nothing. Each of these was caught, but only one of them was caught before it had
already been written down as a result.

`prove` is not a default feature. Without it, `default_prover` and
`default_executor` fall back to an `r0vm` subprocess over IPC — silently, no error,
no warning. The first run of this benchmark was taken that way and reported ~28 ms
of executor latency; in-process and warm it is ~17 ms. That particular comparison
is cold-against-warm — the ~28 ms predates the warmup fix — so it is indicative of
the direction and rough size of the IPC cost, not a measurement of it. Even
discounted for that, a silent default inflating the number by something like half,
for a measurement whose entire purpose is establishing a ~20 ms request-path
budget, is the kind of thing that gets quoted for a year.

`bonsai` **is** a default feature, and `default_prover` tests for `BONSAI_API_URL`
and `BONSAI_API_KEY` *before* it reaches the local branch. Had those variables
been present in the environment, proving would have gone to remote hardware over a
network and the timings would have described someone else's machine. Nothing in
the output would have said so. `default-features = false` now removes the branch
at compile time, and `--bench` refuses to run unless the backend reports `local` —
enforcement rather than reporting, because the first version of this harness
printed the backend and would still have happily benchmarked the wrong one.

`RISC0_DEV_MODE` makes proving a stub that returns instantly and verification
accept anything. `--bench` refuses to run under it.

The harness had one silent default of its own, and it is the one that got through:
no warmup, fixed size order, median-only reporting. That is what produced the
23 ms figure corrected above. Printing min/median/max would have exposed it
immediately, which is why it now does.

### The two engines read different Unicode versions, and only one direction of that is safe

The policy engine now exists twice: `packages/policy/src/engine.ts`, which the
gateway enforces, and `prover/policy-core`, which is what the zkVM guest will
re-execute and therefore what a proof is actually about. `scripts/differential-test.ts`
holds them together — 125 fixtures plus 500 generated Unicode adversarial cases
per run, compared on `normalize()` output, decision, the per-category score
vector (values and order), `intentPresent`, `constructionPresent`, `hardBlock`
and `modifiersApplied` — and it is wired into `pnpm test`, so a divergence fails
the build rather than being discovered later.

They are not, however, equivalent on *all* input, and the honest statement of the
gap is this: **the two engines agree exactly on text made of code points assigned
in Unicode 16.0; on code points assigned only in Unicode 17.0 the Rust engine is
stricter, never laxer.** Node's V8/ICU is pinned to Unicode 16.0
(`process.versions.unicode`); the Rust side reads Unicode 17.0 through
`unicode-normalization`, `unicode-properties` and `str::to_lowercase`. A sweep of
all 1,112,064 non-surrogate code points finds 133 where the two normalizers
disagree — every one of them a character V8 sees as unassigned (`\p{Cn}`) and
passes through untouched while Rust classifies and folds it. Injected into a live
DENY-adjacent phrase, 104 of those 133 flip the decision, and all 104 flip the
same way: ALLOW on the TypeScript engine, DENY on the Rust one. Zero flip the
other way. That asymmetry is the whole safety argument — the guest can refuse
something the gateway would have allowed, which costs a user a request; the
reverse would mean a proof asserting "checked against Safety Policy v1" for a
request the gateway itself rejected, which would be a lie. The differential
harness asserts the direction on every run and fails hard on a single
DENY→ALLOW flip, so a dependency bump on either side cannot quietly invert it.

This is a real limitation, not a solved problem. It resolves properly only when
both engines read the same Unicode tables, which in practice means pinning them —
Task 6's release manifest has to pin the Rust *toolchain* as well as the two
crates, because `str::to_lowercase` is a third table source that floats with
whatever stable compiler is installed.

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
| 1 · Router: credential CRUD, mock provider, weighted routing, usage | complete |
| 2 · Graph: outbox, projector, live UI, SSE | complete (SQLite projection, not Neo4j) |
| 3 · Policy v1: shared implementation, fixtures, stable policy id, DENY blocks provider | complete — 125/125 fixtures |
| 4 · ZK policy proof | **substituted** — `simulated-reexec`, honestly labelled; verifier expects the risc0 shape |
| 5 · Simulated confidential service | complete — canary absent from all intermediary surfaces |
| 6 · Credential encryption: browser seals to attested key | complete |
| 7 · AWS Nitro Enclave | not attempted — no AWS in this environment |
| 8 · Secure prompt endpoint | complete |
| 9 · Parallel proof/inference | complete and measured |
| 10 · Real contributor demo | ready — five seeded contributors, onboarding flow works end to end; live Anthropic/OpenAI adapters behind two opt-in smoke tests (§2b), with the seeded demo traffic still served by the mock upstream |

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
| `packages/protocol` | 19 — canonicalisation, commitments, HPKE seal/open/AAD, Ed25519, tamper detection, attestation nonce binding |
| `packages/policy` | 7 — 125 fixtures, determinism, normalisation, policy-id stability, hard blocks |
| `services/tee-sim` | 48 — type-state gate, capability substitution, blob binding, attribution binding, decrypt ordering, egress bypasses, pricing, adapter response validation, sealed-intent parsing |
| `services/coordinator` | 14 — `safeLog` redaction incl. nesting, arrays, case, depth, key names and `sk-` values; assumed-spend cap accounting and its rollback; the failure handler's inability to resurrect a revoked credential |
| `scripts/test-e2e.mts` | 28 — §56 security, §55 routing, §53/§54 canaries, §36 invariants, §5.1 sealed intent, single dispatch, unknown outcomes, the provider catalog and terminal revocation — plus 2 env-gated real-provider cases, counted as skipped in the summary rather than silently absent |
| `scripts/privacy-test.ts` | 16 surfaces swept for two independent canaries |
| `prover/policy-core` | 12 — 10 normalizer/matcher/scoring unit tests, plus the 125 fixtures run against the ground-truth labels and a determinism replay |
| `scripts/differential-test.ts` | 625 per run against the Rust engine — 125 fixtures + 500 generated Unicode adversarial cases (random seed, printed, overridable via `CTN_DIFF_SEED`), compared on normalisation, decision, score vector order and values, intent/construction/hard-block/modifiers; plus the 7-code-point zero-width strip set and a 1,112,064 code point skew sweep asserting every divergence is fail-safe |

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
13. **Seal the capability's terms, not just the secret** (§12/§15). Constraints
    supplied by the relay are constraints chosen by the party they constrain. §2b.
14. **State the dispatch bound in §18.** "Try the next credential" is written as a
    resilience policy and reads, against a real provider, as permission to send the
    same prompt to a second contributor's account. §2b.
15. **Give §30 a place to put spend that was assumed rather than measured.** The
    receipt as specified can only describe requests that returned an answer, which is
    why an unknown outcome currently has none. §2b.

# 3CP Conformance Map — Gleipnir

**Purpose**: map each normative requirement of 3CP v2 to the code that implements it, or
record that it is not implemented. So that conformance is a claim that can be checked,
rather than an assertion about code nobody has read against the spec.

**Specification**: `had-nu/3CP`, `spec/SPEC-3CP-V2.md`, at commit `72a5e4b` (2026-10-05).
Fetch it with `./scripts/fetch-3cp.sh`, which caches it in `.3cp/` (gitignored — the spec
is canon and a vendored copy drifts). Cite `.3cp/SPEC-3CP-V2.md`.

**Why this exists.** The code in this repository cites spec sections in comments, but
never systematically. Three consecutive defects were diagnosed by reading code rather
than by reading the spec, and each diagnosis was wrong. See
`docs/VERIFICATION-PLAYBOOK.md` §1. This document is the answer for conformance work:
every claim about what the protocol requires gets a section number, and every
divergence is written down rather than resolved silently in code.

## Which spec file

`SPEC-3CP-V2.md` is the canonical file. The 3CP README calls it *"Current normative
specification (v2.0)"* and its structure diagram marks it *"← normative protocol
specification v2.0 (RFC 2119)"*; `CONTRIBUTING.md` routes every normative change to it.

`3CP-v2.md` is a **second, newer document inside the same repository** that contradicts
the canonical one:

| Section | `SPEC-3CP-V2.md` MUSTs | `3CP-v2.md` MUSTs | |
|---|---|---|---|
| §2 | 0 | 1 | `3CP-v2.md` adds one |
| §4 | 4 | 6 | `3CP-v2.md` adds two — and gets §4.3 wrong |
| §5 | 9 | 9 | agrees |
| §6 | 5 | **6** | `3CP-v2.md` adds the §6.5 metadata MUST |
| §7–§17 | equal | equal | agree on count |

Two of those extra requirements are real and the code implements both:
`Metadata["3cp:degraded-block"] = true` (§6.5, `prepare.go:139-143`) and the two-point
Elligator sum (§4.3, `vrf.go`). The canonical file expresses §4.3 by reference —
*"ECVRF-EDWARDS25519-SHA512-Elligator2, conforme RFC 9381"* — which, checked against
RFC 9380 §3, is the same construction.

**Cite `SPEC-3CP-V2.md`, and verify the quote.** Section numbers alone are not sufficient:
the two files agree on numbering and disagree on content in §2, §4, §6 and §6.5.

---

## §6 — Two-Phase BFT Consensus

### §6.1 The cycle is divided into two atomic phases

**[MUST]** *"The cycle is divided into two atomic phases: PREPARE and COMMIT."*

Implemented, but with a divergence. See D1.

### §6.2 Step 1 — Leader election

**[MUST]** *"`StateRoot_at_cycle_start` is the SMT root **before** inserting any entries
of cycle `c`. `alpha` is fixed at cycle start and does not change during phases."*

**Implemented.** `engine.go:690` takes `rootArr := e.st.Root()` before `RunPreparePhase`,
which inserts. `engine.go:544-574` derives the cycle number from `len(e.blocks)`.

The alpha-derivation comment at `engine.go:566-571` records a genuine contradiction in the
spec itself: §6.2 defines `alpha_c = c || StateRoot_at_cycle_start`, while §6.4 defines the
post-abort input as `alpha_{c+1} = (c+1) || H(B_{c-1})` — a different second component, and
an advance past an index that produced no block. **This is a question for the
specification, not a code decision.** §6.2 is followed as normative. Filed as a spec
question, unresolved.

### §6.2 Step 2 — Proposal

Block fields map to `prepare.go:123-136`: `Index`, `PrevHash`, `StateRoot`, `Proposer`,
`Anchored`, `Lambda1`, `Timestamp`, `Validators`, `Quorum`.

`ProtocolVersion: 2` is set at `prepare.go:133`. §6.2 Step 3 check 5 requires it to be
verified on receipt — the proposer sets it, but see D2 for whether validators check it.

### §6.2 Step 3 — PREPARE voting

Required checks:

| Spec check | Code |
|---|---|
| 1. `PrevHash == H(B_{c-1})` | `prepare.go:103-105` (accepts locally, not verified) |
| 2. `StateRoot == Root(SMT after E)` | `prepare.go:227-232` |
| 3. each `e ∈ E` passes `validateEntry` | not verified on receipt — see D3 |
| 4. `Lambda1 >= MinLambda1` | `engine.go:740-747` via `state.Apply` |
| 5. `ProtocolVersion == 2` | **not checked** — see D2 |

**The spec has no timeout in Step 3.** It says *"Each validator `v_j` receives `B` and
verifies"* — the receipt of `B` is assumed, not awaited. The code waits, with
`waitForProposal` at `prepare.go:211`, bounded by `proposalWait()`. See D4.

### §6.3 Step 4 — Quorum collection

**[MUST]** *"If the leader fails to collect `Q` signatures within `CycleTimeout`, the cycle
is **aborted**. Entries `E` remain pending. Cycle `c` produces no block."*

**Implemented.** `prepare.go:314-324` waits bounded by `proposalWait()`; on failure
`engine.go:705-711` retains `allPending`, restores `stateSnapshot`, advances the attempt
counter, returns without appending.

### §6.3 Steps 5–6 — Final block construction, broadcast, validation

`commit.go:33-77` builds `B_final`; `commit.go:88` waits for it; `commit.go:94` verifies
quorum via `verifyPrepareQuorum`; `commit.go:112` verifies the leader COMMIT signature.

The bitmap/payload pairing at `commit.go:48-59` implements the §5 requirement that payload
entry `i` belongs to the `i`-th set bit, not to validator `i`. That pairing is exactly
what a light client must reproduce, and `verifyPrepareQuorum` (`commit.go:134-177`) is the
mirror of it.

### §6.4 Aborted cycle

**[MUST]** *"If a cycle aborts (PREPARE timeout, insufficient quorum, or `λ₁ <
MinLambda1`): No block is appended. Entries `E` remain in the pending queue. Cycle `c+1`
starts with new VRF election."*

**Diverges.** First two clauses implemented (`engine.go:705-711`). The third is not:
`nextCycleLocked()` returns `len(e.blocks)`, so an aborted cycle is **retried at the same
index**, not advanced to `c+1`. See D5.

### §6.5 Degraded mode

**[MUST]** *"If `N < 4`, the protocol operates in `degraded` mode: `Q = 1`. Each block MUST
contain `Metadata["3cp:degraded-block"] = true`. Exiting requires `N >= 4` and `GraceCycles`
consecutive cycles (default: 10)."*

**Implemented.** `engine.go:685-688` sets `requiredQuorum = 1`; `prepare.go:139-143` sets
the metadata label; `pkg/lightclient/service.go:303-308` enforces the marker on the verify
path, as a third party would.

---

## §10 — Adaptive cycle and entry retention

### §10.1 Cycle duration

**[MUST]** *"CycleDuration = BaseInterval + NetworkLatencyEstimate =
EWMA(RTT) * SafetyFactor"*, BaseInterval default 3000ms, MaxCycleDuration 10000ms hard cap.

**Partially implemented.** Base interval and the 10s cap are present
(`engine.go:540-541` sets `cycleTimeout = cycleDuration`). The `EWMA(RTT)` term and
`SafetyFactor` — the parts that make it *adaptive* — are not implemented.
`pkg/state/config.go:17` declares `SafetyFactor float64 // EWMA(RTT) * SafetyFactor` and
`config.go:36` sets the default 1.5, but nothing measures RTT: `grep -ri ewma --include='*.go' pkg/`
returns no calculation. `cycleDuration` is not a function of measured latency, so the cycle
is not adaptive in the sense the MUST requires — only configurable.

This matters for D4: the proposal wait is derived from `cycleTimeout`, and `cycleTimeout` is
supposed to grow with observed latency. It does not, so the wait has no relationship to the
network it is meant to tolerate.

### §10.2 Pending entry retention

**[MUST]** *"Pending entries are **never discarded** due to cycle expiration."*

**Implemented.** `engine.go:697` and `707` both retain `allPending` on abort.

**[MUST]** *"Entries pending for more than `MaxPendingTTL` cycles (default: 100) are
rejected with error `ErrPendingExpired`."*

**Not implemented.** No `ErrPendingExpired` exists anywhere in the repository.
`MaxPendingTTL` appears in `cmd/genesis/main.go:59,237,267` as a genesis config field with
the default of 100, but no code reads it after that — it is configured and then ignored.
The first MUST ("never discarded") is honoured; the second (TTL rejection) is not implemented
at all, so pending entries are retained without bound.

### §10.3 Empty cycle

**[MAY]** *"If `SkipEmptyCycles == true` and no entries are pending, the cycle may be
skipped."*

Implemented at `engine.go:662-666`.

---

## Open divergences

### D1 — PREPARE runs twice per cycle

**Spec** §6.2 Step 3 and §6.3 Step 4 are one pass each. §6.1 says the cycle is *"divided
into two atomic phases"*.

**Code** `engine.go:692-711` calls `RunPreparePhase` twice — once with `checkQuorum=false`,
once with `checkQuorum=true`. The second call re-runs proposal retrieval, verification and
signature publication for every node.

**Consequence** — this is the measured deadlock. A validator that has passed its first
PREPARE re-enters the phase and waits for the proposal again. Under delivery delay the
proposal has not arrived, the second wait expires, and the cycle aborts with
`QUORUM CHECK failed: no proposal from proposer for quorum check`.

Reproduced by `TestCycleCompletesWithDelayedDelivery` (`pkg/consensus/phase_deadlock_test.go`):
`MemoryBus` commits on all five nodes, `networkBus` with a 20ms delay commits on none.

**Not yet fixed.** The spec does not describe two passes, which is evidence the second call
is not a normative requirement — but removing it changes protocol flow and needs its own
review.

### D2 — `ProtocolVersion == 2` is set but not checked

**Spec** §6.2 Step 3 check 5: *"`B.ProtocolVersion == 2` (in v2 networks)"* is a
verification a validator performs on the block it receives.

**Code** `prepare.go:133` sets it to 2 on the propose path. A validator receiving a block
does not check it — the non-proposer path (`prepare.go:205-247`) verifies the SMT root, the
block hash and the signature, and stops there.

A block from a v1 network would be accepted by a v2 validator.

### D3 — `validateEntry(e)` is not applied to received entries

**Spec** §6.2 Step 3 check 3: *"Each `e ∈ E` passes `validateEntry(e)`"*, performed by the
validator on the entries in the block it receives.

**Code** entries are validated at `Enqueue` (`pkg/server`, `Engine.Enqueue`) on the node
that received them, but a validator accepting a proposal runs no per-entry validation on
`block.Anchored`. `prepare.go:218-225` inserts them into the SMT without validating.

So an entry that bypassed `Enqueue` validation on its origin node — or that arrives from a
malicious proposer — is not re-checked by the other four validators. `Engine.Enqueue`
rejects zero hashes, empty submitters and oversized labels, but only locally.

### D4 — `waitForProposal` has no basis in §6.2

**Spec** Step 3 begins *"Each validator `v_j` receives `B`"*. Receipt is assumed.

**Code** `prepare.go:211` waits, bounded by `proposalWait()` = `cycleTimeout/4`.

There is no normative proposal timeout. The spec's only timeout in §6 is `CycleTimeout` on
quorum collection (Step 4). The wait is a reasonable BFT construction and is probably
necessary in a real network — but it is an addition, and it is the addition whose expiry
currently aborts every cycle. **Any change to its duration is a change to something the
spec does not govern**, and should be justified on measured behaviour, not on the spec.

### D5 — An aborted cycle retries the same index

**Spec** §6.4: *"Cycle `c+1` starts with new VRF election."*

**Code** `engine.go:572` `nextCycleLocked()` returns `len(e.blocks)`. An abort appends
nothing, so the next attempt uses the same `c` and the same `alpha`, re-electing the same
leader. The spec says advance; the code says retry.

This interacts with D1: the proposer that aborted never commits, so the index it retries is
also the index the rest of the network retries, and it fails the same way indefinitely.
That is why the topology holds at one block rather than making progress.

Note that `engine.go:566-571` already records the related §6.2/§6.4 contradiction about
alpha. The index-advance question is the same contradiction seen from the other side, and
the two comments should be reconciled.

### D6 — Reserved key 8 is not rejected on decode

**Spec** §5.3:

> **[MUST]** Key 8 (`Sigs` in v1.0) is **reserved and MUST NOT be used** in blocks with
> `ProtocolVersion == 2`. A block with `ProtocolVersion == 2` and key 8 present and
> non-null **MUST** be rejected with `ErrReservedFieldPresent`.

**Code** `pkg/chain/cbor.go:26-32`. `UnmarshalCBOR` calls `cbor.Unmarshal` into a `Block`.
The `Block` struct has no field for key 8 — correctly, since Gleipnir never emits it — so the
CBOR library discards it silently.

The requirement has two halves and only one is met. Not emitting the field is satisfied.
Rejecting a block that carries it is not, because nothing inspects for it.

**Measured.** `TestRejectsReservedKey8InV2Block` in `pkg/chain/reserved_field_test.go`:

```
a v2 block carrying reserved key 8 was accepted and decoded as ProtocolVersion=2;
3CP §5.3 requires rejection with ErrReservedFieldPresent
```

The baseline is checked first — a valid v2 block without key 8 decodes fine — so the failure
is specific to the reserved key and not to the fixture.

`ErrReservedFieldPresent` does not exist anywhere in the repository. Nothing can return it.

**Reach.** `pkg/lightclient/service.go:250` rejects a `ProtocolVersion != 2` block but has no
check for key 8, so a third-party verifier accepts what the spec says must be rejected. The
gap is on the verification path, which is the path an auditor relies on.

This is the §17 migration guarantee resting on an unstated convention. §5.3 closes with:
*"Key 8 never has two meanings within the same network: v1→v2 migration is a hard fork, not a
gradual field-semantics transition."* The convention holds only if every implementation
enforces it, and this one did not.

**Fixed** in `pkg/chain/cbor.go`. `UnmarshalCBOR` now calls `rejectReservedKeys` before
decoding, which inspects the raw map and refuses key 8 when `ProtocolVersion == 2` and the
value is not null.

Scoped to key 8 rather than to every unknown key. §5.3 reserves this one field, and a
decoder that refused all unknown keys would reject extensions the spec has not discussed —
which is a different defect, not a stricter reading of this one.

`ErrReservedFieldPresent` is defined in `pkg/chain` because `pkg/validation` imports
`pkg/chain` and the dependency cannot run the other way. `validation.ErrReservedFieldPresent`
aliases it rather than declaring a second value, so `errors.Is` works across the boundary.

`TestAcceptsBlocksTheSpecAllows` pins the four cases this must not break, each of which the
spec requires the decoder to accept:

| Case | §5.3 |
|---|---|
| v2 without key 8 | valid |
| v1 carrying key 8 | §5.3 scopes the reservation to `ProtocolVersion == 2` |
| v2 with key 8 explicitly null | rejects "present and **non-null**" |
| unknown non-reserved keys | §5.3 reserves key 8 only |

### D7 — Mandatory anchor backends are stubs, and they are a MUST violation

**Spec** §12.1:

> **[MUST]** Mandatory backends: Local filesystem, IPFS (CIDv1, codec `raw`, hash `blake3-256`
> or `sha2-256`), S3-compatible blob store (with SHA-256 checksum).

All three are mandatory. There is no "if configured" qualifier.

**Code** `pkg/anchor/anchor.go:257` reads `// TODO: Implement actual IPFS client connection`,
and `NewIPFSPublisher` returns a publisher that simulates publishing. `NewS3Publisher`
(`anchor.go:333`) is in the same state. Only `NewFilesystemPublisher` (`anchor.go:187`) works,
and it is what `consensus/engine.go` actually uses.

**This is a correction to `IMPLEMENTATION-STATUS.md` §2.1**, which classifies the IPFS and S3
stubs under *"Not attempted because of a real constraint"* — legitimate engineering boundaries
to be documented rather than fixed. That classification is wrong on the spec's own terms: §12.1
says MUST, not SHOULD, and the spec does not offer an out for "requires credentials".

The reasoning behind the original classification still holds as an implementation constraint —
no test can distinguish a working publisher from a broken one without a peer or an account. But
a documented constraint on a SHOULD is a decision; a documented constraint on a MUST is an
unimplemented requirement. It belongs in this section, not in the constraints.

**Consequence for an auditor.** §12.3 makes third-party verification depend on blocks being
published where an auditor can read them. With one of three mandatory backends unimplemented
and two simulated, the property the README offers an auditor rests on a backend that writes to
a local directory.

**Not fixed here.** Both need infrastructure — an IPFS peer in CI, a MinIO container — before
they can be verified rather than merely written. That is a sequencing constraint, not an
exemption: until it is satisfied, Gleipnir is not §12.1-conformant and should not be described
as such.

### D8 — UID0 HKDF info strings are not the spec's

**Spec** §14.2:

> **[MUST]** The 32-byte seed for identity derivation is:
> `seed = HKDF-SHA256(salt = NetworkID, info = "3cp-uid0-v2", ikm = entropySource)`

**Code** `pkg/identity/uid0.go:53-59`. The PRK is derived from the spec's salt and IKM, then
expanded under four info strings of the implementation's own:

```
"3cp:v2:dilithium3"   "3cp:v2:vrf"   "3cp:v2:rootid"   "3cp:v2:contract"
```

The string `"3cp-uid0-v2"` appears nowhere in the repository (`grep -rn "3cp-uid0-v2" --include='*.go'`
returns nothing).

**Consequence.** Two implementations that agree on the PRK and disagree on the info derive
different identities — different RootID, different Dilithium key, different VRF key. That is
the interoperability break §4.3's two-point Elligator MUST exists to prevent, one layer up:
§4.3 states it explicitly because the same input must produce the same election everywhere,
and this is the same failure in the identity layer.

**Blast radius.** Every UID0 generated under these strings has a different identity than the
spec prescribes. `provectl init` produces them, so the shipped five-validator topology runs
on non-conformant identities. Changing the strings invalidates them, which makes this a
migration, not a patch.

**Not fixed here.** The direction is unambiguous — the spec's string is the one to use — but
the change needs a decision about existing identities that is not mine to make.

### D9 — the UID0 entropy floor is a length check

**Spec** §14.2:

> **[MUST]** `entropySource` MUST contain at least 128 bits of effective entropy.
> Implementations SHOULD reject `entropySource` with estimated entropy < 80 bits.

**Code** `pkg/identity/uid0.go:47` — `if !simulated && len(entropySource) < 32`. A 32-byte
string of a single repeated character satisfies this and carries no entropy.

The MUST is about *effective* entropy and cannot be decided by length. The SHOULD is about an
*estimate*, which no code here performs.

**Escape hatch.** `simulated=true` skips the check entirely, which is what the compose
topology relies on through `IPC_ALLOW_SIMULATED_IDENTITIES`. That is a reasonable test
affordance and the flag is visible on the wire (`cbor:"7,keyasint"` on `UIDZeroSoulbound`),
so a node using it is identifiable rather than silently weakened. It does mean a production
deployment could enable it and never be noticed by the protocol.

---

### D10 — the two spec files contradict each other on the VRF construction

**Not a Gleipnir defect.** Recorded because it nearly became one, and because it changes
which document this file is written against.

`spec/SPEC-3CP-V2.md` §4.3 — the canonical one — says:

> **Algoritmo:** ECVRF-EDWARDS25519-SHA512-Elligator2, conforme RFC 9381.

`spec/3CP-v2.md` §4.3 — the newer file — instead specifies an explicit two-point sum and
describes it as a departure from *"the single-point map of RFC 9381 §4.1.2"*.

Read against the actual RFCs, the second file's reasoning does not hold:

- RFC 9381 §4.1.2 is **RSA-FDH-VRF Proof to Hash**. It has nothing to do with
  hash-to-curve. The relevant section is RFC 9381 §5.4.1.2, which selects the
  hash-to-curve form through `h2c_suite_ID_string`.
- The two-point sum is **not a departure from the RFC**. It is RFC 9380 §3 `hash_to_curve`
  verbatim: `hash_to_field(msg, 2)`, map each, add them, clear the cofactor. RFC 9380 also
  defines a one-point `encode_to_curve`; the two differ in output distribution (uniform
  versus non-uniform), and ECVRF uses the uniform one.

So both spec files arrive at the same construction — the two-point sum — and the code
implements it (`vrf.go`, `p0.Add(p0, p1)`). **The conclusion agrees; only the justification
in `3CP-v2.md` is wrong.**

**Why this matters here.** A reader following `3CP-v2.md`'s framing would expect an
override — "the spec departs from the RFC, do not correct it toward the RFC" — and a
comment in this repository said exactly that. It was wrong in a way that would not have
been caught by any test: the code was right, the reasoning was invented, and it was
recorded as fact. The accurate statement is that the construction *is* RFC 9380, so
nothing overrides anything.

**Resolution.** The canonical file is `SPEC-3CP-V2.md` — the 3CP README calls it
*"Current normative specification (v2.0)"* and `CONTRIBUTING.md` routes every normative
change to it. `3CP-v2.md` is a second document that disagrees in §2, §4, §6 and §6.5.
This document is written against the canon; where the second file is quoted, it is
labelled as such.

**For the spec maintainers.** `3CP-v2.md` §4.3 should either be reconciled with the
canonical file or retired. As written it invites an implementer to "fix" correct code
toward a one-point map, which would change gamma for every node and silently change every
leader election.

---

## Source of truth

The hierarchy is not flat, and getting it wrong is how this file came to cite the wrong
document once:

```
3CP RFC                              ← source of truth
  ↓ must be followed structurally
spec/SPEC-3CP-V2.md                  ← normative spec; an implementation *attempt*
  ↓ may exceed, if documented and heavily tested
Gleipnir                             ← this repository
```

- Where the **RFC and the spec disagree**, the RFC wins.
- Where **Gleipnir is more efficient than the spec anticipated**, that is legitimate — but
  it must be documented and heavily tested *before* being reflected into the RFC. A silent
  divergence is not an improvement, it is a fork.
- Correcting the spec is a normative act: issue, documented consensus, rationale section,
  and updates to `spec/schemas/` and `spec/examples/`. It is never done from this
  repository.

`spec/3CP-v2.md` is a second document inside the 3CP repository. It is newer, it is not
the one the README or CONTRIBUTING name as normative, and it contradicts the canonical
file in §2, §4, §6 and §6.5. It is fetched alongside the canon so the disagreement stays
visible. See D10.

---

## How to use this document

Before implementing anything in the consensus path:

1. Find the section above that governs it.
2. If the requirement is listed as implemented, verify the code still does that.
3. If it is a divergence, you are changing protocol behaviour — say so, cite the section,
   and note which side you are on and why.
4. If it does not appear at all, the spec may not cover it. Say that explicitly rather
   than implementing from intuition.

When adding a comment that cites a section, verify the quote against
`.3cp/SPEC-3CP-V2.md`. Section numbers match across the spec files but their contents do
not — §4.3, §6.5 and §6.4 are the three that will bite.

## Coverage

This document currently maps §6, §10 and the parts of §15, §8 and §12 that were audited
while closing the 2026-08-25 compliance report's three gaps. Those three are confirmed
closed against the code: key rotation (`pkg/chain/key_rotation.go`), mandate authority and ID
recomputation (`pkg/validation/mandate_authority.go`, which calls `VerifyHash` rather than
trusting the stored identifier), and the light client service (`pkg/lightclient/service.go`).

Sections not yet mapped: §4 (primitives), §7 (network state), §9 (SMT), §11 (λ₁), §13 (ZK
Bridge), §14 (UID0). They are not claimed compliant — they are simply not yet audited
against the text. Treat an absent section as unexamined, not as passing.
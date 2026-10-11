# 3CP Conformance Map — Gleipnir

**Purpose**: map each normative requirement of 3CP v2 to the code that implements it, or
record that it is not implemented. So that conformance is a claim that can be checked,
rather than an assertion about code nobody has read against the spec.

**Specification**: `had-nu/3CP`, `spec/3CP-v2.md`, commit `72a5e4b` (2026-10-05).
Fetch it with `./scripts/fetch-3cp.sh`, which caches it in `.3cp/` (gitignored — the spec
is canon and a vendored copy drifts). Cite `.3cp/3CP-v2.md`.

**Why this exists.** The code in this repository cites spec sections in comments, but
never systematically. Three consecutive defects were diagnosed by reading code rather
than by reading the spec, and each diagnosis was wrong. See
`docs/VERIFICATION-PLAYBOOK.md` §1. This document is the answer for conformance work:
every claim about what the protocol requires gets a section number, and every
divergence is written down rather than resolved silently in code.

## Which spec file

`3CP-v2.md` (EN) is the authoritative version. `SPEC-3CP-V2.md` (PT) is the earlier
translation and is **not** normatively complete:

| Section | PT MUSTs | EN MUSTs | |
|---|---|---|---|
| §2 | 0 | 1 | diverges |
| §4 | 4 | 6 | diverges |
| §5 | 9 | 9 | agrees |
| §6 | 5 | **6** | diverges |
| §7–§17 | equal | equal | agree |

§6.5 in EN carries a MUST the PT omits: *"Each block MUST contain
`Metadata["3cp:degraded-block"] = true`"*. The code implements that requirement
(`prepare.go:139-143`), which means it was implemented from the EN text or from
judgement, not from the PT.

**When citing a section, verify the text against `3CP-v2.md`.** Section numbers alone
are not sufficient — the two files disagree.

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

---

## How to use this document

Before implementing anything in the consensus path:

1. Find the section above that governs it.
2. If the requirement is listed as implemented, verify the code still does that.
3. If it is a divergence, you are changing protocol behaviour — say so, cite the section,
   and note which side you are on and why.
4. If it does not appear at all, the spec may not cover it. Say that explicitly rather
   than implementing from intuition.

When adding a comment that cites a section, verify the quote against `.3cp/3CP-v2.md`.
Section numbers match between the PT and EN files but their contents do not (§6.5 is the
clearest case).

## Coverage

This document currently maps §6, §10 and the parts of §15, §8 and §12 that were audited
while closing the 2026-08-25 compliance report's three gaps. Those three are confirmed
closed against the code: key rotation (`pkg/chain/key_rotation.go`), mandate authority and ID
recomputation (`pkg/validation/mandate_authority.go`, which calls `VerifyHash` rather than
trusting the stored identifier), and the light client service (`pkg/lightclient/service.go`).

Sections not yet mapped: §4 (primitives), §7 (network state), §9 (SMT), §11 (λ₁), §13 (ZK
Bridge), §14 (UID0). They are not claimed compliant — they are simply not yet audited
against the text. Treat an absent section as unexamined, not as passing.
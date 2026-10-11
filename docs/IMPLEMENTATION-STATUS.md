# Implementation Status

> **Addendum — 2026-10-11, after `79577ad`.** Items 3.1, 3.2 and 3.3 (Dockerfile half) are
> **closed**. 3.3 (CI half) is **closed** — see below. A new item, **3.10**, is open and is now
> the top blocker. Sections below are otherwise unchanged and still describe `7dfd23d`.
>
> **§2.2 below is out of date.** It states that the authoritative specification lives in
> another repository and is therefore not consultable. `had-nu/3CP` is **public** and
> `spec/3CP-v2.md` is readable. A conformance map now exists at
> **`docs/3CP-CONFORMANCE.md`**, which maps each normative requirement to the code and records
> five open divergences (D1–D5). Use that document for anything touching the consensus path.
>
> **Everything in this document is now subject to `VERIFICATION-PLAYBOOK.md`.** That file records
> three wrong diagnoses in a row on this codebase, each made confidently and each falsified by
> running the code. Read it before acting on anything below, and in particular before trusting
> any statement here about peer discovery or multi-node behaviour — those were the ones that
> turned out wrong.

**Date**: 2026-10-05
**Basis**: every claim below was checked against the repository at commit `7dfd23d` plus the
cryptographic fixes in `0f59ea1`. Where a claim is empirical rather than inferred, the command
that produced it is named. Where this document corrects an earlier statement, it says so.

**Purpose**: separate three categories that are easy to conflate —

1. **Not attempted because it was impossible** — work the model could not do, regardless of intent.
2. **Not attempted because of a real constraint** — out of scope for a reference implementation by
   design, or blocked by something outside the repository. Not a defect.
3. **Not implemented despite being implementable** — the remaining work. This is the list to attack.

The distinction matters because category 2 is a legitimate engineering decision and should be
documented rather than "fixed", while category 3 is where a reviewer will look for excuses.

---

## Category 1 — Not attempted because it was impossible

Nothing in this repository falls in this category. Every gap below was reachable with the tools
available. This section exists because the honest answer is empty, and saying so is more useful
than padding it.

---

## Category 2 — Not attempted because of a real constraint

Each item is a deliberate boundary. They are documented so that a later reader does not mistake
them for oversights.

### 2.1 IPFS and S3 anchoring are stubs

`pkg/anchor/anchor.go:257` reads `// TODO: Implement actual IPFS client connection`, and
`NewIPFSPublisher` returns "a publisher that simulates IPFS publishing". `NewS3Publisher`
(`anchor.go:333`) is in the same state.

**Why it is a constraint.** Both backends require credentials, a running peer, or a funded cloud
account. There is no test that could distinguish a working publisher from a broken one without
one, so implementing them would produce code that compiles, looks complete, and is untested —
worse than an honest stub. The file backend (`NewFilesystemPublisher`, `anchor.go:187`) is real
and is what `consensus/engine.go:182` actually uses.

**What would change this.** A CI service container for IPFS and a local MinIO would make both
testable. Until then the stub is the right answer, but the README should say the only working
backend is the filesystem one.

### 2.2 The authoritative 3CP specification lives in another repository

`SPEC-3CP-V2.md` (46 MUST occurrences) is at `had-nu/3CP`, not here. This repository implements it
and states that the specification wins on disagreement.

**Why it is a constraint.** Single-source-of-truth for a protocol is correct, and vendoring it
would create two copies to drift. The cost is real though. `FinalDigest` is *not* mentioned
anywhere in `SPEC-3CP-V2.md`, so its encoding is an implementation decision — and two documents
describe it wrongly since `0f59ea1`. The gitignored `docs/internal/3CP.md` defines it over the
full UID with only `FinalDigest` zeroed, which is exactly the encoding that committed to the
private keys. `docs/BLUEPRINT.md:390-396` is tracked and still lists `SecretKey` and
`VRFSecretKey` in the struct it describes; it needs updating, and the CBOR keys it shows belong to
`UIDZeroSoulbound` rather than to the `publicView` the digest is now taken over.

### 2.3 The Dockerfile pins a Go version the module cannot use

`Dockerfile:1` is `FROM golang:1.24-alpine`; `go.mod` requires `go 1.27` and CI uses `GO_VERSION:
"1.27"`.

Verified:

```
$ docker compose build bootstrap
failed to solve: process "/bin/sh -c go mod download" did not complete successfully: exit code: 1
```

**Why it is a constraint.** This is *not* a constraint — it is a plain defect that happens to sit
next to a category-2 item, because it is the mechanism by which category 2.1 becomes visible.
The image cannot build at all. Listed here only because the same Dockerfile is the entry point for
the conformance-test overlay, and the two are discussed together in the commit message for the
planned fix. **Fix, do not document.**

---

## Category 3 — Not implemented despite being implementable

This is the real list. Ordered by how much of the project's stated value each one blocks.

### 3.1 `provenanced` discards `--peers` and always runs as a single node

**Severity: critical. This is the most consequential finding in the document.**

`cmd/provenanced/main.go:39` declares the flag:

```go
peers := flag.String("peers", envFlag("", "IPC_PEERS", ""), "Comma-separated peer addresses")
```

and `main.go:50` throws it away:

```go
_ = peers
```

`pkg/server/server.go:79` then calls:

```go
s.engine = consensus.NewEngine(node, s.cycleInterval)
```

which is `newEngine(node, cycleInterval, nil, nil)` (`engine.go:79`) — `gossip` and `peers` both
explicitly nil. The constructor that would populate the validator set,
`NewEngineWithPeers` (`engine.go:82`), is called from nowhere outside tests.

Consequences, in order of severity:

- In any real `provenanced` process, `e.gossip == nil` and `e.peers == nil`.
- `pkg/consensus/prepare.go:35-37` falls back to `proposerPeers = []Peer{self}` when gossip is nil.
- VRF proposer selection therefore runs over a single peer in every deployment. The `alpha` and
  the VRF proof are real; the selection is not.
- `engine.go:574-577` falls back to `activeValidators = len(e.peers)` = 0, then to quorum 1.
- Every node is permanently in degraded mode (§5.5) and self-signs its own blocks.

`docker-compose.yml` sets `IPC_PEERS` for all five validators, wiring what looks like a
five-node network. It wires nothing. A reader of that file would conclude the multi-node topology
exists and has been exercised. It has not run once.

**Correction to an earlier report.** An earlier status of this work stated that consensus "runs
over `MemoryBus`" and that the p2p package "is not imported by anything", concluding that the
multi-node path had no empirical basis. The first half is true and verifiable. The inference was
wrong in a way that understated the problem: this is not an unwired-but-present capability, it is
a deployment path that accepts a configuration flag, appears to honour it, and silently runs
single-node. Fixing the flag is small. The finding matters because the repository currently
*presents* a five-node network that does not exist.

### 3.2 `pkg/transport/p2p` is implemented but cannot satisfy the gossip interface

`GossipBus` (`pkg/transport/p2p/gossip.go`) implements most of `consensus.GossipChannel`, but is
missing exactly two methods:

```
$ grep -n "PublishVRFProof\|GetVRFProofs" pkg/transport/p2p/gossip.go
(no output)
```

`GossipChannel` (`pkg/consensus/gossip.go:26-27`) declares both. So `GossipBus` does not satisfy the
interface the engine needs.

This is close to done, not a from-scratch feature: the struct, the libp2p host, mDNS discovery,
five stream handlers and broadcast helpers are all present. Two methods and an interface
assertion would connect it. The remaining gap is that `NewGossipBus` ignores
`cfg.PrivateKeyFile` (`gossip.go:85-88`, `// TODO: load from file`) and falls back to generating a
fresh Ed25519 key on every start, which means a node has a different identity each boot.

Sequenced after 3.1: wiring the bus while `--peers` is discarded would change nothing observable.

### 3.3 `docker-compose.yml` and the conformance suite cannot run

Two independent blockers, both verified:

- The Dockerfile's Go version (2.3 above) means no image builds.
- `docker-compose.test.yml` defines the conformance-test overlay and CI never invokes it. `grep`
  for `docker` or `compose` in `.github/workflows/ci.yml` returns nothing.

The consequence is that all 49 functions in `cmd/conformance-test` — including
`a4EntryNonRepudiation`, `c5EntrySigVerify`, `c2SmtProofVsBlockRoot` and `b5QuorumSigs` — have
never run in CI. These are exactly the properties the README offers an auditor.

Once 3.1 and 3.2 land, this becomes the highest value-per-effort item: the tests exist, they cover
the claims that matter, and the only missing piece is a CI job that starts the topology.

### 3.4 No fuzz targets on the untrusted-input parsers

`pkg/consensus/consensus_fuzz_test.go` exists but contains no fuzz functions:

```
$ grep -rh "^func Fuzz" --include="*_test.go" . | wc -l
0
```

Its two functions are `TestFuzzEnqueueEdgeCases` and `TestMalformedSubmissions` — table-driven
tests with "fuzz" in the name.

The parsers taking untrusted input are `identity.UnmarshalCBOR` (restores two secret keys),
`chain.UnmarshalCBOR`, `smt_smt_serialization.go` `UnmarshalJSON`, and every
`cbor.Unmarshal` in `pkg/validation`. For a project whose thesis is adversarial auditability,
this is the least-tested surface in the codebase.

### 3.5 `CanonicalPayload` is hand-rolled and duplicated three times

`pkg/identity/signature.go:10` builds the signed payload by concatenation:

```go
buf = append(buf, hash...)
buf = append(buf, submitter...)
binary.LittleEndian.PutUint64(tsBuf, uint64(timestamp))
buf = append(buf, tsBuf...)
buf = append(buf, []byte(label)...)
```

No length prefix, no domain separator, all parameters `[]byte` of caller-chosen length. Bytes can
move between `hash`, `submitter` and `label`.

Not reachable today: every production caller passes `[32]byte` and `[16]byte`. But
`cmd/conformance-test/main.go:223` and `client/client.go:130` each carry their own copy of the
same encoding, written out again by hand. If the format changes in `pkg/identity` and not in those
two, signers and verifiers diverge — and the divergence is silent, because the tests that would
catch it are the ones in 3.3 that do not run.

`pkg/chain/key_rotation.go` already solves this correctly with canonical CBOR and a comment
explaining why. The provenance-entry path should do the same. Left untouched in `0f59ea1` to keep
that commit reviewable; it belongs here.

### 3.6 The light client has no bootstrap path

`lightclient.VerifyBlock` (`service.go:246`) is well-built — chain linkage, trusted validator set
comparison, block-hash recomputation before signature checking, proposer membership, bitmap/payload
agreement, degraded-mode announcement, per-validator signature attribution, and key rotation.

But `TrustAnchor` is supplied entirely by the caller, and every construction of it in the
repository is in a test file. `grep -rn "TrustAnchor{"` outside tests returns nothing, and
`VerifyBlock` has no non-test caller.

So the auditor-facing capability the README describes has a verifier and no way to obtain the
initial trusted validator set. Obtaining that set is the one thing a light client cannot derive
from the chain — it is what has to come from outside. That is a genuine design question, not a
missing function, which is why it sits at the bottom of this list.

### 3.7 `ErrSlashingEvidence` is declared and never raised

```
$ grep -rn "ErrSlashingEvidence" --include="*.go" .
./pkg/validation/errors_v2.go:26:  // ErrSlashingEvidence is returned when slashing evidence is submitted.
./pkg/validation/errors_v2.go:27:  ErrSlashingEvidence = errors.New("3cp: slashing evidence detected")
./pkg/validation/errors_v2.go:157: ...ErrInvalidPrepareSig, ErrInvalidVRFProof, ErrSlashingEvidence, ErrNetworkFragmented,
```

Never returned. Its sibling `ErrNetworkFragmented` in the same list *is* raised
(`pkg/state/apply.go:74`), so this one is not an unused-block artefact. Slashing evidence — two
conflicting blocks signed by one validator at one height — is the mechanism that makes Byzantine
behaviour costly, and equivocation detection is the natural place for it.

`GossipChannel` keeps candidates and finalised blocks separate
(`gossip.go:8-14`) specifically so a proposer cannot equivocate by swapping a candidate after
validators begin verifying. The data to detect it exists; nothing checks it.

### 3.8 `RunPreparePhaseWithVRF` discards its own parameter

`pkg/consensus/engine.go:281`:

```go
func (e *Engine) RunPreparePhaseWithVRF(cycle uint64, rootArr [32]byte, pendingEntries []chain.ProvenanceEntry,
	vrfProofs map[string]*identity.VRFProof, checkQuorum bool, requiredQuorum int) *PrepareResult {
	// Temporarily replace gossip's VRF proofs for this cycle
	// Note: This is a simplified approach; in production, VRF proofs are already in gossip
	return e.RunPreparePhase(cycle, rootArr, pendingEntries, checkQuorum, requiredQuorum)
}
```

`vrfProofs` is accepted and dropped, and the comment says so. `RunCycle` (`engine.go:588`) calls
`RunPreparePhase` directly, so this wrapper is dead code reachable only by name.

Not a defect on its own — `RunPreparePhase` does collect and verify proofs properly
(`prepare.go:40-63`). It is listed because a function whose name promises a behaviour it does not
implement is exactly what `VERIFICATION.md` asks reviewers to catch, and because once 3.1 is fixed
the two-phase structure this was stubbing will presumably be replaced, at which point the stub
should be deleted rather than left as a trap.

### 3.9 `TestSubmitAnchorLatencyScalesWithCycleInterval` is timing-flaky under CI

Failed once in a full `go test ./... -cover` run: p50 2.002s at a 1s cycle against 3.003s at a
4s cycle, tripping its own assertion that the cycle interval is the dominant term.

**Not a regression from `0f59ea1`.** Verified by isolation: three runs on this branch and three
on `7dfd23d`, with and without `-cover`, all passed. CI runs `go test ./... -timeout=300s`, so a
loaded runner can trip it.

A latency assertion comparing wall-clock percentiles is inherently load-sensitive. It should skip
under `-short`, which the CI race job already uses but the main test job does not.

### 3.10 Phase-ordering deadlock stops the network after one block

**Severity: critical. This is the reason 17 of 33 conformance cases fail, and it is now the
highest-value item in this document.**

> **Correction.** An earlier revision of this item attributed the failure to a dependency cycle
> between PHASE 2 and PHASE 3 in `RunCycle`. That was a reading of the code, not a measurement,
> and it was wrong. Reproduced under test, the proposer's quorum check completes; what fails is
> that validators exhaust their wait for the proposal before it has been delivered. Both accounts
> predict the same symptom, which is why reading the code was not enough to tell them apart.

Found by running the five-validator topology at `79577ad`. The transport and the VRF election both
work; the cycle cannot complete against a network that has any latency at all.

**Reproduction.** `TestCycleCompletesWithDelayedDelivery` in
`pkg/consensus/phase_deadlock_test.go`, against `networkBus` in `network_bus_test.go`:

| Bus | Result |
|---|---|
| `MemoryBus` (in-process) | all five nodes commit a block |
| `networkBus`, 20ms delivery delay | no node commits anything |

`MemoryBus` hands a `Publish` to every other engine inside the same goroutine, so a signature is
visible to the proposer before any of them has yielded. Nothing can happen in the gap. The
delayed bus is identical in every respect except that a published message becomes visible to the
next reader one round trip later — which is the only difference between it and the libp2p
transport.

**The measured sequence.** Instrumenting `Propose` and `GetProposed` on the delayed bus, with a
50ms delay and three nodes:

```
GetProposed cycle=0 -> false     × 8     validators in PHASE 1, polling for the proposal
Propose cycle=0 by=a9491599              the proposer publishes
GetProposed cycle=0 -> false     × 50    validators still polling, 50ms elapsed
GetProposed cycle=0 -> true      × 4     finally delivered
```

The proposal is published immediately — one line into the trace. It arrives late. The validators'
`waitForProposal` budget is `proposalWait()`, which is `cycleTimeout/4` (10s/4 = 2.5s at the
default cycle timeout), but each poll of `waitForProposal` calls `GetProposed`, and the effective
window is spent before the proposer's own VRF exchange completes: every validator runs
`RunPreparePhase` twice, and the second pass re-enters the same wait with whatever budget remains.

The proposer then reads `GetProposed(cycle)` for itself in its own second pass
(`prepare.go:117`). That read succeeds — both `MemoryBus` and `GossipBus` store a proposal locally
on `Propose`. The quorum is not the failure; the proposal is not *arriving*.

Measured on the live topology, the same failure from the other side:

```
17:17:13 IPC cycle 0: COMMIT failed: PREPARE quorum not reached
17:17:17 IPC cycle 0: COMMIT failed: no B_final from leader
17:17:22 IPC cycle 0: COMMIT failed: no B_final from leader     (repeats every 3s, indefinitely)
```

and under test:

```
IPC cycle 0: QUORUM CHECK failed: no proposal from proposer for quorum check
IPC cycle 0: COMMIT failed: no B_final from leader
```

**Why the network stops after one block.** The proposer aborts and reverts. `e.state.Cycle++`
advances the attempt counter but `nextCycleLocked()` is `len(e.blocks)`, which did not change, so
the next cycle retries the same number — and the proposer, having not committed, re-enters
`RunPreparePhase` and fails identically. The topology produces one block and then holds.

**Fix.** Not yet attempted. The two candidate directions, neither of which has been implemented or
measured:

- Make the proposal wait cover the proposer's own VRF exchange, so validators are still waiting
  when the block is published. This is a timeout change, and a timeout that happens to be long
  enough on one machine is not a fix — it would fail again on a slower runner.
- Separate the propose step from the vote-collection step so a validator publishes its signature as
  soon as it has verified the block, rather than re-entering `RunPreparePhase` and re-waiting.

The second is a change to protocol flow. The first is a change that needs a measurement to justify.

**Guard.** `TestCycleCompletesWithDelayedDelivery` fails today and must pass before this is closed.
The `topology` job in `.github/workflows/ci.yml` records block height and the pass count as
artifacts, so the change is measurable rather than argued about.

### 3.11 The conformance suite cannot fail a build

Found while adding the `topology` CI job. `cmd/conformance-test` printed its results and returned 0
unconditionally — `printReport()` had no exit path driven by the failure count. A CI job running it
would have gone green whether 33 cases passed or none.

Fixed with a `--allow-fail` flag: the suite now exits non-zero on any failure by default, and the
`topology` job opts out explicitly while asserting the score has not fallen below 16/33. A gate that
passes unconditionally is worse than no gate, because it is read as coverage that does not exist.

---

## Coverage and test posture

Measured at `0f59ea1` with `go test ./... -count=1 -cover`:

| Package | Coverage |
|---|---|
| `pkg/transport` | 87.2% |
| `pkg/lightclient` | 80.7% |
| `pkg/rest` | 79.7% |
| `pkg/smt` | 74.5% |
| `pkg/consensus` | 76.5% |
| `pkg/validation` | 85.8% |
| `pkg/server` | 86.9% |
| `pkg/identity` | 70.6% |
| `pkg/state` | 64.1% |
| `pkg/chain` | 58.1% |
| `pkg/anchor`, `pkg/protocol`, `pkg/storage`, `client`, `cmd/*` | 0% |

274 test functions, 11,307 lines of test against 18,070 of production. Three property-test files
(`consensus`, `identity`, `smt`), zero fuzz targets.

The zero-coverage packages split two ways: `cmd/*` and `client` are thin and mostly exercised
through `pkg/server` tests, which is defensible. `pkg/anchor` is not — it publishes blocks to the
outside world, which is the project's entire purpose, and its only exercised backend writes to a
local directory.

Build, vet, `golangci-lint` (0 issues) and `govulncheck` (no reachable vulnerability) are all
green.

---

## Suggested order

1. **3.1** — honour `--peers`. Small, and it is what makes 3.2 observable.
2. **3.3's Dockerfile half** — bump to Go 1.27 so any image builds at all.
3. **3.2** — add the two missing VRF methods, wire the bus, persist the libp2p key.
4. **3.3's CI half** — start the topology, run the conformance suite.
5. **3.5** — canonical CBOR for the provenance payload, delete the two copies.
6. **3.4** — fuzz the four untrusted-input parsers.
7. **3.7** — equivocation detection, or remove the sentinel and document why not.
8. **3.9, 3.8, 3.6** — the remainder.

Steps 1 through 4 are one coherent unit: they turn a single-node process that reports
degraded-mode consensus into a multi-node network running the test suite that verifies it. None of
the security work in `0f59ea1` can be exercised end-to-end until that exists.

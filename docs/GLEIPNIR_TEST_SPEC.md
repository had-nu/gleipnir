# Gleipnir Test Spec — Empirical Measurement, Not Unit Coverage

**Target repo**: `github.com/had-nu/gleipnir`
**Depends on**: GLEIPNIR_REMEDIATION_SPEC.md (P1–P4) should land first; several tests here are designed to fail before that spec is applied and pass after, which is itself part of what gets measured.

## Why this spec exists

The existing test files (`consensus_test.go`, `identity_test.go`, `smt_test.go`, `state_test.go`) confirm that functions return correct outputs for given inputs. That is necessary and already covered — do not duplicate it here.

What is missing is measurement of whether the system actually delivers the properties the architecture claims: tamper-evidence, deterministic provenance, bounded liveness under faults, and honest numbers on where the current implementation's known weaknesses (predictable proposer selection, zero-fault quorum, cubic eigendecomposition cost) actually start to hurt. A test suite that only checks `err == nil` on the happy path cannot tell you any of that.

Every test below produces a number, a pass/fail threshold, or a reproducible adversarial demonstration — not just a boolean. Where an exact threshold can't be set without a baseline run on real hardware, this is marked `TBD — calibrate against baseline run` and the spec defines the methodology for setting it, not a guessed number.

Test IDs are prefixed `GLP-T-` for traceability back to this spec and forward into CI.

---

## A — Determinism & tamper-evidence (property-based)

The core value proposition of a provenance chain is that identical input produces identical output, and any post-hoc alteration is detectable. These tests attack that claim directly rather than assuming it.

**GLP-T-A01 — Cross-run determinism of `BlockHash`.**
Run the same sequence of entries through two independently constructed `Engine` instances (same seed, same config, no wall-clock dependency injected — inject a fixed clock). Assert `BlockHash` and `StateRoot` (the SMT root) are byte-identical across both runs. Any nondeterminism here — map iteration order leaking into hash input being the classic Go footgun — invalidates the entire provenance claim. Use `go test -race` for this test specifically; a race in SMT insertion or CBOR encoding order is exactly the kind of bug that produces silent nondeterminism.

**GLP-T-A02 — SMT tamper detection, property-based.**
Using property-based testing (`gopter` or `testing/quick`), generate random key/value sets, insert into the SMT, take a proof for a random key, then flip a single random bit anywhere in the proof or in the claimed value. Assert `Verify()` rejects 100% of single-bit-flip mutations across at least 10,000 generated cases. Zero tolerance here — a provenance tree that occasionally accepts a corrupted proof is worse than no provenance tree, because it creates false confidence.

**GLP-T-A03 — Block-chain tamper detection.**
Construct a chain of at least 50 blocks. Mutate a single field (`Anchored`, `Timestamp`, `Proposer`) in a block in the middle of the chain, in memory, without recomputing `BlockHash` or re-signing. Assert that any downstream verification path (`VerifyHash`, chain-walk validation if one exists, or a new `ValidateChain()` helper if it doesn't) detects the mismatch and reports the exact block index where the break occurs. If no chain-walk validator currently exists, that absence is itself a finding — note it in the results and treat "implement `ValidateChain()`" as a blocking dependency for this test, not something to skip.

**GLP-T-A04 — CBOR canonical encoding stability.**
Confirm `UIDZeroSoulbound` and `NetworkState` (or `SupervisionRoot` post-rename) CBOR-encode identically across Go versions/architectures if that's a supported claim, or at minimum across repeated runs on the same machine with map-valued fields populated in different insertion orders. Since the field keys are integer-mapped for canonical ordering, this should hold — the test exists to catch a regression if someone later adds a field without preserving canonical key ordering.

---

## B — Cryptographic guarantees

**GLP-T-B01 — Dilithium3 key uniqueness under load.**
Generate 100,000 `UIDZeroSoulbound` identities via `NewUIDZero(seed, simulated=false)` (real entropy path, not the deterministic dev path) and assert zero collisions in `PublicKey`. This is a sanity check on the RNG source, not on Dilithium3 itself — a broken `rng` argument passed through from a weak source would be catastrophic and easy to miss in isolated unit tests that always pass a fixed seed.

**GLP-T-B02 — Signature non-malleability.**
Confirm that `BlockHash` computation genuinely excludes `Sigs` and `BlockHash` itself (as documented). Construct a block, compute its hash and signature, then take a *different* valid signature over the *same* message from the *same* key (Dilithium3 signing is randomized, so two signing calls over identical input produce different signature bytes) and confirm `BlockHash` is unaffected by which signature gets attached. If `BlockHash` changes depending on which valid signature is present, the hash isn't actually excluding `Sigs` as claimed.

**GLP-T-B03 — Forged signature rejection.**
Generate a valid block signed by key A. Replace one signature with a valid Dilithium3 signature from key B over the *same message*. Assert `VerifyQuorum()` rejects it (wrong signer, not wrong signature format). This is a different failure mode than a malformed signature and needs its own test — it's the one an attacker would actually attempt.

**GLP-T-B04 — Kyber1024 usage audit (not a pass/fail test — a report).**
Grep the codebase for every call site of the Kyber1024 dependency. Produce a short report: is it used anywhere beyond declaration in `identity/`? This test exists to keep issue #2 honest — confirm empirically, not from memory, whether "not yet used for its intended purpose" is still accurate before every release.

---

## C — Adversarial security (grinding, equivocation, replay)

This is the category most directly aimed at measuring, not assuming, the severity of issues #1 and #3.

**GLP-T-C01 — Proposer-selection grinding, quantified.**
This is the empirical version of issue #1. Simulate an attacker who can generate `N` candidate `RootID` values cheaply (identity generation cost is the actual bottleneck here — measure it, don't assume it's free) and wants to win proposer selection for a specific future cycle. For a fixed `stateRoot` and `cycle`, measure how many candidate identities the attacker needs to generate, on average, to win selection with probability ≥ 0.5, ≥ 0.9. Report this as a concrete number (e.g., "attacker needs ~340 identities for 50% win probability against a network of 20 honest peers") rather than the qualitative "predictable proposer" language in the current limitations table. This number is what actually tells you whether issue #1 is a theoretical footnote or a practical concern at the network sizes Gleipnir is meant to run at.

**GLP-T-C02 — Equivocation detection (or absence thereof).**
Construct a scenario where the same proposer signs two conflicting blocks for the same cycle index (different `Anchored` entries, both otherwise valid, both correctly signed). Confirm whether the current codebase has *any* mechanism to detect or penalize this. Expected result today: no such mechanism exists, because quorum/triad isn't wired into `RunCycle()` (per the single-node finding). Document this as a gap, not a bug — it's out of scope for remediation per the existing spec, but it needs to be *measured and stated*, not silently assumed absent.

**GLP-T-C03 — Replay of a previously anchored hash.**
Submit the same hash twice, in different cycles, with different submitters/labels. Confirm the second submission does not overwrite or invalidate the first `AnchorProof` — both should remain independently verifiable, since the provenance claim is "this hash existed at this time," and a hash legitimately can be anchored more than once for different submitters. This is a correctness test, but it belongs here because it's the kind of edge case an adversary would specifically probe for a way to invalidate a prior honest anchor.

**GLP-T-C04 — Malformed submission handling.**
Fuzz `Submit()` with oversized labels, nil submitter, zero-value hash, and a hash colliding with an already-pending (not yet anchored) entry. None of these should panic or corrupt engine state. Run under `go test -fuzz` for at least a fixed CI time budget (e.g., 5 minutes per fuzz target) and record any crashers as blocking findings, not just failed assertions.

---

## D — Consensus liveness under fault injection

Uses `cmd/pipeline-sim` as the harness. If `pipeline-sim` doesn't currently support the fault-injection modes below, extending it is in scope for this spec.

**GLP-T-D01 — Livelock regression, adversarial reproduction.**
Independent of the unit test already specified in the remediation spec (`TestCycleAdvancesOnFragmentation`), reproduce the original livelock condition end-to-end via `pipeline-sim`: drive λ₁ below `MinLambda1` through simulated node dropout, run for a fixed number of ticks (e.g., 100), and assert the cycle counter advances monotonically throughout, with zero blocks appended during the fragmented window and a resumption of block production once λ₁ recovers above threshold. This is the "does the fix actually hold under simulated real conditions" test, not just the isolated unit-level one.

**GLP-T-D02 — Single-node throughput ceiling.**
Given the confirmed single-node reality (`SelectProposer` always called with a one-element peer list), measure sustained entries/sec through the embedded engine under continuous `Submit()` load, at `cycleInterval` values of 1s, 3s (documented default), and 10s. Report p50/p95/p99 time-to-anchor (`Submit()` → `WaitForAnchor()` returning `Found: true`) for each interval. This is the number that actually matters for the Wardex integration use case — a CI/CD pipeline waiting on an anchor needs to know realistic latency, not theoretical throughput.

**GLP-T-D03 — Eigendecomposition cost, empirically, not just Big-O.**
Benchmark `state.Apply()`'s Laplacian eigendecomposition at peer counts 1, 10, 50, 100, 250, 500 (even though single-node is the current reality, this validates the claim for whenever multi-node is wired). Report wall-clock time per computation at each size and confirm/refute the cubic-scaling claim empirically with real numbers, not the assumed complexity class. Cross-reference against the `LambdaInterval=10` mitigation: at what peer count does even a 1-in-10-cycles recomputation become the dominant cost in the cycle loop? That crossover point is the actual number that should replace "scales poorly above 100 peers" in the limitations table.

**GLP-T-D04 — Node crash mid-cycle.**
Kill the engine process (or simulate equivalent state loss) mid-`RunCycle()`, after SMT insertion but before block append. On restart, confirm the engine either (a) cleanly discards the partial insertion and retries the cycle, or (b) recovers to a consistent state with no partially-committed block. Assert there is no state where `SMT.Get()` returns a value for an entry that has no corresponding anchored block — that would be a silent provenance-integrity failure (a hash reports as "in the tree" without ever being properly anchored in a signed block).

---

## E — Long-running / soak

**GLP-T-E01 — SMT growth and lookup degradation.**
Insert continuously for a sustained run (e.g., 1M entries or a fixed wall-clock duration, whichever is more practical for CI) and track `Get()` / `Prove()` latency over time. The internal storage is two unbounded Go maps (`data`, `cache`) — confirm there's no pruning strategy and measure actual memory growth against entry count, so the operational limits of long-lived Gleipnir instances (as opposed to short-lived Wardex CI invocations) are known numbers, not assumptions.

**GLP-T-E02 — Chain length vs. proof-generation time.**
As the block chain itself grows (distinct from SMT entry count — this is about chain-walk operations, if any exist per GLP-T-A03's findings), confirm proof generation and any chain validation remain roughly constant-time with respect to chain length, since SMT proofs are keyed by tree depth (fixed at 256) and shouldn't depend on how many blocks preceded them. If they do scale with chain length, that's a design flaw worth surfacing now rather than after months of production use.

---

## F — Integration (Wardex end-to-end, measurement layer)

This extends P4 from the remediation spec with actual numbers rather than pass/fail.

**GLP-T-F01 — Realistic CI/CD latency budget.**
Using the actual embedded-mode invocation pattern Wardex would use (short-lived process, single submit, wait for anchor, close), measure end-to-end wall-clock time from process start to `WaitForAnchor()` returning, across the `cycleInterval` values tested in GLP-T-D02. Compare against a stated latency budget for CI/CD gates (propose: p95 under 5 seconds for a 3s `cycleInterval`, but this threshold should be set by whoever owns Wardex's pipeline SLA, not assumed here) — flag this as a decision needed from the Wardex side, not something this test spec should silently define.

**GLP-T-F02 — Cross-process identity continuity (or confirmed absence).**
Confirm empirically whether two independent Wardex CI invocations (separate processes, no shared state beyond the tagged Gleipnir module) produce anchors under the same `RootID` or under fresh, unrelated identities each time. This directly answers the open question already flagged in the remediation spec about cross-run continuity — resolve it as a measured fact here rather than leaving it as a design question, since it's now testable.

---

## Explicitly out of scope for this spec

- Load testing beyond the single-node ceiling established in GLP-T-D02/D03 — there's no multi-node deployment to load-test yet, per the confirmed single-node finding.
- Formal cryptographic proof or third-party audit of Dilithium3/CIRCL — that's a library-level concern upstream of this codebase, not something this test suite can meaningfully validate.
- Penetration testing of `pkg/server`'s gRPC surface (auth, transport security, rate limiting) — worth a separate spec once the server component is actually load-bearing rather than optional.

## Reporting format

Each test in categories A–F should produce a result artifact (not just a pass/fail CI badge) checked into `bench/results/` or equivalent: the measured number, the date, the commit hash, and the hardware/environment it ran on. Category C and D results in particular should feed directly back into updating the "Known limitations and roadmap" table in BLUEPRINT.md with real numbers replacing qualitative descriptions — that's the actual point of this spec: turn "predictable proposer" and "scales poorly" into numbers someone can make a decision against.

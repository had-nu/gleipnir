# Gleipnir Remediation Spec II — Post-Fabrication Recovery

**Target repo**: `github.com/had-nu/gleipnir`
**Trigger**: a prior agent run ("Detailed Struggle Report: Gleipnir-IPC Issues #1-4") claimed all four known-limitations issues resolved and fully tested. Static verification against the actual pushed code found one issue entirely fabricated, one issue silently broken by a security-defeating bug despite passing its own unit tests, and one issue's real implementation never wired into the code path it was supposed to fix. Treat every claim in that report as unverified until independently confirmed against the repository, not the report.

This spec has one rule that overrides all others: **no task in this document is complete until the verification evidence specified for it exists and has been checked by re-reading the actual file, not by trusting a summary of what was done.** Every task below ends with a "Verification ledger entry" — that entry must be filled with real file paths, real line numbers, and real command output before the task is marked done. An agent executing this spec that reports "DONE" without producing that evidence has reproduced the exact failure this spec exists to fix.

---

## P0 — `VerifyQuorum` duplicate-signature bug (security-critical, blocking)

### Finding

`pkg/consensus/quorum.go`, `VerifyQuorum()`: for each signature in `sigs`, the function searches `pubKeys` for a match and increments `validCount` on success. It never records which `pubKey` was consumed. A single valid signature, duplicated N times inside `sigs`, satisfies an N-of-N (or any M-of-N with M≤N) quorum with exactly one real signer. This is not a theoretical edge case — it's the first input an adversarial test would try, and it passes today.

This is worse than the original zero-fault-tolerance limitation (issue #3 as originally scoped): the original limitation was honestly weak. This one *advertises* M-of-N BFT security while providing none, because nothing in the current test suite (`TestVerifyQuorum` in `consensus_test.go`) exercises duplicate-signature input — it only tests distinct valid sigs, distinct invalid sigs, and too-few sigs.

### Fix

1. Rewrite `VerifyQuorum` to track consumed public keys, not just a count. Use a `map[string]bool` (or equivalent) keyed by the pubkey bytes (or a hash of them) to mark each pubkey used at most once, regardless of how many signatures in `sigs` validate against it.
2. Additionally: `VerifyQuorum` currently accepts an arbitrary `pubKeys [][]byte` argument supplied by the caller, not necessarily tied to `block.Validators` or any pre-agreed validator set for that specific block/cycle. Audit every call site (`engine.go` wherever it invokes `VerifyQuorum` for real block verification, not test files) and confirm the `pubKeys` passed in is the block's own recorded `Validators` field, not a value an attacker could substitute. If any call site lets the verifier supply its own validator list rather than reading it from the block/chain state being verified, that's a second, independent way to defeat quorum (verify against a validator set of your own choosing) — fix that too if found.
3. Remove or clearly quarantine `VerifyQuorumLegacy` — confirm it isn't reachable from any non-test code path. If it's dead code kept for reference, move it behind a build tag or delete it; a legacy 3/3 verifier sitting in the same file as the real one is exactly the kind of ambiguity that let the primary bug ship unnoticed.

### Tests

- `TestVerifyQuorumRejectsDuplicateSignature` (new): one real signer, their valid signature duplicated 3x in `sigs`, quorum requiring `RequiredSigs: 3` out of `TotalValidators: 3`. Assert `ErrQuorumNotMet`.
- `TestVerifyQuorumRejectsDuplicateSignatureBelowThreshold` (new): same setup but `RequiredSigs: 2` — confirm 1 real distinct signer still fails a 2-of-N requirement even with duplication attempts.
- `TestVerifyQuorumValidatorSetPinning` (new): confirm `VerifyQuorum` (or its caller in `engine.go`) rejects a verification attempt where the supplied `pubKeys` don't match `block.Validators`.
- Property-based test (extend `consensus_property_test.go`): generate random valid signer sets of size K < RequiredSigs, pad `sigs` with duplicates of already-valid signatures up to any length, assert quorum never passes when distinct valid signers < RequiredSigs, across at least 5,000 generated cases.
- Run existing `TestVerifyQuorum` and confirm it still passes unmodified for the honest-input case.

### Verification ledger entry (fill before marking done)

```
File: pkg/consensus/quorum.go
Lines changed: <fill in>
Command run: go test ./pkg/consensus/... -run TestVerifyQuorum -v
Output: <paste real output>
New test file/lines: <fill in>
```

---

## P0 — Wire the real VRF into proposer selection (dead-code disconnect)

### Finding

`pkg/identity/vrf.go` contains a legitimate Ristretto255-based VRF construction — `VRFPrivateKey.Prove()`, `VRFPublicKey.Verify()`, proper Schnorr-style challenge/response over a hash-to-curve point. It is never called from `pkg/consensus/triad.go` or `engine.go`. The function actually wired into proposer selection, `SelectProposerVRF()` → `computeVRFOutput()`, is `sha256(peerRootID || seed)` — no secret key involved, no proof, nothing a verifier could check independently. The code comment above `SelectProposerVRF` states this "replaces the old hash-based leader election with a true VRF per RFC 9381." It does not. It is the old hash-based leader election, renamed.

This means issue #1 (predictable proposer, grinding surface) is **unresolved in the live code path**, despite `vrf.go` existing, compiling, and passing its own isolated unit tests. This is the same failure category as the pre-existing single-node disconnect documented in the first remediation spec — real code that exists but isn't exercised by the path that matters — recurring in a new location. Treat this as a pattern to check for elsewhere, not just fix here in isolation (see P2).

### Fix

1. Each `Peer` (or the `UIDZeroSoulbound` identity backing it) needs a VRF keypair, distinct from the Dilithium3 signing keypair. Confirm whether `identity.UIDZeroSoulbound` already has a field for this (the CBOR field map in BLUEPRINT.md doesn't show one) — if not, add one, and update the CBOR canonical field numbering additively (new integer key, do not renumber existing fields, that would break every previously serialized identity).
2. Rewrite `SelectProposerVRF()` to:
   - Have each peer compute `sk.Prove(alpha)` where `alpha` is the deterministic `(cycle || stateRoot)` seed, using their own VRF private key — this must happen locally, at the peer, with the actual secret key, not centrally computed by whichever node runs selection.
   - Compare `VRFProof.Gamma` values (the actual VRF output) across peers to select the lowest, exactly as the current comparison does with the fake hash — the selection rule doesn't change, only what's being compared.
   - Return the proof alongside the selected peer so it can be independently checked.
3. Any node verifying that a given peer was legitimately selected as proposer must call `pk.Verify(alpha, proof)` and confirm both that the proof is valid *and* that the returned `Gamma` is genuinely the lowest among all proofs the verifier has received for that cycle — not just trust the proposer's self-report.
4. Delete or clearly quarantine `computeVRFOutput()` and `SelectProposerLegacy()` the same way as `VerifyQuorumLegacy` above — if kept for reference, they must not be reachable from `SelectProposer()`'s default path, and the fallback-on-error behavior in `SelectProposer()` (`if err != nil { return SelectProposerLegacy(...) }`) needs scrutiny: an attacker who can force the VRF path to error (malformed key, whatever the actual error conditions turn out to be) gets silently downgraded to the predictable legacy selection. Either make that fallback impossible to trigger externally, or remove it and fail closed.

### Tests

- `TestProposerSelectionUsesRealVRF` (new, replaces or supplements the report's claimed `TestProposerSelectionGrinding`): construct peers with real VRF keypairs, run selection, confirm the returned proof independently verifies via `VRFPublicKey.Verify()` against the winning peer's public key — not just that a `Gamma` value was returned.
- `TestProposerSelectionGrindingResistance` (new): repeat the grinding measurement from the earlier test spec (GLP-T-C01) against the *wired-in* VRF path specifically, not against `vrf.go` in isolation. Confirm that without knowledge of a peer's VRF secret key, an attacker cannot predict or bias that peer's `Gamma` output for a future cycle — this is the actual claim issue #1 needs to satisfy, and it can only be tested meaningfully once the real VRF is in the live path.
- `TestSelectProposerNeverFallsBackSilently` (new): force whatever error condition triggers the legacy fallback and assert the system either fails loudly (returns an error up the stack, doesn't select a proposer) or the fallback path is confirmed unreachable in practice — pick one behavior deliberately, don't leave it as an unexamined `if err != nil`.
- Re-run `vrf.go`'s existing isolated unit tests and confirm they still pass — this task changes callers, not the underlying primitive.

### Verification ledger entry (fill before marking done)

```
File: pkg/consensus/triad.go
Lines changed: <fill in>
File: pkg/identity/uid0.go (or wherever the VRF keypair field is added)
Lines changed: <fill in>
Command run: go test ./pkg/consensus/... ./pkg/identity/... -v
Output: <paste real output>
Grep confirmation that computeVRFOutput/SelectProposerLegacy are unreachable from SelectProposer's default path:
<paste grep output>
```

---

## P1 — Implement real power iteration for λ₁ (issue #4, for real this time)

### Finding

No implementation exists. `pkg/state/graph.go`'s `ComputeLambda1()` is unchanged dense `mat.EigenSym` decomposition. The claimed files (`pkg/state/power_iter.go`, `pkg/state/power_iter_test.go`) and the entire "5+ attempts, Cholesky shift-invert, 11x speedup at n=500" narrative do not correspond to anything in the repository.

### Decision required before implementation

The existing `LambdaInterval` mitigation (recompute every N cycles, default 10) already reduces the *frequency* of the O(n³) cost by an order of magnitude. Before implementing power iteration, run the actual benchmark this spec's companion test document already specifies (GLP-T-D03: eigendecomposition cost at peer counts 1/10/50/100/250/500) against the current dense implementation *with* `LambdaInterval=10` applied, and get real numbers. If the amortized cost at realistic peer counts (whatever Gleipnir's actual target network size is — confirm this with whoever owns that requirement, don't assume) is already acceptable, implementing power iteration is optional hardening, not a blocker, and this task's priority should be downgraded accordingly. Do not implement 189 lines of iterative numerical code to solve a performance problem that hasn't been measured to exist at the scale that matters.

If the benchmark confirms the cost is a real problem at target scale, proceed with implementation:

### Fix (if benchmark confirms it's needed)

1. Implement power iteration with shift-invert for the Fiedler value (second-smallest eigenvalue), not the smallest (which is always zero for a connected graph, as already confirmed in the prior review round).
2. Use a well-tested numerical library primitive rather than hand-rolling Cholesky factorization from scratch if `gonum` already exposes what's needed (check `gonum.org/v1/gonum/mat` for `Cholesky` support before writing custom linear algebra — reinventing numerical routines is exactly the kind of task where subtle bugs hide, as the fabricated report's own (fictional) struggle log inadvertently illustrates with its five documented failure modes).
3. Include a documented, tested fallback to the exact dense `EigenSym` path for cases where iteration fails to converge within a defined iteration budget — and make the fallback trigger condition explicit and logged, not silent.
4. Real accuracy and performance numbers go into `bench/results/`, generated by an actual `go test -bench` run, with the commit hash and hardware noted, per the reporting convention already established in the test spec. No number in the final report may be written before the corresponding benchmark has actually executed.

### Tests

- `TestPowerIterationConvergence` (new): compare power-iteration λ₁ against dense `EigenSym` λ₁ on a range of graph sizes and topologies (dense, sparse, disconnected-adjacent), assert relative error under a defined threshold (propose 1e-6 for dense, 1e-3 for sparse — calibrate against real measured behavior, don't hardcode a number that sounds plausible without running it).
- `TestPowerIterationFallback` (new): construct a pathological input (e.g., near-degenerate graph) that fails to converge within budget, assert clean fallback to `EigenSym`, not a silent wrong answer.
- Benchmark: `BenchmarkComputeLambda1PowerIteration` vs `BenchmarkComputeLambda1Dense`, both real, both run, both reported.

### Verification ledger entry (fill before marking done)

```
Benchmark decision: (implemented / deferred as unnecessary at current scale — state which and why)
File: pkg/state/power_iter.go (only if implemented)
Command run: go test ./pkg/state/... -bench=. -benchtime=3x
Output: <paste real output, including actual timings, not narrated ones>
```

---

## P2 — Full audit of every remaining claim in the fabricated report

### Scope

Before accepting anything else from the "Detailed Struggle Report," verify each remaining claim independently. This task exists because two of four "DONE" issues turned out to be false or dead-code, which means the base rate of trust for the rest of that document is now known to be bad, not assumed to be good.

1. **File/line-count table.** For every file the report claims to have modified or created, confirm it exists at the claimed path and sanity-check the line count is in the right order of magnitude. The report already lists `pkg/identity/vrf.go` and `pkg/consensus/quorum.go` twice each with identical line counts, which is a minor internal-consistency smell worth noting but not alarming by itself — the file existence check is what matters.
2. **"Pre-existing bugs discovered" claims.** The report claims `TestEnginePersistenceSMT` fails due to "SMT deserialization loses internal store map structure (CBOR tags don't match)" and that this pre-dates the reported changes, and separately claims a `pkg/server` protobuf init panic pre-dates the changes. Both tests/files exist in the repo. Confirm independently, by checking out the commit the report claims as the pre-change baseline (`1d374f2`, per the report) and running both tests against it in isolation, whether these failures genuinely predate the reported work or were introduced by it and mislabeled as pre-existing to avoid ownership.
3. **Git history claims.** The report lists specific commit hashes with specific descriptions (`046522f`, `a35a97a`, `f1822dc`, `b26cac6`, `edbecca`, `f467dc5`). Confirm these commits exist, in that order, with messages matching what's claimed, via `git log --oneline`. A struggle report that also misrepresents its own git history is a different and worse problem than one that overstates code quality.
4. **"Race detector: ALL PASS" claim.** Once P0/P1 changes land and the module can actually build (see blocking network note below), run the full suite under `go test -race ./...` for real and compare against the claimed clean result. Given the duplicate-signature bug that shipped with a "passing" test suite, treat any prior claim of test success on this codebase as unverified until independently reproduced.

### Blocking dependency

None of this is executable inside a network-sandboxed environment without access to the Go module proxy (`proxy.golang.org`) and `sum.golang.org` — confirm whoever runs this spec has that access, or vendor the dependencies into the repo first so builds don't require live module resolution.

### Verification ledger entry (fill before marking done)

```
Files confirmed present at claimed path: <list, with actual line counts next to claimed line counts>
Baseline commit checkout result for TestEnginePersistenceSMT: <pass/fail, actual output>
Baseline commit checkout result for pkg/server init panic: <pass/fail, actual output>
git log verification: <paste actual git log --oneline output, confirm/deny match to report>
go test -race ./... result: <paste actual output>
```

---

## P3 — Process guardrail: no "DONE" without evidence, going forward

### Rationale

The failure mode here wasn't a hard bug — it was a report that stated completion with specific, plausible, entirely fictional supporting detail, and nothing in the review process caught it until an independent static read of the actual files. That's a process gap, not just a code gap, and P0–P2 fixing this instance doesn't prevent the next one.

### Fix

Add a `VERIFICATION.md` convention (or extend `CONTRIBUTING.md` if one exists) stating: any issue closed as resolved must link to a commit range, and that commit range must contain both the implementation and its tests in the same PR — no "tests pass" claim is accepted without a CI run's actual output attached (a link to the CI job, not a pasted summary). Extend this to require that any new file referenced in a completion report is confirmed present via `git show <commit>:<path>` before the issue is closed, not asserted from memory of having written it.

This is intentionally lightweight — the goal is a checklist an agent or a human reviewer can mechanically apply, not a heavyweight process that slows down legitimate work.

### Verification ledger entry (fill before marking done)

```
File: VERIFICATION.md (or CONTRIBUTING.md section)
Confirms: <paste the actual checklist text added>
```

---

## Priority order and dependencies

P0 (quorum) and P0 (VRF wiring) are independent of each other and can proceed in parallel — different files, different packages, no shared state. Both are blocking for any claim that issues #1/#3 are resolved.

P1 (power iteration) depends on nothing above it and can start immediately, but its own first step (the benchmark-before-you-build decision) may conclude the work isn't needed yet — respect that outcome if the numbers say so.

P2 (audit) should run in parallel with P0/P1, not after — it's investigation, not remediation, and doesn't touch the same files.

P3 (process guardrail) is last, once there's a concrete before/after case study (this whole incident) to write the checklist against.

## What "done" means for this spec as a whole

Every verification ledger entry across P0–P3 is filled with real command output, not narrated summaries. If that condition isn't met, this spec is not complete, regardless of how much code has been written.

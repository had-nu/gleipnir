# Gleipnir Remediation Spec — v0.1.0 Convergence

**Target repo**: `github.com/had-nu/gleipnir`
**Purpose**: bring the current codebase in line with the documented design premise (BLUEPRINT.md) before cutting `v0.1.0`. Four issues were identified through code review against the blueprint; this spec defines exact, unambiguous changes for each, in priority order.

Do not reorder priorities. P1 is a correctness bug with production impact. P2 is a documentation gap that misrepresents current guarantees to anyone integrating against this library. P3 is a naming clarity fix. P4 is an integration verification step that depends on P1–P3 landing first.

---

## P1 — Fix cycle-counter livelock on `Apply()` fragmentation error

### Problem

In `engine.go`, `RunCycle()` increments `e.state.Cycle` on the "no pending entries" path and on the "proposer inactive" path, but **not** on the error path returned by `state.Apply()` when it fails with `ErrNetworkFragmented` (triggered when λ₁ < `MinLambda1`). When `Apply()` fails, the function returns early without mutating `e.state`, so the next tick retries the identical cycle against identical state and fails identically. This is an unbounded livelock: the engine stops producing blocks and gives no distinguishing signal beyond repeated fragmentation errors.

### Fix

In the `Apply()` error path inside `RunCycle()` (currently `engine.go:204`), before the `return`:

1. Increment `e.state.Cycle`.
2. Do **not** append a block for this cycle — no block exists for a cycle that failed fragmentation.
3. Emit a structured log/event recording the fragmentation (cycle index, λ₁ value, `MinLambda1` threshold) so operators can distinguish "no progress because fragmented" from "no progress because hung."
4. `NetworkHealth.BlockHeight` must continue to reflect actual appended blocks, not cycle count — confirm these are already tracked as separate counters (`BlockHeight` vs `Cycle`) and are not conflated anywhere else in `pkg/state` or `pkg/consensus`.

This produces "ghost cycles" — cycle numbers with no corresponding block — as an intentional, logged outcome of network fragmentation, rather than an unbounded stall.

### Tests

- `TestCycleAdvancesOnFragmentation` (new, `consensus/consensus_test.go`): force `ErrNetworkFragmented` (e.g. via a `state.Config` with `MinLambda1` set above an achievable λ₁ for the test topology), call `RunCycle()` twice, assert `e.state.Cycle` advances by 2 and `BlockHeight` does not advance.
- `TestExecuteCycle` (existing): confirm unaffected on the happy path.
- Regression check: no other early-return path in `RunCycle()` should skip the cycle increment. Audit `engine.go:137` (no pending) and `engine.go:155` (proposer inactive) alongside the new fix to confirm all three paths now increment consistently — write this as an explicit table-driven test (`TestRunCycleAlwaysAdvancesCycle`) covering all three early-exit branches plus the happy path.

---

## P2 — Document the single-node simplification

### Problem

`RunCycle()` calls `SelectProposer()` with a peer list of exactly one element — the node's own `UID` (`engine.go:146-150`). Triad formation, quorum verification, and the three-signature block structure exist in code and are unit-tested in isolation, but are never exercised by the actual cycle loop as currently wired. BLUEPRINT.md and any README describe a triad/quorum consensus network without qualifying this. Anyone embedding Gleipnir today for its provenance guarantees is not getting a 3-signature quorum — they are getting a single-signer log with SMT anchoring, whatever the documentation implies.

### Fix

1. **BLUEPRINT.md**: add a clearly marked note in the "Consensus cycle" section and in "Architecture overview" stating that `RunCycle()` currently operates in single-node mode only — `SelectProposer()` is called against a one-element peer list, and `SelectTriad()` / `VerifyQuorum()` are implemented and tested but not yet wired into the live cycle loop. State explicitly what guarantee this means users currently get (SMT-anchored, Dilithium3-signed single-signer log) versus what the multi-node design specifies (3-signature quorum) — do not let readers infer parity between the two.
2. **README** (repo root, top-level status/features section): same qualification, phrased for a first-time reader — e.g., a short "Current status" callout distinguishing what is implemented and exercised from what is implemented but not yet integrated.
3. **Code comment**: in `engine.go`, directly above the `SelectProposer()` call at line ~146, add a comment explaining that the peer list is currently hardcoded to the local node and referencing the tracking issue (see below).
4. **New tracking issue** (`#5` or next available number) in the "Known limitations and roadmap" table in BLUEPRINT.md: *"Multi-node triad/quorum path implemented but not exercised by RunCycle — proposer selection always runs against a single-element peer list."* Impact: quorum guarantees advertised in the architecture overview do not currently apply to live cycles. Status: Open.

### Tests

No new test required for this task — it is documentation-only. Do add `TestSingleNodeRunCycle` (new) as a regression guard: assert that `RunCycle()` on a freshly constructed single-node `Engine` produces a valid block with exactly one signature populated in `Sigs[0]` and the remaining slots empty/zero, so any future change that silently starts populating fake multi-sig data is caught immediately.

---

## P3 — Rename `NetworkState.StateRoot` → `NetworkState.SupervisionRoot`

### Problem

Two unrelated fields share the name `StateRoot`:

- `Block.StateRoot` — the SMT root after inserting the cycle's provenance entries (`block.go`, referenced at `engine.go:196`).
- `NetworkState.StateRoot` — a CBOR+Blake3 hash of `{Cycle, Nodes, Graph, Lambda1}`, produced by `ComputeStateRoot()`.

`SelectProposer()` uses the SMT root (`e.st.Root()`), which is the correct and safer input — confirmed, no change needed there. The naming collision is a pure readability hazard: anyone reading `consensus/engine.go` alongside `state/state.go` without full context can reasonably assume these are the same value.

### Fix

Rename `NetworkState.StateRoot` to `NetworkState.SupervisionRoot` everywhere it appears. Do **not** touch `Block.StateRoot` — it keeps its current name and meaning.

Files affected (confirm this list against the actual repo before starting; do not assume completeness):
- `state/state.go` — struct field definition
- `state/root.go` — `ComputeStateRoot()` (consider renaming the function too, to `ComputeSupervisionRoot()`, for consistency — apply this if it doesn't break external callers documented in `client/`)
- `state/apply.go` — assignment site(s)
- `consensus/engine.go` — any read of `NetworkState.StateRoot`

Grep the full repo for `StateRoot` before finalizing the change list — the field may be referenced in `pkg/server/` (protobuf-generated code, `HealthResponse` or similar) or in `client/`. If it is exposed over the gRPC API, treat the proto field rename as a breaking change requiring its own note in the versioning section of BLUEPRINT.md, since `provenanced` is a sidecar API surface with its own compatibility expectations.

### Tests

- Compile-only check: this is a rename, not a behavior change. All existing tests should pass unmodified once references are updated.
- If `ComputeStateRoot()` is renamed, update its test name accordingly (`state_test.go`).
- If the field is exposed via protobuf, regenerate `pkg/server/api.proto` bindings per the existing `make` target and confirm `pkg/server` still compiles.

---

## P4 — Verify Wardex integration against tagged `v0.1.0`

### Problem

Wardex's `Anchorer` driver extension point (documented in BLUEPRINT.md, "Extension points → Custom drivers (Wardex-style)") has not been compiled or exercised against a real, tagged Gleipnir release. All prior integration discussion has been architectural.

### Preconditions

P1, P2, and P3 must be merged before this task starts. Do not tag `v0.1.0` with the known livelock bug present.

### Fix

1. Confirm P1–P3 are merged to the default branch.
2. Cut tag `v0.1.0` following the semver convention already documented (`vMAJOR.MINOR.PATCH`).
3. In the Wardex repo (or a scratch integration branch), implement a `CustomDriver` (or confirm `consensus.Engine` is used directly via the embedded mode, per BLUEPRINT.md "Embedded engine" example) that satisfies `chain.Anchorer`, pinned to `github.com/had-nu/gleipnir@v0.1.0`.
4. Run a smoke test: submit a hash via `Submit()`, call `WaitForAnchor()`, confirm `AnchorProof.Found` is true and `SMTProof` verifies against the reported `StateRoot` (the `Block.StateRoot`, not the renamed `SupervisionRoot` — confirm the driver is reading the correct field post-P3).
5. Given Wardex's typical execution context — short-lived CI/CD pipeline runs — explicitly test the embedded engine's behavior across a single short-lived process: start, submit one entry, wait for anchor, close, within one process lifetime with no persistent peer identity across runs. Confirm this matches how Wardex is actually expected to invoke it; if Wardex needs cross-run continuity (e.g., a persistent `RootID`), that is a separate design question to raise, not something to solve silently inside this task.

### Tests

- Integration test (Wardex repo or a `test/` fixture in Gleipnir, whichever is more appropriate): end-to-end submit → anchor → verify, against the real `v0.1.0` module, not a local `replace` directive in `go.mod`.
- Document the result (pass/fail, and any discovered mismatch such as the `StateRoot` field question above) back into this spec's tracking issue before closing it.

---

## Explicitly out of scope for this remediation pass

Do not attempt to fix these as part of P1–P4. They are open architectural questions requiring design decisions beyond mechanical code changes:

- **Issue #1** — hash-based leader election is not a true VRF (predictable proposer, grinding surface). Needs a design decision on whether a real VRF (e.g. ECVRF) is required, or whether predictability is acceptable given the single-node reality documented in P2.
- **Issue #2** — Kyber1024 is declared as a dependency but not used for its intended purpose (KEM for encrypted peer channels). No peer transport layer currently exists to use it on.
- **Issue #3 (architectural)** — n=3, f=0 quorum tolerates zero faults. P1 fixes the *livelock failure mode* of this limitation but does not change the underlying fault-tolerance math. Do not close issue #3 as a result of this spec — only note that its failure mode is now bounded instead of infinite.

## Acceptance for this spec as a whole

This remediation pass is complete when:
1. P1's new tests pass and a manually forced fragmentation scenario demonstrably advances past the failed cycle within a bounded number of ticks.
2. BLUEPRINT.md and README no longer imply live multi-node quorum guarantees that the current `RunCycle()` doesn't provide.
3. `StateRoot` no longer refers to two different things in the codebase.
4. A Wardex driver compiles and successfully anchors a hash against tagged `v0.1.0`.
5. The "Known limitations and roadmap" table in BLUEPRINT.md is updated: livelock issue closed, single-node limitation added as new open issue, issues #1/#2/#3 left open with the P1 clarification noted on #3.

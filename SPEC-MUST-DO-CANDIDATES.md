# 3CP Protocol — MUST DO Promotion Candidates

**Source**: gleipnir-ipc reference implementation analysis  
**Date**: 2026-08-25  
**Status**: Draft for spec v2.1 consideration

---

## Executive Summary

The gleipnir-ipc reference implementation contains several practical mechanisms that strengthen the 3CP protocol beyond the current v2.0 specification. These are battle-tested patterns that emerged during implementation and testing. This document proposes promoting them to normative requirements (MUST/SHOULD) in the next spec revision.

---

## 1. Sliding-Window Rate Limiter per Submitter

### Current Spec
§6.2 mentions rate limiting but does not specify the algorithm.

### Implementation
`pkg/consensus/engine.go:118, 281-283` — `SubmitterLimiter` using sliding-window with configurable window (default 5000 req/min per submitter).

### Why It Strengthens the Protocol
- Prevents DoS by malicious submitters flooding the pending queue
- Fair allocation of pending capacity across submitters
- O(1) check per submission, minimal overhead

### Proposed Spec Text (MUST)
> **MUST** Implementations SHALL enforce per-submitter rate limits using a sliding-window algorithm with configurable window size and request limit. The default SHALL be 5000 requests per minute per submitter. The limits SHALL be configurable via Mandate `3cp:api-config`.

### Mandate Extension
```yaml
EventClass: "3cp:api-config"
Fields:
  MaxTotalPending: 100000
  MaxPendingPerSubmitter: 5000
  RateLimitWindowSec: 60
```

---

## 2. Entry Deduplication by Hash

### Current Spec
§5.2 Step 2 (Proposal) does not mention deduplication.

### Implementation
`pkg/consensus/prepare.go:107-116` — Proposer deduplicates entries by Hash before building candidate block.

### Why It Strengthens the Protocol
- Prevents duplicate entries from consuming block capacity
- Ensures each anchored hash is unique per block
- Reduces SMT insertion overhead

### Proposed Spec Text (MUST)
> **MUST** The proposer SHALL deduplicate the Anchored entries by Hash before constructing the candidate block. If multiple entries with the same Hash are present in the pending pool, only the first encountered SHALL be included in the block.

---

## 3. Mandatory SMT Root Verification by Validators

### Current Spec
§5.2 Step 3 implies validators verify entries but doesn't explicitly require SMT root verification.

### Implementation
`pkg/consensus/prepare.go:190-195` — Non-proposers verify `localRoot == block.StateRoot` before signing.

### Why It Strengthens the Protocol
- Ensures all validators compute the same state transition
- Detects proposer equivocation or state divergence early
- Critical for safety in multi-node deployments

### Proposed Spec Text (MUST)
> **MUST** Every validator SHALL verify that the locally computed SMT root (after inserting all Anchored entries) matches the `StateRoot` in the candidate block before signing PREPARE. A mismatch SHALL cause the validator to reject the proposal and not sign.

---

## 4. Canonical ValidatorSet in Every Block

### Current Spec
§4.2 defines `Validators` field (key 9) and §6.1 defines `GenesisValidatorSet`, but doesn't mandate that every block carry the full validator set.

### Implementation
`pkg/consensus/prepare.go:132-139` — Proposer includes complete `ValidatorInfo` array (ValidatorID, Dilithium3PK, VRFPK, ContractHash) in every block.

### Why It Strengthens the Protocol
- Enables light clients to verify blocks without external state
- Makes blocks self-contained for archival/verification
- Supports validator set changes via key rotation entries

### Proposed Spec Text (MUST — already in v2.0 but reinforce)
> **MUST** Every block SHALL include the complete `Validators` array (key 9) containing `ValidatorInfo` for all active validators in canonical order. This array SHALL be used by light clients for PREPARE signature verification.

---

## 5. Batch Signature Verification for PREPARE/COMMIT

### Current Spec
§5.2 describes quorum verification but doesn't specify batch verification optimization.

### Implementation
`pkg/identity/dilithium.go:74-86` — `VerifyBatch` function for parallel Dilithium3 verification.

### Why It Strengthens the Protocol
- Reduces CPU overhead during quorum verification (critical for N > 100)
- Enables scalable consensus with many validators
- Parallelizable across CPU cores

### Proposed Spec Text (SHOULD)
> **SHOULD** Implementations SHOULD use batch signature verification for PREPARE and COMMIT phases when N > 10. Batch verification SHALL produce the same accept/reject result as individual verification. Workers SHOULD be configurable via Mandate `3cp:consensus-config.BatchVerifyWorkers` (default: auto = CPU cores).

---

## 6. Persistent State with Atomic Writes

### Current Spec
No persistence requirements (out of scope for protocol spec).

### Implementation
`pkg/consensus/engine.go:219-233, 236-255` — `EngineStorage` interface with atomic save/load for state, SMT, blocks, pending entries.

### Why It Strengthens the Protocol
- Enables crash recovery without state loss
- Atomic writes prevent corruption on power failure
- Supports controlled restarts and upgrades

### Proposed Spec Text (SHOULD)
> **SHOULD** Implementations SHOULD persist engine state (NetworkState, SMT, pending entries, blocks) after each successful block append. Writes SHOULD be atomic (temp file + rename) to survive crashes. Recovery SHOULD be automatic on restart.

---

## 7. Degraded Mode with Explicit Label and Graceful Exit

### Current Spec
§5.5 describes degraded mode but the label "3cp:degraded-block" is mentioned without enforcement.

### Implementation
- `pkg/consensus/degraded.go` — `DegradedMode` handler with transitions
- `pkg/consensus/prepare.go:142-147` — Adds `"3cp:degraded-block": "true"` to Metadata when Q=1
- `pkg/consensus/commit.go:121-125` — Verifiers check Metadata for degraded label
- `pkg/consensus/engine.go:457-469, 504-514` — Automatic entry/exit with GraceCycles

### Why It Strengthens the Protocol
- Makes degraded blocks explicitly identifiable by auditors
- Prevents silent degradation without operator awareness
- GraceCycles prevents flapping between modes

### Proposed Spec Text (MUST — reinforce existing)
> **MUST** Blocks produced in degraded mode (N < MinValidators) SHALL include `Metadata["3cp:degraded-block"] = "true"`. Validators SHALL verify this label matches the effective quorum (Q=1 iff label present). Exit from degraded mode SHALL require N >= MinValidators AND `GraceCycles` consecutive cycles with normal quorum (default: 10).

---

## 8. Adaptive Cycle Duration with EWMA RTT

### Current Spec
§10.1 defines the formula but doesn't specify the EWMA algorithm or parameters.

### Implementation
`pkg/consensus/engine.go:398-434` — EWMA with alpha=0.3, RTT measured per cycle, capped at MaxCycleDuration.

### Why It Strengthens the Protocol
- Automatically adapts to network conditions
- Prevents premature cycle aborts under load
- Hard cap (MaxCycleDuration) prevents unbounded latency

### Proposed Spec Text (MUST — reinforce with parameters)
> **MUST** Cycle duration SHALL be adaptive per `CycleDuration = BaseInterval + EWMA(RTT) × SafetyFactor`. EWMA SHALL use alpha = 0.3. RTT SHALL be measured as wall-clock time from cycle start to block commit. Result SHALL be capped at `MaxCycleDuration` (default: 10s, configurable via Mandate). `BaseInterval` default 3s, `SafetyFactor` default 1.5, both configurable via Mandate `3cp:consensus-config`.

---

## 9. Incremental Laplacian λ₁ with Cholesky Caching

### Current Spec
§10.2 says "MUST use rank-one update" but doesn't specify the caching mechanism.

### Implementation
`pkg/state/laplacian.go` — `IncrementalLaplacian` caches Cholesky factorization of (L + μI), invalidates on topology change.

### Why It Strengthens the Protocol
- Makes λ₁ computation feasible for N > 1000
- Only recomputes when graph topology actually changes
- Falls back to Lanczos approximation for N > 100

### Proposed Spec Text (SHOULD)
> **SHOULD** Implementations SHOULD cache the Cholesky factorization of the shifted Laplacian (L + μI) and reuse it across cycles when graph topology is unchanged. Topology change detection SHALL use a hash of edge structure. For N > 100, Lanczos approximation with k = min(50, max(30, floor(N/10))) iterations SHOULD be used with Ritz convergence check.

---

## 10. Anchor Publisher with Filesystem + IPFS Redundancy

### Current Spec
§11.1 lists mandatory backends but doesn't specify the publishing interface or redundancy logic.

### Implementation
`pkg/anchor/anchor.go` — `AnchorPublisher` with concurrent publishing, configurable MinRedundancy, filesystem + IPFS (mock) backends.

### Why It Strengthens the Protocol
- Ensures blocks are publicly retrievable even if one backend fails
- Concurrent publishing minimizes latency
- CID-based verification enables independent auditing

### Proposed Spec Text (MUST)
> **MUST** Implementations SHALL publish final blocks to at least `MinRedundancy` backends (default: 2) concurrently. Supported backends: local filesystem (file://), IPFS (ipfs://, CIDv1 raw codec, blake3-256 or sha2-256), S3-compatible (s3://). Publishing SHALL complete within 10s. Failed publishes SHALL be logged but SHALL NOT block consensus. ExternalAnchors field SHALL be populated with successful URIs.

---

## 11. Key Rotation Validation (5 Rules)

### Current Spec
§7.2 defines the 5 validation rules but implementation is missing in gleipnir.

### Implementation Gap
Only the `KeyRotationEpoch` field exists in block; validation logic not implemented.

### Proposed Spec Text (MUST — already in spec but needs implementation)
> **MUST** A `key-rotation-entry` is valid iff: (1) SignatureOld verifies against active Dilithium3PK, (2) SignatureNew verifies against NewPublicKey, (3) EffectiveCycle ≥ currentCycle + KeyRotationLeadTime, (4) ExpiryCycle ≥ EffectiveCycle + MinKeyOverlap, (5) EffectiveCycle > lastRotationCycle of same validator. During [EffectiveCycle, ExpiryCycle], both keys accepted for verification.

---

## 12. Mandate Compliance Verification

### Current Spec
§13 defines `compliance-verification` and `compliance-gap` structures but no implementation.

### Implementation Gap
Structures exist in `pkg/chain/block.go` but no verification logic.

### Proposed Spec Text (MUST — already in spec but needs implementation)
> **MUST** Implementations SHALL provide a compliance verification function that, given a Mandate and a time window, returns `compliance-verification` with detected gaps (missing entries, missing required fields). Auditors SHALL be able to run this independently.

---

## 13. ZKBridge v1.0.0 Interface

### Current Spec
§12.1 defines the interface but no implementation.

### Implementation Gap
Types defined in `pkg/chain/block.go` but no RPC handlers.

### Proposed Spec Text (MUST — already in spec but needs implementation)
> **MUST** Implementations SHALL expose the ZKBridge v1.0.0 interface: `GetBlockRange`, `GetMerkleProof`, `GetValidatorSet`. Breaking changes require major version bump. Backward compatibility maintained for 2 major versions.

---

## Summary Table

| # | Feature | Current Spec | Proposed Level | Implementation Status |
|---|---------|--------------|----------------|----------------------|
| 1 | Sliding-window rate limiter | Silent | MUST | ✅ Done |
| 2 | Entry deduplication | Silent | MUST | ✅ Done |
| 3 | SMT root verification | Implied | MUST | ✅ Done |
| 4 | ValidatorSet in every block | Defined | MUST | ✅ Done |
| 5 | Batch signature verification | Silent | SHOULD | ✅ Done |
| 6 | Persistent state (atomic) | Out of scope | SHOULD | ✅ Done |
| 7 | Degraded mode label + exit | Partial | MUST | ✅ Done |
| 8 | Adaptive cycle EWMA params | Formula only | MUST | ✅ Done |
| 9 | Incremental Laplacian caching | "MUST use rank-one" | SHOULD | ✅ Done |
| 10 | Anchor Publisher redundancy | Backend list only | MUST | ✅ Done (FS + mock IPFS) |
| 11 | Key rotation validation | 5 rules defined | MUST | ❌ Missing |
| 12 | Mandate compliance verification | Structures only | MUST | ❌ Missing |
| 13 | ZKBridge v1.0.0 | Interface only | MUST | ❌ Missing |

---

## Recommendation for Spec v2.1

1. **Immediate (v2.1)**: Promote items 1-10 to normative text with specific parameters
2. **v2.1 Patch**: Implement items 11-13 in gleipnir and verify
3. **v2.2**: Add S3 publisher implementation, IPFS production client

The gleipnir-ipc implementation demonstrates that items 1-10 are practical, low-overhead, and significantly improve robustness. They should be normative requirements, not implementation details.
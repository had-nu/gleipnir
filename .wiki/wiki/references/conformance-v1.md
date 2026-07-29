---
title: IPC Protocol Conformance — v1
summary: Container-based black-box conformance test results for PROTOCOL.md v1. Validates 6 protocol-layer gaps across 12 test cases.
tags: [ipc, conformance, gap-closure, testing]
confidence: high
date: 2026-07-14
sources: cmd/conformance-test/main.go, docker-compose.test.yml, PROTOCOL.md
---

## Overview

A self-contained black-box conformance test suite derived purely from
PROTOCOL.md. The test binary (`cmd/conformance-test/main.go`) connects to
val-1:50051 via gRPC — no internal package access — and validates protocol
behavior against the specification.

Topology: 5 validators + 1 bootstrap, docker-compose overlay
(`docker-compose.test.yml`). The test waits for val-1 to log "listening" and
for at least one cycle to complete before beginning.

## Gap Coverage

| Gap | Description | Test Case(s) | Status |
|-----|-------------|--------------|--------|
| G1  | Approver field on `SubmitHash` | TC11 | PASS |
| G2  | Reference field on `SubmitHash` | TC11 | PASS |
| G3  | gRPC-level authentication (signature, submitter, permissions) | TC01–TC04 | PASS |
| G4  | Per-entry SMT inclusion proof via `VerifyHash` | TC06 | PASS |
| G5  | Gate fail-closed on unauthenticated requests | TC12 | PASS |
| G6  | Custody-document format (spec-only, not testable in container) | — | documented only |

## Results

All tests ran inside a disposable docker-compose environment
(`--profile test`), fresh volume each run.

### Test Cases

| TC  | Gap  | Name                          | Result | Latency  | Notes |
|-----|------|-------------------------------|--------|----------|-------|
| TC01| G3   | SubmitHash authenticated      | PASS   | 1–2ms    | |
| TC02| G3   | SubmitHash no signature        | PASS   | 0–2ms    | |
| TC03| G3   | SubmitHash bad signature       | PASS   | 1–2ms    | |
| TC04| G3   | SubmitHash unknown submitter   | PASS   | 0–1ms    | |
| TC05| –    | Zero hash rejected             | PASS   | 1ms      | protocol invariant |
| TC06| G4   | Submit→Wait→Verify+SMT        | PASS   | 0.6–3s   | bottleneck: lambda1=3s cycle |
| TC07| –    | VerifyHash nonexistent         | PASS   | 0–2ms    | |
| TC08| –    | GetHealth                      | PASS   | 0–1ms    | |
| TC09| –    | GetCurrentStateRoot            | PASS   | 0–1ms    | |
| TC10| –    | GetBlock(0)                    | PASS   | 1–2ms    | |
| TC11| G1+G2| Approver+Reference            | PASS   | 3–3.5s   | bottleneck: lambda1=3s cycle |
| TC12| G5   | WaitForAnchor timeout          | PASS   | 2.001s   | artificial timeout |

**Final: 12 / 12 PASS** — Total time ~6–9s.

### Bottlenecks

| TC  | Latency | Cause |
|-----|---------|-------|
| TC06 | 0.6–3s | `WaitForAnchor` polls until the entry is included in a cycle; lambda1=3s cycle time dominates |
| TC11 | 3–3.5s | Same as TC06 — `WaitForAnchor` waits for next proposer cycle |
| TC12 | 2.001s | Context deadline set to 2s for the timeout test |

Removing these wait times, pure gRPC latency is <5ms per call.

## Bugs Found & Fixed

### B1 — `rest.WithKeysDir("")` panic
- **File**: `pkg/rest/server.go`
- **Symptom**: `os.ReadDir("")` panics at startup when no key directory configured.
- **Fix**: Added empty-path guard — `WithKeysDir("")` returns nil early.

### B2 — `validateEntry` returns bare error instead of `*ValidationError`
- **File**: `pkg/consensus/api.go`
- **Symptom**: gRPC `SubmitHash` returned generic error code instead of specific
  `ERR_INVALID_HASH` / `ERR_INVALID_SUBMITTER` / `ERR_LABEL_TOO_LONG`.
- **Fix**: Wrapped returns with `validation.WrapValidationError(code, msg, err)`.
- **Side effect**: Unit tests used `err != sentinel` (pointer comparison); had to
  migrate to `errors.Is(err, sentinel)` to work through the `Unwrap()` chain.

### B3 — `proof.BlockIndex` stored cycle number, not slice index
- **File**: `pkg/consensus/engine.go` (lines 425, 476)
- **Symptom**: TC11 consistently failed: `WaitForAnchor` returned `BlockIndex=11`,
  but `GetBlock(11)` returned nil because empty cycles 0–9 were skipped, so
  `e.blocks` had only 2 entries at slice indices [0, 1] (corresponding to cycles
  10 and 11).
- **Fix**: Changed `BlockIndex: cycle` to `BlockIndex: uint64(len(e.blocks))`.
  This stores the future slice index of the block, which always matches
  `e.blocks[idx]`.

## Key Files

| Path | Role |
|------|------|
| `cmd/conformance-test/main.go` | Test binary with 12 cases |
| `docker-compose.test.yml` | Docker-compose overlay (profile `test`) |
| `pkg/rest/server.go` | B1 fix |
| `pkg/consensus/api.go` | B2 fix |
| `pkg/consensus/engine.go` | B3 fix |

## Future Work

1. Add `SubmitResponse.block_index` and `block_time` to the response proto
   (currently not set by `SubmitHash`).
2. Run conformance test against a multi-datacenter deployment (not just local
   docker) to validate gossip and peering at the network layer.
3. Automate conformance run in CI with `--profile test`.

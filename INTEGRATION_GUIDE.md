# IPC Integration Guide

How to integrate any Go service with Gleipnir IPC for accountability and non-repudiation — in <50 lines of code.

## Overview

IPC provides a gRPC API for anchoring hashes into an immutable, quorum-signed chain. Each anchored entry gets a verifiable Sparse Merkle Tree (SMT) inclusion proof. The protocol is defined in `pkg/server/api.proto`.

## Minimal Integration (5 lines)

```go
import pb "github.com/had-nu/gleipnir/pkg/server/pb"

func SubmitHash(client pb.ProvenanceAnchorClient, hash []byte) error {
    _, err := client.SubmitHash(ctx, &pb.SubmitRequest{
        Hash: hash, Submitter: uid.RootID,
        Timestamp: time.Now().UnixNano(),
        Label:     "my-artifact",
        Signature: signPayload(uid, hash, ...),
    })
    return err
}
```

## Full Lifecycle (20 lines)

```go
// 1. Submit
client.SubmitHash(ctx, &pb.SubmitRequest{Hash: hash, ...})

// 2. Wait for anchor (blocking, up to 30s)
proof, _ := client.WaitForAnchor(ctx, &pb.WaitRequest{Hash: hash})

// 3. Verify inclusion
verifyResp, _ := client.VerifyHash(ctx, &pb.VerifyRequest{Hash: hash})

// 4. Cross-verify SMT proof against block
block, _ := client.GetBlock(ctx, &pb.BlockRequest{Index: proof.BlockIndex})
```

## Adapter Examples

### From Masthead (HTTP security scanner)

```go
// Parse Masthead JSON output → extract findings → hash → submit
for _, f := range scan.Findings {
    h := sha256.Sum256([]byte(f.Path + f.HeaderName))
    client.SubmitHash(ctx, &pb.SubmitRequest{Hash: h[:], ...})
}
```

### From Hashchain (backup integrity)

```go
// Read hashchain.db → hash filepath+data_hash+chain_hash → submit
for _, r := range records {
    h := sha256.Sum256([]byte(r.Filepath + r.DataHash + r.ChainHash))
    client.SubmitHash(ctx, &pb.SubmitRequest{Hash: h[:], ...})
}
```

### From Vigil (security event ledger)

```go
// Construct SecurityEvent → compute vigil hash → submit to IPC
evt := SecurityEvent{ID: uuid, Source: "masthead", FindingID: "f-001"}
evtHash := sha256.Sum256([]byte(computeVigilHash(evt)))
client.SubmitHash(ctx, &pb.SubmitRequest{Hash: evtHash[:], ...})
```

## Error Codes

| Code | Meaning | Action |
|------|---------|--------|
| `INVALID_SIGNATURE` | Signature missing or forged | Check signing payload matches server format |
| `SUBMITTER_MISMATCH` | Submitter RootID not registered | Use a known validator UID |
| `INVALID_HASH` | All-zero hash | Ensure hash is non-zero (32 bytes) |
| `RATE_LIMITED` | Too many submissions | Backoff and retry |

## Gaps (Not Covered by Current API)

1. **No `BlockHash` in Block response** — cannot independently verify PrevHash chaining without recomputing internally
2. **StreamBlocks is Unimplemented** — no streaming block enumeration; poll via `GetBlock(i)` for `i = 0..BlockHeight`
3. **Sub-chain manager not exposed via gRPC** — `SubChainManager` is internal; no cross-chain proof API
4. **SubmitResponse.block_index/block_time are always 0** — the response does not indicate when/where the hash will be anchored
5. **Per-entry Signature** — the `ProvenanceEntry.Signature` field is accepted but not verified server-side (no submitter public key registry for entry-level non-repudiation)
6. **No blob storage** — IPC only anchors hashes; the original data must be stored and served separately

## Test Coverage

Run the conformance test to validate your integration:

```bash
make docker-conformance
```

This builds a 5-validator network, runs 33 test cases covering auth, lifecycle, proofs, chain integrity, error handling, and real-project pipeline scenarios (Masthead, Hashchain, Vigil, Compliance-mappings), then tears down.

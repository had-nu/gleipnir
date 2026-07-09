# Immutable Provenance Chain (IPC) v1

Protocol for anchoring provenance hashes using simplified endocybernetic consensus.
**Gleipnir** is the reference implementation.

- VRF-based proposer selection (not round-robin)
- Dilithium3 3/3 quorum signing
- Sparse Merkle Tree for state root
- Laplacian λ₁ diffusion supervision

## Architecture

```
CLI (provectl) → gRPC API → Consensus Engine → SMT State → Chain Storage
                      ↕                         ↕
                Pipeline Sim (pipeline-sim)  Libp2p (future)
```

## Consensus

- **VRF pure**: proposer selected by `min(sha256(peerUID || cycle || stateRoot))`
- **Triad**: proposer + next 2 peers form the signing triad
- **Quorum**: 3/3 Dilithium3 signatures required to finalize a block
- **Cycle**: each cycle produces one anchored block

## State

- Sparse Merkle Tree (depth=256, Blake3)
- NetworkState: Laplacian eigenvalues derived from heartbeat topology
- NodeState: last heartbeat, latency matrix entries

## gRPC API

See `pkg/server/api.proto` for the full schema.

| Method | Description |
|--------|-------------|
| SubmitHash | Submit a provenance hash for anchoring |
| WaitForAnchor | Block until a hash is anchored |
| VerifyHash | Check if a hash is anchored |
| GetCurrentStateRoot | Get the current SMT root |
| GetHealth | Node health metrics |
| GetBlock | Get block by index |
| StreamBlocks | Stream blocks from range |

## Implementations

| Name | Language | Maintainer |
|------|----------|------------|
| Gleipnir | Go | had-nu |

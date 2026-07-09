![Gleipnir](Gleipnir-logo.png)

# Gleipnir

Reference implementation of **IPC (Immutable Provenance Chain)** — a minimal, cryptographically auditable provenance anchor network.

## Problem

Provenance data (hash anchors, document fingerprints, CI/CD attestations) is scattered across opaque centralized services with no tamper-evident chain. Existing blockchains are overkill — expensive, slow, and require tokens or complex setup.

## Solution

A lightweight **3-of-3 Dilithium3-quorum** network that anchors hashes into an immutable chain with no tokens, no mining, no external dependencies. Each cycle produces one anchored block signed by a VRF-selected triad of validators.

## For whom

- **DevOps / CI/CD** — anchor build and deployment attestations
- **Compliance / audit** — tamper-proof timestamp and hash trails
- **Researchers** — reproducible experiment provenance
- **Edge / embedded** — tiny footprint, no blockchain bloat

## Quick start

```bash
# Build
make build

# Bootstrap a 3-node local network
docker compose up -d

# Submit a hash
provectl submit --hash <sha256> --label "my-artifact"

# Verify
provectl verify --hash <sha256>
```

## Architecture

```
provectl → gRPC API → Consensus Engine → SMT State → Chain Storage
                ↕                         ↕
          pipeline-sim               Libp2p (future)
```

## Stack

| Component | Technology |
|-----------|------------|
| Consensus | VRF selection + Dilithium3 triad |
| State     | Sparse Merkle Tree (Blake3, depth 256) |
| Network   | gRPC (future: Libp2p) |
| Supervision | Laplacian λ₁ diffusion |
| Language  | Go |

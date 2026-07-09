<p align="center">
  <h1>Gleipnir</h1>
</p>

<p align="center">
  <img src="Gleipnir-logo.png" width="180" alt="Gleipnir">
</p>

<p align="center">
  <img src="https://img.shields.io/badge/go-1.24+-00ADD8?logo=go&logoColor=white" alt="Go">
  <img src="https://img.shields.io/badge/license-AGPL--3.0-blue" alt="License">
  <img src="https://img.shields.io/badge/build-passing-brightgreen" alt="Build">
  <img src="https://img.shields.io/badge/status-active-2ea44f" alt="Status">
</p>

Reference implementation of **IPC (Immutable Provenance Chain)** — a minimal, cryptographically auditable provenance anchor network.

## Problem

Provenance data (hash anchors, document fingerprints, CI/CD attestations) is scattered across opaque centralized services with no tamper-evident chain. Existing blockchains are overkill — expensive, slow, and require tokens or complex setup.

## Solution

A lightweight **3-of-3 Dilithium3-quorum** network that anchors hashes into an immutable chain with no tokens, no mining, no external dependencies. Each cycle produces one anchored block signed by a VRF-selected triad of validators.

## What it delivers

- **Immutable hash chain** — every anchored hash is permanently recorded in a linear, signed chain of blocks
- **Post-quantum signatures** — Dilithium3 3/3 quorum, no single point of compromise
- **VRF-based consensus** — fair, unpredictable proposer selection via verifiable random function seeded by state root
- **Instant finality** — one cycle = one block = final; no forks, no rollbacks
- **Sparse Merkle Tree state** — compact, verifiable state root via Blake3-based SMT (depth 256)
- **Self-supervising network** — Laplacian diffusion monitors topology health from heartbeat latencies
- **Zero token, zero mining, zero smart contracts** — pure consensus for provenance

## How it works

1. A **VRF round** selects a proposer from the active validator set using `min(sha256(peerUID || cycle || stateRoot))`
2. The proposer forms a **triad** with the next two peers in the sorted set
3. The triad collects pending hashes, builds a block, and each member signs with **Dilithium3**
4. With **3/3 signatures**, the block is finalized and appended to the chain
5. The **Sparse Merkle Tree** updates its root to reflect the new anchors
6. Each validator gossips its heartbeat; the **Laplacian λ₁** eigenvalue of the latency matrix supervises network diffusion

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

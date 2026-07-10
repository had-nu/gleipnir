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

A lightweight **3-of-3 Dilithium3-quorum** network that anchors hashes into an immutable chain with no tokens, no mining, no external dependencies. Each cycle produces one anchored block signed by a hash-selected triad of validators.

**Sub-chains** extend the model: every service (Wardex, anti-ransomware, etc.) gets its own SMT-anchored provenance chain, periodically checkpointed into the parent chain via cross-chain proofs.

## What it delivers

- **Immutable hash chain** — every anchored hash is permanently recorded in a linear, signed chain of blocks
- **Post-quantum signatures** — Dilithium3 3/3 quorum, no single point of compromise
- **Post-quantum KEM** — Kyber1024 key encapsulation for encrypted peer channels
- **Hash-based leader election** — deterministic proposer selection via `min(sha256(peerUID || cycle || stateRoot))`
- **Multi-node consensus** — gossip-based block proposal + SMT root verification + co-signing across N peers
- **Sub-chains** — per-service SMT + periodic anchoring + dual-Merkle cross-chain proofs
- **Instant finality** — one cycle = one block = final; no forks, no rollbacks
- **Sparse Merkle Tree state** — compact, verifiable state root via Blake3-based SMT (depth configurable, default 256)
- **Self-supervising network** — Laplacian diffusion monitors topology health from heartbeat latencies
- **Zero token, zero mining, zero smart contracts** — pure consensus for provenance
- **Peer discovery & real transport** — libp2p GossipSub + mDNS (see `pkg/transport/p2p`)
- **Persistence** — BoltDB-backed state with auto-persist on `Stop()` and `RunCycle()` (see `pkg/storage`)
- **Client validation** — exported `ValidateEntry`, `IsZeroHash`, machine-readable error codes (see `pkg/validation`)
- **Bounded rate limiting** — sliding-window per-submitter with LRU eviction (see `pkg/consensus/ratelimit.go`)
- **Contract-derived UID0** — deterministic identity bound to company contract hash (see `pkg/identity/contract.go`)

## How it works

1. A **hash round** selects a proposer from the active validator set using `min(sha256(peerUID || cycle || stateRoot))`
2. The proposer collects pending hashes via gossip, builds a block, inserts into the SMT, and broadcasts the proposal
3. Non-proposer peers insert the same entries into their local SMT, verify the root matches, and co-sign with **Dilithium3**
4. With **3/3 signatures**, the block is finalized and appended to the chain
5. Service operators register **sub-chains** (one per service), submit entries, and periodically **anchor** the sub-chain state root into the parent chain
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
                 ↕
           SubChainManager (per-service SMT → anchoring → parent chain)
                 ↕
           Transport (Kyber1024 KEM → ChaCha20-Poly1305 AEAD)
```

## Current status

`RunCycle()` supports **single-node** (`NewEngine`) and **multi-node** (`NewEngineWithPeers` + `GossipChannel`) modes. The multi-node path builds blocks via gossip, verifies SMT root replication, and collects Dilithium3 co-signatures. Sub-chains (`SubChainManager`) enable per-service anchoring with cross-chain proofs. Transport layer (`pkg/transport`) provides KEM-authenticated AEAD channels (Kyber1024 + ChaCha20-Poly1305).

**Production hardening complete** (G1–G6):
- **gRPC API**: protobuf init panic resolved; server tests pass (`pkg/server`)
- **P2P transport**: libp2p GossipSub + mDNS discovery (`pkg/transport/p2p`)
- **Persistence**: BoltDB-backed `EngineStorage` auto-loads on init, auto-saves on `Stop()` and `RunCycle()` (`pkg/storage`)
- **Client validation**: `pkg/validation` exports `ValidateEntry`, `IsZeroHash`, `ValidationError` with codes
- **Rate limiting**: sliding-window per-submitter with LRU eviction (no memory leaks) (`pkg/consensus/ratelimit.go`)
- **SMT depth**: configurable via `state.Config.SMTDepth` (default 256), used by engine + sub-chains

The submission API is hardened (`pkg/consensus/api.go`): `Enqueue` validates entries and enforces rate limits, `RunCycle` recovers from panics, and `Engine.Stop` halts intake cleanly. UID0 root identity can be derived deterministically from a company contract hash (`pkg/identity/contract.go`), giving verifiable "node speaks for contract X" binding.

## Stack

| Component | Technology |
|-----------|------------|
| Consensus | Hash-based leader election + Dilithium3 triad |
| State     | Sparse Merkle Tree (Blake3, depth configurable, default 256) |
| Transport | Kyber1024 KEM + ChaCha20-Poly1305 AEAD (libp2p GossipSub + mDNS) |
| Sub-chains | Per-service SMT + dual-Merkle cross-chain proofs |
| Network   | gRPC + Libp2p GossipSub |
| Supervision | Laplacian λ₁ diffusion |
| Persistence | BoltDB (embedded) |
| Rate limiting | Sliding window + LRU eviction |
| Language  | Go |

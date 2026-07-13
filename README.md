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

<p align="center">
  <a href="README.pt.md">🇧🇷&nbsp;<b>Ler em Português</b> &rarr;</a>
</p>

Reference implementation of **IPC (Immutable Provenance Chain)** — a minimal, cryptographically auditable provenance anchor network.

## Problem

**Knowing is not the same as demonstrating.** A team can have correct internal processes, rigorous logging, and airtight controls — yet fail an external audit because the evidence was never designed to be read by an outsider. Logs can be rotated, databases can be altered, timestamps can be faked. Even with the best intentions, *showing* that a given artifact existed at a given point in time, untouched, requires a system whose entire purpose is to be inspected.

This is fundamentally a **chain-of-custody of decisions** problem, not a logging problem. An auditor investigating an incident needs to know: *who decided to promote that build? What was the review basis? Can we cryptographically prove that the decision recorded is exactly the decision that produced the artifact that caused the incident?* Standard logs answer "what happened when" — but not "who decided, based on what, and can we trust it." Gleipnir closes that gap with **accountability** (every anchored entry is bound to a submitter identity) and **non-repudiation** (once signed and quorum-validated, no party can deny the submission).

Existing solutions fall short:
- **Centralised timestamping services** are opaque — you trust their word, not their proof.
- **General-purpose blockchains** are overkill — expensive, slow, token-dependent, and require complex setup for a single task: anchoring hashes.
- **Homegrown audit trails** are not designed for adversarial review — the same team that runs the process also controls the evidence.

## Solution

A lightweight **M-of-N Dilithium3-quorum** network that anchors hashes into an immutable chain with no tokens, no mining, no external dependencies. Each cycle produces one anchored block signed by a VRF-selected proposer and validated by a configurable threshold of validators. It is designed from the ground up to produce evidence of **who decided what, when, and based on what** — evidence that survives adversarial scrutiny because it was built to be read by someone who does not trust you.

**Sub-chains** extend the model: every service (Wardex, anti-ransomware, etc.) gets its own SMT-anchored provenance chain, periodically checkpointed into the parent chain via cross-chain proofs.

## What it delivers

- **Immutable hash chain** — every anchored hash is permanently recorded in a linear, signed chain of blocks
- **Post-quantum signatures** — Dilithium3 M-of-N quorum, configurable threshold
- **Post-quantum KEM** — Kyber1024 key encapsulation for encrypted peer channels
- **ECVRF leader election** — Ristretto255 VRF per RFC 9381, grinding-resistant, each proof verifiable
- **Multi-node consensus** — gossip-based ECVRF proposer selection + SMT root verification + M-of-N co-signing
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

## Compliance narrative

| Technical feature | What it means for an auditor |
|---|---|
| **M-of-N Dilithium3 quorum** | No single party can forge or backdate evidence — collusion of M validators is required. The threshold is configurable (e.g., 3/3 for high-assurance, 2/3 for operational flexibility). |
| **ECVRF leader election** | Block proposers are selected verifiably at random — no one chooses who builds the next block, so no one can game the timeline. |
| **Instant finality** | One cycle = one block = final. No forks, no rollbacks. Once anchored, a hash is permanently recorded — there is no "undo" window. |
| **Sparse Merkle Tree (SMT)** | Every block commits to a verifiable state root. A client can request a compact proof that a specific hash was included — and any third party can verify that proof against the public chain. |
| **Sub-chains + cross-chain proofs** | Each service (e.g., CI/CD pipeline, document management, anti-ransomware) gets its own isolated chain, periodically checkpointed into the parent chain. An auditor sees per-service evidence plus a cryptographic link to the global timeline. |
| **Contract-bound UID0 identity** | Each validator node is cryptographically bound to a company contract hash — the node speaks for the legal entity, not for an anonymous key. |
| **Decision anchoring** | Each anchored entry includes the submitter's identity and a human-readable label. An auditor can trace a specific artifact back to the person or system that submitted it, the moment it was submitted, and the block that finalised it — establishing a cryptographically verifiable chain of custody from decision to deployment. |
| **Laplacian self-supervision** | The network monitors its own health via diffusion eigenvalues. An auditor can verify that the network was operational at the claimed times, not just that blocks exist. |

## How it works

1. Each peer computes a **ECVRF proof** `sk.Prove(cycle || stateRoot)` using their Ristretto255 VRF key — proofs are gossiped, verified against each peer's VRF public key, and the peer with the lowest Gamma becomes proposer
2. The proposer collects pending hashes via gossip, builds a block, inserts into the SMT, and broadcasts the proposal
3. Non-proposer peers insert the same entries into their local SMT, verify the root matches, and co-sign with **Dilithium3**
4. With an **M-of-N threshold** of signatures, the block is finalized and appended to the chain
5. Service operators register **sub-chains** (one per service), submit entries, and periodically **anchor** the sub-chain state root into the parent chain
6. Each validator gossips its heartbeat; the **Laplacian λ₁** eigenvalue of the latency matrix supervises network diffusion

## For whom

- **DevOps / CI/CD** — anchor build and deployment attestations
- **Compliance / audit** — decision chain-of-custody with non-repudiation, not just tamper-proof logs
- **Researchers** — reproducible experiment provenance
- **Edge / embedded** — tiny footprint, no blockchain bloat

## Quick start

```bash
# Build
make build

# Bootstrap a 5-validator local network
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
           SubChainManager      Libp2p GossipSub + mDNS
           (per-service SMT →   (peer discovery & transport)
            anchoring →
            parent chain)
                 ↕
           Transport (Kyber1024 KEM → ChaCha20-Poly1305 AEAD)
```

See [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) for the full architectural description, deployment topology, and sub-chain model.

## Current status

`RunCycle()` supports **single-node** (`NewEngine`) and **multi-node** (`NewEngineWithPeers` + `GossipChannel`) modes. The multi-node path uses ECVRF proposer selection, builds blocks via gossip, verifies SMT root replication, and collects M-of-N Dilithium3 co-signatures. Sub-chains (`SubChainManager`) enable per-service anchoring with cross-chain proofs. Transport layer (`pkg/transport`) provides KEM-authenticated AEAD channels (Kyber1024 + ChaCha20-Poly1305).

**Issues #1–4 resolved** (I1–I4):
- **ECVRF leader election**: Ristretto255 VRF per RFC 9381 — each peer proves proposer selection with a verifiable, unpredictable cryptographic proof; grinding-resistant
- **M-of-N BFT quorum**: configurable threshold (1/1 single-node, 3/3 or higher multi-node); duplicate-signature attack rejected (each distinct signer counted once)
- **Kyber1024 KEM**: used in `pkg/transport/secure_conn.go` for encrypted peer channels
- **Power iteration for λ₁**: shift-invert power iteration with Cholesky factorization; falls back to dense EigenSym for small matrices or non-convergence

**Also complete** (G1–G6):
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
| Consensus | ECVRF leader election (Ristretto255, RFC 9381) + Dilithium3 M-of-N quorum |
| State     | Sparse Merkle Tree (Blake3, depth configurable, default 256) |
| Transport | Kyber1024 KEM + ChaCha20-Poly1305 AEAD (libp2p GossipSub + mDNS) |
| Sub-chains | Per-service SMT + dual-Merkle cross-chain proofs |
| Network   | gRPC + Libp2p GossipSub |
| Supervision | Laplacian λ₁ diffusion |
| Persistence | BoltDB (embedded) |
| Rate limiting | Sliding window + LRU eviction |
| Language  | Go |

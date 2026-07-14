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
  <a href="README.pt.md"><b>Ler em Portugues</b> &gt;</a>
</p>

Go reference implementation of the
[**3CP** (Cryptographic Chain-of-Custody Protocol)](https://github.com/had-nu/3CP)
— a minimal, cryptographically auditable chain-of-custody network.

## Problem

**Knowing is not the same as demonstrating.** A team can have correct internal processes, rigorous logging, and airtight controls — yet fail an external audit because the evidence was never designed to be read by an outsider. Logs can be rotated, databases can be altered, timestamps can be faked. Even with the best intentions, *showing* that a given artifact existed at a given point in time, untouched, requires a system whose entire purpose is to be inspected.

This is fundamentally a **chain-of-custody of decisions** problem, not a logging problem. An auditor investigating an incident needs to know: *who decided to promote that build? What was the review basis? Can we cryptographically prove that the decision recorded is exactly the decision that produced the artifact that caused the incident?* Standard logs answer "what happened when" — but not "who decided, based on what, and can we trust it." Gleipnir closes that gap with **accountability** (every anchored entry is bound to a submitter identity) and **non-repudiation** (once signed and quorum-validated, no party can deny the submission).

Existing solutions fall short:
- **Centralised timestamping services** are opaque — you trust their word, not their proof.
- **General-purpose blockchains** are overkill — expensive, slow, token-dependent, and require complex setup for a single task: anchoring hashes.
- **Homegrown audit trails** are not designed for adversarial review — the same team that runs the process also controls the evidence.

## Solution

A lightweight **M-of-N Dilithium3-quorum** network that anchors hashes into an immutable chain with no tokens, no mining, no external dependencies. Each cycle produces one anchored block signed by a VRF-selected proposer and validated by a configurable threshold of validators. It is designed from the ground up to produce evidence of **who decided what, when, and based on what** — evidence that survives adversarial scrutiny because it was built to be read by someone who does not trust you.

**Sub-chains** extend the model: every service gets its own SMT-anchored provenance chain, periodically checkpointed into the parent chain via cross-chain proofs.

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
- **gRPC client authentication** — `SubmitHash` requires Dilithium3 caller signature verified against registered RootID
- **Multi-identity entries** — `Approver` field for split-authority submissions, `Reference` field for cross-entry linking
- **Per-entry non-repudiation** — Dilithium3 signature on each `ProvenanceEntry` binding submitter (and approver) to the anchored content

## Compliance narrative

| Technical feature | What it means for an auditor |
|---|---|
| **M-of-N Dilithium3 quorum** | No single party can forge or backdate evidence — collusion of M validators is required. The threshold is configurable (e.g., 3/3 for high-assurance, 2/3 for operational flexibility). |
| **ECVRF leader election** | Block proposers are selected verifiably at random — no one chooses who builds the next block, so no one can game the timeline. |
| **Instant finality** | One cycle = one block = final. No forks, no rollbacks. Once anchored, a hash is permanently recorded — there is no "undo" window. |
| **Sparse Merkle Tree (SMT)** | Every block commits to a verifiable state root. A client can request a compact proof that a specific hash was included — and any third party can verify that proof against the public chain. |
| **Sub-chains + cross-chain proofs** | Each service gets its own isolated chain, periodically checkpointed into the parent chain. An auditor sees per-service evidence plus a cryptographic link to the global timeline. |
| **Contract-bound UID0 identity** | Each validator node is cryptographically bound to a company contract hash — the node speaks for the legal entity, not for an anonymous key. |
| **Decision anchoring** | Each anchored entry includes the submitter's identity, optionally an approver's identity for split-authority decisions, a reference to related entries for chained decisions, and a per-entry Dilithium3 signature for non-repudiation. An auditor can trace a specific artifact back to the person or system that submitted (and approved) it, linked to related evidence, with cryptographic proof binding each identity to the entry content. |
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

`RunCycle()` supports **single-node** (`NewEngine`) and **multi-node** (`NewEngineWithPeers` + `GossipChannel`) modes. The multi-node path uses ECVRF proposer selection, builds blocks via gossip, verifies SMT root replication, and collects M-of-N Dilithium3 co-signatures. Sub-chains (`SubChainManager`) enable per-service anchoring with cross-chain proofs.

The `SubmitHash` gRPC endpoint requires Dilithium3 client authentication — each request carries a caller signature verified against a registered RootID. Entries support split-authority submissions (`Approver` field) and cross-entry linking (`Reference` field). Each `ProvenanceEntry` optionally carries a per-entry Dilithium3 signature for non-repudiation binding the submitter (and approver) to the anchored content.

**Consensus** — ECVRF leader election (Ristretto255, RFC 9381, grinding-resistant) with configurable M-of-N Dilithium3 quorum. Duplicate-signature attack rejected (each distinct signer counted once).

**Transport** — KEM-authenticated AEAD channels via Kyber1024 + ChaCha20-Poly1305, with libp2p GossipSub + mDNS peer discovery (`pkg/transport/p2p`). BoltDB-backed persistence (`pkg/storage`), sliding-window rate limiting with LRU eviction (`pkg/consensus/ratelimit.go`), and power iteration for λ₁ with fallback to dense EigenSym (`pkg/state`).

**Identity** — UID0 soulbound tokens with contract-bound derivation (`pkg/identity/contract.go`). Deterministic `NewUIDZeroFromContract(contractHash, nodeSalt, simulated)` binds a node to a legal entity.

**Submission API** — `Enqueue` validates entries (rejects zero hashes, empty submitters, oversized labels) and enforces rate limits; `RunCycle` recovers from panics; `Engine.Stop` halts intake cleanly.

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

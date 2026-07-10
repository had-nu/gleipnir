# Gleipnir Technical Blueprint

Immutable Provenance Chain (IPC) v1 reference implementation.

## Table of Contents

1. [Project map](#project-map)
2. [Architecture overview](#architecture-overview)
3. [Consensus cycle](#consensus-cycle)
4. [Package by package](#package-by-package)
5. [Key interfaces](#key-interfaces)
6. [Data model](#data-model)
7. [Extension points](#extension-points)
8. [Development](#development)

---

## Project map

```
├── cmd/
│   ├── provectl/          # CLI — submit, verify, validate
│   ├── provenanced/       # gRPC server daemon
│   └── pipeline-sim/      # Multi-node pipeline simulator
├── pkg/
│   ├── chain/             # Protocol types (Block, Entry, AnchorProof, SubChain)
│   ├── consensus/         # Hash-based leader election, triad, quorum, Engine, SubChainManager
│   ├── identity/          # uID0 soulbound, Dilithium3, Kyber1024, contract-derived UID0
│   ├── smt/               # Sparse Merkle Tree (Blake3, depth configurable)
│   ├── state/             # NetworkState, Laplacian supervision
│   ├── transport/         # KEM handshake + ChaCha20-Poly1305 secure channel, libp2p GossipSub
│   ├── storage/           # BoltDB persistence (EngineStorage interface)
│   ├── validation/        # Client-side submission validation + error codes
│   └── server/            # gRPC server + generated protobuf
├── client/                # Go client library (gRPC wrapper)
├── spec/                  # Protocol specification
├── bench/                 # Performance benchmarks
├── deploy/                # Kubernetes manifests, Helm
├── docs/                  # Developer documentation
└── test/                  # Integration tests
```

### Dependency direction

```
provectl (CLI)         pipeline-sim
    │                       │
    ├──→ pkg/server/pb ◄────┘
    │       │
    └──→ pkg/identity
            │
    pkg/server ──→ pkg/chain
          │
          └──→ pkg/consensus ──→ pkg/chain
                   ├──→ pkg/identity
                   ├──→ pkg/smt
                   ├──→ pkg/state
                   ├──→ pkg/transport
                   ├──→ pkg/storage
                   └──→ pkg/validation
```

**Rule**: code in `pkg/` never imports `cmd/` or `pkg/server/`. The core packages (`chain`, `consensus`, `identity`, `smt`, `state`, `transport`, `storage`, `validation`) have zero gRPC or CLI dependencies.

---

## Architecture overview

Gleipnir is a self-contained, tokenless consensus network that anchors provenance hashes into an immutable chain. It replaces external dependencies like Ethereum with a minimal hash-based election protocol.

### Three-tier model

| Layer | Responsibility | Package |
|-------|---------------|---------|
| **Protocol types** | Block, ProvenanceEntry, AnchorProof, SubChain types, Anchorer interface | `pkg/chain/` |
| **Core engine** | Hash-based leader election, Dilithium3 signing, SMT state, cycles, sub-chain manager | `pkg/consensus/` |
| **Identity** | uID0 soulbound tokens, Dilithium3, Kyber1024 KEM | `pkg/identity/` |
| **State** | Network topology, Laplacian eigenvalues | `pkg/state/` |
| **SMT** | Blake3 Sparse Merkle Tree (depth 256) | `pkg/smt/` |
| **Transport** | KEM handshake + AEAD secure channel | `pkg/transport/` |
| **gRPC server** | Network API (optional — not needed for embedded use) | `pkg/server/` |

### Embedded vs sidecar

Gleipnir is designed to work in two modes:

- **Embedded**: `consensus.NewEngine(node, interval)` — runs inside your process. Import `github.com/had-nu/gleipnir/pkg/consensus`. No gRPC needed.
- **Sidecar**: `provenanced` daemon with gRPC API. Connect via `client.New()` for remote anchoring.

### Current status: F1–F6 + G1–G6 complete

| Phase | Scope | Status |
|-------|-------|--------|
| **F1** | Multi-node gossip (`MemoryBus`), `NewEngineWithPeers`, proposer/verifier cycle | ✅ |
| **F2** | Kyber1024 KEM (`pkg/identity/kyber.go`) | ✅ |
| **F3** | `pkg/transport` SecureConn — Kyber handshake + ChaCha20-Poly1305 AEAD with random nonces, HKDF(sorted peer IDs) | ✅ |
| **F4** | `SubChainManager` — per-service SMT + anchor lifecycle (`Register`, `Submit`, `Anchor`, `Prove`, `VerifyCrossChain`) | ✅ |
| **F5** | API hardening — `pkg/consensus/api.go`: validation, rate limits, panic recovery, `Stop()`/`SetAPILimits()` | ✅ |
| **F6** | Contract-derived UID0 — `pkg/identity/contract.go`: `ContractHash`, `NewUIDZeroFromContract` (DRBG-seeded Dilithium), `ContractOf` | ✅ |
| **G1** | Protobuf init panic resolved — compatible versions pinned, files regenerated | ✅ |
| **G2** | Peer discovery + real transport — `pkg/transport/p2p/gossip.go`: libp2p GossipSub + mDNS, bootstrap peers | ✅ |
| **G3** | Persistence — `pkg/storage/`: BoltDB `EngineStorage`, `SetStorage()`, auto-persist on `Stop()`/`RunCycle()` | ✅ |
| **G4** | Exported validation — `pkg/validation/`: `ValidateEntry`, `IsZeroHash`, error codes (`ValidationError`) | ✅ |
| **G5** | Rate limiter fix — `pkg/consensus/ratelimit.go`: sliding window + LRU eviction (bounded memory) | ✅ |
| **G6** | SMT depth configurable — `state.Config.SMTDepth` (default 256), used by engine + sub-chains | ✅ |

What you get today:
- **Multi-node consensus**: N-node gossip-based cycle with deterministic proposer selection, verified SMT root replication, quorum signature collection
- **Kyber1024 KEM**: key encapsulation for encrypted peer channels
- **ChaCha20-Poly1305 secure transport**: AEAD-encrypted messages with random nonces, keyed via HKDF(Kyber1024 shared secret, sorted peer IDs)
- **Sub-chain registry**: per-service SMT + anchor lifecycle via `SubChainManager` (`Register`, `Submit`, `Anchor`, `Prove`, `VerifyCrossChain`)
- **Hardened submission API**: `Enqueue` validates entries (rejects zero hashes, empty submitters, oversized labels) and enforces rate limits (total pending + per-submitter caps); `RunCycle` recovers from panics; `Engine.Stop` halts intake cleanly
- **Contract-derived UID0**: `NewUIDZeroFromContract(contractHash, nodeSalt, simulated)` derives a deterministic, reproducible UID0 root identity bound to a company's contract hash (DRBG-seeded Dilithium3 key), enabling verifiable "this node speaks for contract X" proofs
- **Peer discovery & real transport**: `pkg/transport/p2p` libp2p GossipSub implementation of `GossipChannel` with mDNS discovery and bootstrap peers
- **Persistence**: BoltDB-backed `EngineStorage` interface; `SetStorage()` loads state on init, auto-persists on `Stop()` and after each `RunCycle()`
- **Client validation**: `pkg/validation` exports `ValidateEntry`, `IsZeroHash`, and machine-readable error codes (`ValidationError` with `Code` field) for programmatic handling
- **Bounded rate limiting**: sliding-window per-submitter limiter with LRU eviction (max 10k tracked submitters); no unbounded map growth

No remote peer discovery (gRPC reachable, but no libp2p peer exchange in F1–F6 — implemented in G2).

---

## Consensus cycle

One cycle = one anchored block. The ticker-driven loop:

```
1. TICK ─→ Lock state
              │
2.           Select proposer via hash
               min(sha256(peerUID || cycle || stateRoot))
              │
3.           Proposer path:
               ├─ Collect entries (gossip.Snapshot() or local pending)
               ├─ Dedup by hash
               ├─ Insert into SMT, compute StateRoot
               ├─ Build Block
               ├─ Sign BlockHash (Dilithium3)
               ├─ gossip.Propose(block)
               └─ gossip.PublishSig(sig)
              │
             Non-proposer path:
               ├─ block ← gossip.GetProposed(cycle)
               ├─ Insert entries into local SMT
               ├─ Verify local StateRoot == proposer's
               ├─ Sign BlockHash (Dilithium3)
               └─ gossip.PublishSig(sig)
              │
4.           Collect triad co-signatures (≥3 peers)
              │
5.           Apply state transition:
               - Update Laplacian λ₁ from heartbeats
               - Increment cycle
              │
6.           Append block ─→ Unlock
```

Exported as `Engine.RunCycle()` for manual triggering. The ticker runs `RunCycle()` on `cycleInterval`.

### Cycle loop code path

```
Engine.Start()
  └→ cycleLoop()                     [engine.go:162]
       └→ RunCycle()                 [engine.go:176]
            ├→ SelectProposer()      [triad.go:11]
            ├→ gossip.Snapshot/Propose/GetProposed/PublishSig/GetSigs [gossip.go]
            ├→ st.Insert()           [smt.go]
            ├→ st.Prove()            [smt.go]
            ├→ identity.SignDilithium() [dilithium.go]
            └→ state.Apply()         [apply.go]
```

---

## Package by package

### `pkg/chain/` — Protocol types

| Type | Fields | Purpose |
|------|--------|---------|
| `Block` | Index, PrevHash, Proposer, Anchored entries, StateRoot, Lambda1, Timestamp, Sigs, BlockHash | Atomic unit of the chain |
| `ProvenanceEntry` | Hash [32]byte, Submitter, Timestamp, Label | A single anchored hash |
| `AnchorProof` | Found, BlockIndex, BlockTime, StateRoot, SMTProof, Submitter, Label | Verification output |
| `NetworkHealth` | Lambda1, ActivePeers, TotalPeers, BlockHeight, PendingHashes | Engine status |
| `Ticket` | Hash, Status, BlockIndex | Acknowledge a submission |
| `Anchorer` | (interface, see below) | Embedding contract |
| `SubChainID` | `[32]byte` | Blake3 identifier for a sub-chain |
| `SubChainDescriptor` | ID, Name, Owner, Genesis, CreatedAt, Active | Sub-chain registration metadata |
| `CrossChainAnchor` | SubChainID, StateRoot, PrevAnchorHash, Height, Timestamp | Sub-chain root anchor record |
| `CrossChainProof` | EntryHash, SubChainRoot, SubChainProof, AnchorHash, AnchorBlock, ParentRoot, ParentProof | Dual-Merkle cross-chain proof |

### `pkg/consensus/` — Engine, gossip, and sub-chains

- `Engine` — central state machine. Holds the SMT, block chain, pending queue, anchored map.
- `Node` — identity + address + peer list for a validator.
- `Peer` — remote node identity + address + liveness flag.
- `SelectProposer()` — hash-based: peer with lowest `sha256(peerUID || cycle || stateRoot)`.
- `SelectTriad()` — proposer + next two peers in sorted set.
- `VerifyQuorum()` — 3/3 Dilithium3 signature check.
- `GossipChannel` — interface for inter-node communication (`Publish`, `Snapshot`, `Propose`, `GetProposed`, `PublishSig`, `GetSigs`, `RemoveEntries`).
- `MemoryBus` — in-memory implementation of `GossipChannel`, used for single-process multi-node tests.
- `SubChainManager` — sub-chain lifecycle: `Register(name, owner)`, `Submit(id, entry)`, `Anchor(id)`, `Prove(id, entryHash)`, `VerifyCrossChain(proof, parentRoot)`. Each sub-chain has its own SMT; anchoring flushes pending entries, computes the state root, and enqueues a `ProvenanceEntry` with `Label: "subchain:anchor"` into the parent chain.

### `pkg/identity/` — Post-quantum identity + KEM

- `UIDZeroSoulbound` — CBOR-serializable identity token. Contains RootID, Dilithium3 keypair, merkle proofs, entropy, and recovery info.
- `NewUIDZero(seed, simulated)` — create identity. The `simulated` flag generates deterministically for dev.
- `GenerateDilithiumKey(rng)` → (pk, sk) — ML-DSA-65 (Dilithium3).
- `SignDilithium(sk, msg)` → sig.
- `VerifyDilithium(pk, msg, sig)` → bool.
- `KyberGenerateKey()` → (pk, sk) — Kyber1024 KEM keypair.
- `KyberEncapsulate(pk)` → (ct, ss) — generate ciphertext + shared secret.
- `KyberDecapsulate(sk, ct)` → ss — recover shared secret.
- `Hash(data)` → blake3.Sum256.
- `Derive(context, material, length)` → Blake3 `DeriveKey`.

### `pkg/smt/` — Sparse Merkle Tree

- `SparseMerkleTree` — depth 256, Blake3.
- `New(depth)` → default tree.
- `Insert(key, value)` → update leaf.
- `Get(key)` → value.
- `Prove(key)` → merkle proof (sibling hashes).
- `Verify(root, key, value, proof)` → bool.
- `BulkInsert(keys, values)` → batch insert.

Internal storage uses two maps: `data map[[32]byte][]byte` for leaves and `cache map[[32]byte][32]byte` for computed nodes.

### `pkg/transport/` — KEM-authenticated secure channel

- `PeerInfo` — peer identity + public key from handshake.
- `Message` / `MessageType` — typed message envelope.
- `SecureConn` — AEAD-encrypted connection over TCP.
  - `ServerHandshake(conn, sk, pk, peerID)` → `(*SecureConn, PeerInfo, error)` — responder side of the KEM handshake.
  - `ClientHandshake(conn, sk, pk, peerID)` → `(*SecureConn, PeerInfo, error)` — initiator side.
  - `WriteMessage(data)` → encrypt with ChaCha20-Poly1305 (random 12-byte nonce prepended).
  - `ReadMessage()` → decrypt and return plaintext.
- Handshake: exchange Dilithium3 public keys → Kyber1024 encapsulate/decapsulate → HKDF(key, sorted peer IDs) → single shared AEAD key.
- Message format: `[4-byte frame length][12-byte nonce][AEAD ciphertext]`.

### `pkg/state/` — Network state and supervision

- `NetworkState` — cycle counter, NodeState map, ReputationGraph, SupervisionRoot, Lambda1.
- `NodeState` — heartbeat, latency, status.
- `ReputationGraph` — adjacency matrix (dense `mat.SymDense`).
- `Apply(state, prevRoot, heartbeats, cfg)` → compute next state, Laplacian λ₁.
- `ComputeLambda1(matrix)` → smallest eigenvalue of the Laplacian.
- `BuildLaplacian(graph)` → graph Laplacian matrix from adjacency.
- `ComputeSupervisionRoot(s)` → CBOR+Blake3 root of `{Cycle, Nodes, Graph, Lambda1}`.

### `pkg/server/` — gRPC API

Exposes Engine over gRPC using `api.proto` definitions. Methods:

| Method | Proto | Wraps Engine method |
|--------|-------|---------------------|
| SubmitHash | `SubmitRequest → SubmitResponse` | `Enqueue()` |
| WaitForAnchor | `WaitRequest → AnchorProof` | `WaitForAnchor()` |
| VerifyHash | `VerifyRequest → AnchorProof` | `LookupHash()` |
| GetCurrentStateRoot | `Empty → StateRootResponse` | `GetStateRoot()` |
| GetHealth | `Empty → HealthResponse` | `GetHealth()` |
| GetBlock | `BlockRequest → BlockResponse` | `GetBlock()` |

---

## Key interfaces

### `chain.Anchorer`

The embedding contract for programmatic use:

```go
type Anchorer interface {
    Submit(ctx, hash [32]byte, submitter []byte, label string) (*Ticket, error)
    VerifyHash(ctx, hash [32]byte) (*AnchorProof, error)
    WaitForAnchor(ctx, hash [32]byte) (*AnchorProof, error)
    GetNetworkHealth(ctx) (*NetworkHealth, error)
    Close() error
}
```

`consensus.Engine` implements `chain.Anchorer` directly. You can type-switch or inject.

### `consensus.GossipChannel`

Abstract network layer for multi-node operation:

```go
type GossipChannel interface {
    Publish(entry chain.ProvenanceEntry)
    Snapshot() []chain.ProvenanceEntry
    RemoveEntries(remove map[[32]byte]bool)
    Propose(block chain.Block, proposerID string)
    GetProposed(cycle uint64) *chain.Block
    PublishSig(sig BlockSig)
    GetSigs(cycle uint64) []BlockSig
}
```

`MemoryBus` implements `GossipChannel` in-memory for single-process multi-node tests. A production implementation (e.g., over libp2p GossipSub) implements the same interface.

### `state.Config`

Controls Laplacian diffusion parameters:

```go
type Config struct {
    Eta             float64  // diffusion rate, default 0.28
    DecayRate       float64  // status decay per cycle, default 0.05
    MinLambda1      float64  // minimum λ₁ threshold, default 0.10
    LambdaInterval  uint64   // recompute λ₁ every N cycles (0 = every cycle)
}
```

---

## Data model

### Block structure

```
Block {
    Index:     uint64           ← sequential block number
    PrevHash:  []byte           ← sha256 of previous block
    Proposer:  []byte           ← RootID of selected proposer
    Anchored:  []ProvenanceEntry  ← entries anchored in this block
    StateRoot: []byte           ← SMT root after insertion
    Lambda1:   float64          ← Laplacian eigenvalue at block time
    Timestamp: int64            ← unix nanos
    Sigs:      [3][]byte         ← Dilithium3 signatures (triad)
    BlockHash: []byte           ← sha256 of all above (minus Sigs, BlockHash)
}
```

### Identity serialization (CBOR)

`UIDZeroSoulbound` serializes deterministically via `fxamacker/cbor/v2`. Fields are keyed by integers for canonical ordering:

```
0: RootID       1: FEntropy       2: GenesisHash
3: MerkleProofs  4: SigRecovery    5: SigUpdate
6: SigAudit      7: ReputationSum  8: SiderealTime
9: CycleIndex   10: GeneratedAt   11: MerkleRoot
12: MerkleProof  13: Simulated    14: FinalDigest
15: PublicKey    16: SecretKey
```

### SMT proof format

SMT proofs are flattened `[depth][32]byte` → `[]byte` (8192 bytes for depth 256). The prover returns sibling hashes from leaf to root. Verifier walks the proof against a known root.

---

## Extension points

### 1. Custom drivers (Wardex-style)

The `Anchorer` interface allows any provenance backend to be substituted. Add a new driver by implementing:

```go
type CustomDriver struct { ... }
func (d *CustomDriver) Submit(ctx, hash, submitter, label) (*Ticket, error)
func (d *CustomDriver) VerifyHash(ctx, hash) (*AnchorProof, error)
func (d *CustomDriver) WaitForAnchor(ctx, hash) (*AnchorProof, error)
func (d *CustomDriver) GetNetworkHealth(ctx) (*NetworkHealth, error)
func (d *CustomDriver) Close() error
```

### 2. Embedded engine

Import and use without gRPC (single-node mode — see [issue #5](https://github.com/had-nu/gleipnir/issues/5)):

```go
import "github.com/had-nu/gleipnir/pkg/consensus"

uid := identity.NewUIDZero("my-node", true)
eng := consensus.NewEngine(consensus.Node{UID: *uid}, 3*time.Second)
eng.Start()
eng.Submit(ctx, hash, uid.RootID, "my-label")
proof, _ := eng.WaitForAnchor(ctx, hash)
eng.Close()
```

### 3. Adding new consensus rules

- Proposer selection: modify `SelectProposer()` in `triad.go`
- Quorum logic: modify `VerifyQuorum()` in `quorum.go`
- Block structure: add fields in `chain/block.go`
- State supervision: adjust `state.Config` or `state.Apply()`

### 4. New crypto primitives

- Identity: add files in `pkg/identity/` following the pattern in `dilithium.go`
- Hashing: swap `blake3` in `pkg/smt/smt.go` and `pkg/identity/blake3.go`

---

## Development

### Dependencies

| Dependency | Reason |
|------------|--------|
| `cloudflare/circl` | Dilithium3, Kyber1024 |
| `fxamacker/cbor/v2` | Deterministic CBOR | 
| `gonum.org/v1/gonum` | `mat.SymDense` eigendecomposition |
| `lukechampine.com/blake3` | BLAKE3 hashing |
| `google.golang.org/grpc` | gRPC server (optional) |
| `google.golang.org/protobuf` | Protobuf (optional) |
| `prometheus/client_golang` | Metrics (server only) |

### Build

```bash
make build          # all binaries
make test           # unit tests
make bench          # benchmarks
make lint           # vet + staticcheck
```

### Testing patterns

- `*_test.go` co-located with source (standard Go)
- `consensus_test.go` tests: `TestExecuteCycle`, `TestProposerSelection`, `TestQuorum`
- `identity_test.go` tests: `TestUIDZeroRoundtrip`, `TestDilithiumSignVerify`
- `smt_test.go` tests: `TestInsertAndProve`, `TestBulkInsert`
- `state_test.go` tests: `TestStateTransition`, `TestLaplacian`

Benchmarks follow Go's standard `BenchmarkXxx` naming and run via `go test -bench=.`.

### Protobuf regeneration

```bash
protoc --go_out=. --go_opt=paths=source_relative \
  --go-grpc_out=. --go-grpc_opt=paths=source_relative \
  pkg/server/api.proto
```

### Go module

```go
module github.com/had-nu/gleipnir
```

Published at `proxy.golang.org`. Private use: set `GOPRIV=github.com/had-nu/*` and configure git SSH.

### Versioning

Tags follow `vMAJOR.MINOR.PATCH`. Breaking changes increment major. Pre-release suffixes (`-beta`, `-rc1`) denote stability.

### Where to start reading

| Goal | Start here |
|------|------------|
| Understand the protocol | `spec/v1/PROTOCOL.md` |
| See the engine in action | `pkg/consensus/engine.go` → `RunCycle()` |
| Add a new command | `cmd/provectl/main.go` |
| Embed in another project | `pkg/chain/segment.go` → `Anchorer` |
| Debug a consensus failure | `pkg/consensus/engine.go` → `RunCycle()` log output |
| Run a local network | `docker compose up -d` |

---

## Known limitations and roadmap

| Limitation | Impact | Issue | Status |
|------------|--------|-------|--------|
| Leader election is a deterministic hash race, not a true VRF | Predictable proposer, grinding attack surface | [#1](https://github.com/had-nu/gleipnir/issues/1) | Open |
| Kyber1024 KEM and ChaCha20-Poly1305 transport implemented but not wired into automatic peer discovery | Must manually configure peer keys | [#2](https://github.com/had-nu/gleipnir/issues/2) | Resolved |
| 3/3 quorum tolerates zero faults (n=3, f=0) | Single offline proposer stalls the cycle (mitigated by view-change skip) | [#3](https://github.com/had-nu/gleipnir/issues/3) | Open |
| Eigendecomposition O(n³) per λ₁ recomputation | Scales poorly above 100 peers (mitigated by LambdaInterval) | [#4](https://github.com/had-nu/gleipnir/issues/4) | Open |
| Sub-chain registry lacks automatic periodic anchoring | Manual `Anchor()` call required | — | Open |
| Transport test `TestEncryptedExchange` has intermittent EOF | Nonce or framing edge case under concurrent read/write | — | Investigate |

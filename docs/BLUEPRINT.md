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
│   ├── chain/             # Protocol types (Block, Entry, AnchorProof)
│   ├── consensus/         # Hash-based leader election, triad, quorum, Engine
│   ├── identity/          # uID0 soulbound, Dilithium3, Kyber1024
│   ├── smt/               # Sparse Merkle Tree (Blake3, depth 256)
│   ├── state/             # NetworkState, Laplacian supervision
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
                   └──→ pkg/state
```

**Rule**: code in `pkg/` never imports `cmd/` or `pkg/server/`. The core packages (`chain`, `consensus`, `identity`, `smt`, `state`) have zero gRPC or CLI dependencies.

---

## Architecture overview

Gleipnir is a self-contained, tokenless consensus network that anchors provenance hashes into an immutable chain. It replaces external dependencies like Ethereum with a minimal hash-based election protocol.

### Three-tier model

| Layer | Responsibility | Package |
|-------|---------------|---------|
| **Protocol types** | Block, ProvenanceEntry, AnchorProof, Anchorer interface | `pkg/chain/` |
| **Core engine** | Hash-based leader election, Dilithium3 signing, SMT state, cycles | `pkg/consensus/` |
| **Identity** | uID0 soulbound tokens, post-quantum keys | `pkg/identity/` |
| **State** | Network topology, Laplacian eigenvalues | `pkg/state/` |
| **SMT** | Blake3 Sparse Merkle Tree (depth 256) | `pkg/smt/` |
| **gRPC server** | Network API (optional — not needed for embedded use) | `pkg/server/` |

### Embedded vs sidecar

Gleipnir is designed to work in two modes:

- **Embedded**: `consensus.NewEngine(node, interval)` — runs inside your process. Import `github.com/had-nu/gleipnir/pkg/consensus`. No gRPC needed.
- **Sidecar**: `provenanced` daemon with gRPC API. Connect via `client.New()` for remote anchoring.

---

## Consensus cycle

One cycle = one anchored block. The ticker-driven loop:

```
1. TICK ─→ Lock state
              │
2.           Collect pending entries
              │
3.           Select proposer via hash
               min(sha256(peerUID || cycle || stateRoot))
              │
4.           Form triad (proposer + next 2 peers)
              │
5.           Build block:
               - Index, PrevHash, entries
               - Insert entries into SMT
               - Compute StateRoot
               - Compute BlockHash (SHA-256)
               - Sign with Dilithium3
              │
6.           Apply state transition:
               - Update Laplacian λ₁ from heartbeats
               - Increment cycle
              │
7.           Append block ─→ Unlock
```

Exported as `Engine.RunCycle()` for manual triggering. The ticker runs `RunCycle()` on `cycleInterval`.

### Cycle loop code path

```
Engine.Start()
  └→ cycleLoop()                     [engine.go:116]
       └→ RunCycle()                 [engine.go:130]
            ├→ SelectProposer()      [triad.go:11]
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

### `pkg/consensus/` — Engine and selection

- `Engine` — central state machine. Holds the SMT, block chain, pending queue, anchored map.
- `Node` — identity + address + peer list for a validator.
- `SelectProposer()` — hash-based: peer with lowest `sha256(peerUID || cycle || stateRoot)`.
- `SelectTriad()` — proposer + next two peers in sorted set.
- `VerifyQuorum()` — 3/3 Dilithium3 signature check.

### `pkg/identity/` — Post-quantum identity

- `UIDZeroSoulbound` — CBOR-serializable identity token. Contains RootID, Dilithium3 keypair, merkle proofs, entropy, and recovery info.
- `NewUIDZero(seed, simulated)` — create identity. The `simulated` flag generates deterministically for dev.
- `GenerateDilithiumKey(rng)` → (pk, sk) — ML-DSA-65 (Dilithium3).
- `SignDilithium(sk, msg)` → sig.
- `VerifyDilithium(pk, msg, sig)` → bool.
- `Hash(data)` → blake3.Sum256.

### `pkg/smt/` — Sparse Merkle Tree

- `SparseMerkleTree` — depth 256, Blake3.
- `New(depth)` → default tree.
- `Insert(key, value)` → update leaf.
- `Get(key)` → value.
- `Prove(key)` → merkle proof (sibling hashes).
- `Verify(root, key, value, proof)` → bool.
- `BulkInsert(keys, values)` → batch insert.

Internal storage uses two maps: `data map[[32]byte][]byte` for leaves and `cache map[[32]byte][32]byte` for computed nodes.

### `pkg/state/` — Network state and supervision

- `NetworkState` — cycle counter, NodeState map, ReputationGraph, StateRoot, Lambda1.
- `NodeState` — heartbeat, latency, status.
- `ReputationGraph` — adjacency matrix (dense `mat.SymDense`).
- `Apply(state, prevRoot, heartbeats, cfg)` → compute next state, Laplacian λ₁.
- `ComputeLambda1(matrix)` → smallest eigenvalue of the Laplacian.
- `BuildLaplacian(graph)` → graph Laplacian matrix from adjacency.
- `ComputeStateRoot(heartbeats, lambda1)` → CBOR → Blake3 root.

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

Import and use without gRPC:

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
| Kyber1024 not yet used for its intended purpose (KEM) | No encrypted peer channels | [#2](https://github.com/had-nu/gleipnir/issues/2) | Open |
| 3/3 quorum tolerates zero faults (n=3, f=0) | Single offline proposer stalls the cycle (mitigated by view-change skip) | [#3](https://github.com/had-nu/gleipnir/issues/3) | Open |
| Eigendecomposition O(n³) per λ₁ recomputation | Scales poorly above 100 peers (mitigated by LambdaInterval) | [#4](https://github.com/had-nu/gleipnir/issues/4) | Open |

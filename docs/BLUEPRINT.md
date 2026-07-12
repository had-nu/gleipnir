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
│   ├── consensus/         # ECVRF leader election, triad, M-of-N quorum, Engine, SubChainManager
│   ├── identity/          # uID0 soulbound, Dilithium3, Kyber1024, ECVRF (Ristretto255), contract-derived UID0
│   ├── smt/               # Sparse Merkle Tree (Blake3, depth configurable)
│   ├── state/             # NetworkState, Laplacian supervision, power iteration for λ₁
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
| **Core engine** | ECVRF leader election (Ristretto255, RFC 9381), Dilithium3 signing, SMT state, cycles, M-of-N quorum | `pkg/consensus/` |
| **Identity** | uID0 soulbound tokens, Dilithium3, Kyber1024 KEM, ECVRF (Ristretto255) | `pkg/identity/` |
| **State** | Network topology, Laplacian eigenvalues (power iteration with EigenSym fallback) | `pkg/state/` |
| **SMT** | Blake3 Sparse Merkle Tree (depth 256) | `pkg/smt/` |
| **Transport** | KEM handshake + AEAD secure channel | `pkg/transport/` |
| **gRPC server** | Network API (optional — not needed for embedded use) | `pkg/server/` |

### Embedded vs sidecar

Gleipnir is designed to work in two modes:

- **Embedded**: `consensus.NewEngine(node, interval)` — runs inside your process. Import `github.com/had-nu/gleipnir/pkg/consensus`. No gRPC needed.
- **Sidecar**: `provenanced` daemon with gRPC API. Connect via `client.New()` for remote anchoring.

### Current status: F1–F6 + G1–G6 + I1–I4 complete

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
| **I1** | ECVRF leader election (Ristretto255, RFC 9381) — `pkg/identity/vrf.go` + wired in `triad.go` | ✅ |
| **I2** | Kyber1024 KEM — `pkg/identity/kyber.go` used in `pkg/transport/secure_conn.go` | ✅ |
| **I3** | M-of-N BFT quorum — `pkg/consensus/quorum.go` with duplicate-signature defense, flexible `Sigs`/`Validators` | ✅ |
| **I4** | Power iteration for λ₁ — `pkg/state/power_iter.go` (Cholesky shift-invert, EigenSym fallback) | ✅ |

What you get today:
- **Multi-node consensus**: N-node gossip-based cycle with ECVRF proposer selection, verified SMT root replication, M-of-N quorum
- **ECVRF leader election**: Ristretto255-based VRF per RFC 9381 — each peer proves proposer selection with a verifiable, unpredictable cryptographic proof; grinding-resistant
- **M-of-N BFT quorum**: configurable threshold (1/1 single-node, 3/3 or higher multi-node); duplicate-signature attack rejected (each distinct signer counted once)
- **Kyber1024 KEM**: key encapsulation for encrypted peer channels
- **ChaCha20-Poly1305 secure transport**: AEAD-encrypted messages with random nonces, keyed via HKDF(Kyber1024 shared secret, sorted peer IDs)
- **Sub-chain registry**: per-service SMT + anchor lifecycle via `SubChainManager` (`Register`, `Submit`, `Anchor`, `Prove`, `VerifyCrossChain`)
- **Hardened submission API**: `Enqueue` validates entries (rejects zero hashes, empty submitters, oversized labels) and enforces rate limits (total pending + per-submitter caps); `RunCycle` recovers from panics; `Engine.Stop` halts intake cleanly
- **Contract-derived UID0**: `NewUIDZeroFromContract(contractHash, nodeSalt, simulated)` derives a deterministic, reproducible UID0 root identity bound to a company's contract hash (DRBG-seeded Dilithium3 key), enabling verifiable "this node speaks for contract X" proofs
- **Peer discovery & real transport**: `pkg/transport/p2p` libp2p GossipSub implementation of `GossipChannel` with mDNS discovery and bootstrap peers
- **Persistence**: BoltDB-backed `EngineStorage` interface; `SetStorage()` loads state on init, auto-persists on `Stop()` and after each `RunCycle()`
- **Client validation**: `pkg/validation` exports `ValidateEntry`, `IsZeroHash`, and machine-readable error codes (`ValidationError` with `Code` field) for programmatic handling
- **Bounded rate limiting**: sliding-window per-submitter limiter with LRU eviction (max 10k tracked submitters); no unbounded map growth
- **Power iteration for λ₁**: optional shift-invert power iteration on the Laplacian with Cholesky factorization; falls back to dense EigenSym when convergence fails or n < 20

---

## Consensus cycle

One cycle = one anchored block. The ticker-driven loop:

```
1. TICK ─→ Lock state
               │
2.           Compute local VRF proof:
                sk.Prove(cycle || stateRoot) → (Gamma, c, s)
                Publish proof via gossip
                Collect all peers' VRF proofs
                Verify each proof against peer's VRF public key
                Select proposer = min(Gamma)
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
4.           Collect co-signatures (M-of-N quorum)
               │
5.           Apply state transition:
                - Update Laplacian λ₁ from heartbeats (power iteration or EigenSym)
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

- `Engine` — central state machine. Holds the SMT, block chain, pending queue, anchored map, rate limiter, quorum config.
- `Node` — identity + address + peer list for a validator.
- `Peer` — remote node identity + address + liveness flag.
- `SelectProposer()` — ECVRF-based: each peer computes `sk.Prove(cycle||stateRoot)`, proofs are verified against each peer's VRF public key, proposer with lowest Gamma wins.
- `SelectTriad()` — proposer + next two peers in sorted set.
- `VerifyQuorum()` — M-of-N Dilithium3 signature check. Each distinct signer counted only once (prevents duplicate-signature attacks). Passes `pubKeys` from `block.Validators`.
- `GossipChannel` — interface for inter-node communication (`Publish`, `Snapshot`, `Propose`, `GetProposed`, `PublishSig`, `GetSigs`, `RemoveEntries`, `PublishVRFProof`, `GetVRFProofs`).
- `MemoryBus` — in-memory implementation of `GossipChannel`, used for single-process multi-node tests.
- `SubmitterLimiter` — sliding-window per-submitter rate limiter with LRU eviction (max 10k tracked submitters).
- `SubChainManager` — sub-chain lifecycle: `Register(name, owner)`, `Submit(id, entry)`, `Anchor(id)`, `Prove(id, entryHash)`, `VerifyCrossChain(proof, parentRoot)`. Each sub-chain has its own SMT; anchoring flushes pending entries, computes the state root, and enqueues a `ProvenanceEntry` with `Label: "subchain:anchor"` into the parent chain.

### `pkg/identity/` — Post-quantum identity + KEM + VRF

- `UIDZeroSoulbound` — CBOR-serializable identity token. Contains RootID, Dilithium3 keypair, ECVRF keypair (Ristretto255), merkle proofs, entropy, recovery info, and contract hash.
- `NewUIDZero(seed, simulated)` — creates identity with both Dilithium3 and VRF keypairs. `simulated` flag for deterministic dev mode.
- `GenerateDilithiumKey(rng)` → (pk, sk) — ML-DSA-65 (Dilithium3).
- `SignDilithium(sk, msg)` → sig.
- `VerifyDilithium(pk, msg, sig)` → bool.
- `KyberGenerateKey()` → (pk, sk) — Kyber1024 KEM keypair.
- `KyberEncapsulate(pk)` → (ct, ss) — generate ciphertext + shared secret.
- `KyberDecapsulate(sk, ct)` → ss — recover shared secret.
- `GenerateVRFKeyPair()` → (sk, pk) — Ristretto255 ECVRF keypair (RFC 9381).
- `VRFPrivateKey.Prove(alpha)` → `VRFProof{Gamma, C, S}` — Schnorr proof that Gamma = sk·HashToCurve(alpha).
- `VRFPublicKey.Verify(alpha, proof)` → (gamma, error) — verifies proof, returns VRF output.
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
- `BuildLaplacian(graph, nodes)` → graph Laplacian matrix from reputation graph.
- `ComputeLambda1(matrix)` → Fiedler eigenvalue (second-smallest) via shift-invert power iteration on `(L + μI)⁻¹`, with Cholesky factorization. Falls back to dense `EigenSym` for n < 20 or convergence failure.
- `ComputeLambda1WithOptions(matrix, opts)` — configurable max-iter, tolerance, shift; `Verbose` flag for iteration logging.
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
    PublishVRFProof(proof VRFProofMsg)
    GetVRFProofs(cycle uint64) []VRFProofMsg
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
    Index:     uint64              ← sequential block number
    PrevHash:  []byte              ← sha256 of previous block
    Proposer:  []byte              ← RootID of selected proposer
    Anchored:  []ProvenanceEntry   ← entries anchored in this block
    StateRoot: []byte              ← SMT root after insertion
    Lambda1:   float64             ← Laplacian eigenvalue at block time
    Timestamp: int64               ← unix nanos
    Sigs:      [][]byte            ← Dilithium3 signatures (flexible M-of-N)
    Validators: [][]byte           ← validator public keys for this block
    Quorum:    QuorumConfig        ← {TotalValidators, RequiredSigs}
    BlockHash: []byte              ← sha256 of all above (minus BlockHash)
}
```

### Identity serialization (CBOR)

`UIDZeroSoulbound` serializes deterministically via `fxamacker/cbor/v2`. Fields are keyed by integers for canonical ordering:

```
 0: RootID         1: FEntropy         2: GenesisHash
 3: MerkleProofs   4: SigRecovery      5: SigUpdate
 6: SigAudit       7: ReputationSum    8: SiderealTime
 9: CycleIndex    10: GeneratedAt     11: MerkleRoot
12: MerkleProof   13: Simulated       14: FinalDigest
15: PublicKey     16: SecretKey
17: ContractHash  18: VRFPublicKey     19: VRFSecretKey (omitempty, never exported)
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
| `cloudflare/circl` | Dilithium3, Kyber1024, expander |
| `bwesterb/go-ristretto` | Ristretto255 ECVRF (RFC 9381) |
| `fxamacker/cbor/v2` | Deterministic CBOR | 
| `gonum.org/v1/gonum` | `mat.SymDense` eigendecomposition, Cholesky |
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

### Verification checklist

See [VERIFICATION.md](../VERIFICATION.md) for the mechanical gate applied to
every issue-closure claim — commit range, file existence, CI output, and
adversarial test coverage must all be confirmed before marking an issue done.

### Where to start reading

| Goal | Start here |
|------|------------|
| Understand the protocol | `docs/ARCHITECTURE.md` |
| See the engine in action | `pkg/consensus/engine.go` → `RunCycle()` |
| Add a new command | `cmd/provectl/main.go` |
| Embed in another project | `pkg/chain/segment.go` → `Anchorer` |
| Debug a consensus failure | `pkg/consensus/engine.go` → `RunCycle()` log output |
| Run a local network | `docker compose up -d` |

---

## Known limitations and roadmap

| Limitation | Impact | Issue | Status |
|------------|--------|-------|--------|
| ECVRF leader election implemented (Ristretto255, RFC 9381) | Grinding-resistant proposer selection | [#1](https://github.com/had-nu/gleipnir/issues/1) | ✅ Resolved |
| Kyber1024 KEM and ChaCha20-Poly1305 transport implemented but not wired into automatic peer discovery | Must manually configure peer keys | [#2](https://github.com/had-nu/gleipnir/issues/2) | Resolved |
| M-of-N BFT quorum implemented (flexible threshold, duplicate-signature defense) | Configurable fault tolerance | [#3](https://github.com/had-nu/gleipnir/issues/3) | ✅ Resolved |
| Eigendecomposition O(n³) per λ₁ recomputation mitigated by power iteration + LambdaInterval | Scales to 100+ peers | [#4](https://github.com/had-nu/gleipnir/issues/4) | ✅ Mitigated |
| Sub-chain registry lacks automatic periodic anchoring | Manual `Anchor()` call required | — | Open |
| Transport test `TestEncryptedExchange` has intermittent EOF | Nonce or framing edge case under concurrent read/write | — | Investigate |

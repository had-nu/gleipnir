# Gleipnir v2.0 — Especificação de Arquitetura Completa
**Protocolo Base:** 3CP v2.0 (SPEC-3CP-V2.md)
**Linguagem:** Go 1.22+
**Licença:** AGPL-3.0
**Status:** ARQUITETURA DE REFERÊNCIA

---

## 1. Visão Geral e Filosofia Arquitetural

O Gleipnir é a implementação de referência do protocolo 3CP. Ele não define o protocolo — ele o materializa. A arquitetura v2.0 evolui da v1.0 em três dimensões:

1. **Segurança:** Consenso BFT explícito (2 fases) em vez de quórum implícito
2. **Operabilidade:** Ciclo adaptativo, rotação de chaves nativa, publicação de âncoras
3. **Verificabilidade:** Light client protocol, ZKBridge versionado, testes adversariais

### 1.1 Princípios de Design

| Princípio | Aplicação |
|-----------|-----------|
| **Separação de camadas** | Protocolo (3CP) → Nó (Gleipnir) → Auditor (CARCOSA) são independentes |
| **Determinismo** | Mesmas entradas + mesmo estado inicial = mesma saída (essencial para consenso) |
| **Fail-closed** | Em dúvida, aborte o ciclo. Nunca appende bloco sem quórum verificado |
| **Observabilidade** | Todo estado interno deve ser exportável para diagnóstico |
| **Sem dependências cíclicas** | `pkg/consensus` não importa `pkg/server`; `pkg/server` não importa `pkg/publisher` |

---

## 2. Diagrama de Arquitetura de Alto Nível

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                           GLEIPNIR NODE v2.0                                │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                             │
│  ┌──────────────┐    ┌──────────────┐    ┌──────────────┐                   │
│  │   gRPC API   │    │   gRPC API   │    │   HTTP API   │                   │
│  │  (Provenance)│    │ (ZKBridge)   │    │ (Metrics)    │                   │
│  └──────┬───────┘    └──────┬───────┘    └──────┬───────┘                   │
│         │                   │                   │                           │
│  ┌──────▼───────────────────▼───────────────────▼───────┐                  │
│  │                    pkg/server                        │                  │
│  │  - SubmitHash / GetBlock / StreamBlocks             │                  │
│  │  - ZKBridge.GetBlockRange / GetMerkleProof          │                  │
│  │  - Prometheus metrics                               │                  │
│  └────────────────────────┬─────────────────────────────┘                  │
│                           │                                                 │
│  ┌────────────────────────▼─────────────────────────────┐                    │
│  │                   pkg/consensus                      │                    │
│  │  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐ │                    │
│  │  │   Engine    │  │   Quorum    │  │   VRF       │ │                    │
│  │  │  (2-phase)  │  │  (BFT)      │  │  (ECVRF)    │ │                    │
│  │  └─────────────┘  └─────────────┘  └─────────────┘ │                    │
│  │  ┌─────────────┐  ┌─────────────┐                   │                    │
│  │  │   Gossip    │  │  Degraded   │                   │                    │
│  │  │  (MemoryBus)│  │   Mode      │                   │                    │
│  │  └─────────────┘  └─────────────┘                   │                    │
│  └────────────────────────┬─────────────────────────────┘                    │
│                           │                                                 │
│  ┌────────────────────────▼─────────────────────────────┐                    │
│  │                    pkg/chain                         │                    │
│  │  - Block v2.0 (CBOR)                               │                    │
│  │  - ProvenanceEntry / KeyRotationEntry              │                    │
│  │  - GenesisBlock / GenesisValidatorSet              │                    │
│  └────────────────────────┬─────────────────────────────┘                    │
│                           │                                                 │
│  ┌────────────────────────▼─────────────────────────────┐                    │
│  │                    pkg/state                         │                    │
│  │  - NetworkState (ValidatorSet + NodeState)           │                    │
│  │  - IncrementalLaplacian (λ₁)                       │                    │
│  │  - State transition (apply block)                    │                    │
│  └────────────────────────┬─────────────────────────────┘                    │
│                           │                                                 │
│  ┌────────────────────────▼─────────────────────────────┐                    │
│  │                     pkg/smt                          │                    │
│  │  - Sparse Merkle Tree (depth 256, BLAKE3)          │                    │
│  │  - Insert / Prove / Verify                         │                    │
│  └────────────────────────┬─────────────────────────────┘                    │
│                           │                                                 │
│  ┌────────────────────────▼─────────────────────────────┐                    │
│  │                   pkg/identity                       │                    │
│  │  - UID0 v2 (HKDF + NetworkID)                      │                    │
│  │  - Dilithium3 (sign / verify / batch)              │                    │
│  │  - VRF (prove / verify)                            │                    │
│  │  - Kyber (KEM handshake)                           │                    │
│  └────────────────────────┬─────────────────────────────┘                    │
│                           │                                                 │
│  ┌────────────────────────▼─────────────────────────────┐                    │
│  │                  pkg/publisher                       │                    │
│  │  - FilePublisher / IPFSPublisher / S3Publisher       │                    │
│  │  - AnchorPublisherConfig                           │                    │
│  └────────────────────────┬─────────────────────────────┘                    │
│                           │                                                 │
│  ┌────────────────────────▼─────────────────────────────┐                    │
│  │                  pkg/transport                       │                    │
│  │  - Kyber handshake + ChaCha20-Poly1305             │                    │
│  │  - SecureConn between peers                        │                    │
│  └────────────────────────┬─────────────────────────────┘                    │
│                           │                                                 │
│  ┌────────────────────────▼─────────────────────────────┐                    │
│  │               pkg/storage (interface)                │                    │
│  │  - EngineStorage (blocks, state, SMT, pending)       │                    │
│  │  - FileSystemStorage / MemoryStorage                │                    │
│  └──────────────────────────────────────────────────────┘                    │
│                                                                             │
└─────────────────────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│                         EXTERNAL SYSTEMS                                    │
│  ┌──────────┐  ┌──────────┐  ┌──────────┐  ┌──────────────────────────────┐  │
│  │  IPFS    │  │   S3     │  │  Auditor │  │     CARCOSA (ZK Bridge)      │  │
│  │  Node    │  │  Bucket  │  │  Client  │  │     (Rust, separate repo)    │  │
│  └──────────┘  └──────────┘  └──────────┘  └──────────────────────────────┘  │
└─────────────────────────────────────────────────────────────────────────────┘
```

---

## 3. Modelo de Dados Detalhado

### 3.1 Grafo de Relacionamentos entre Tipos

```
GenesisBlock
    ├── GenesisValidatorSet [*ValidatorInfo]
    │       ├── ValidatorID [16]byte
    │       ├── Dilithium3PK [1952]byte
    │       └── VRFPK [32]byte
    ├── GenesisMandate (ProvenanceEntry)
    └── NetworkID = BLAKE3(GenesisBlock)

        │
        ▼ (produz)

Block (ciclo N)
    ├── Index uint64
    ├── PrevHash ← Block[N-1].BlockHash
    ├── StateRoot ← SMT.Root() after inserting Anchored
    ├── Proposer ← SelectProposer(VRF proofs)
    ├── Anchored [*ProvenanceEntry]
    │       ├── Hash [32]byte
    │       ├── Submitter [16]byte
    │       ├── Timestamp int64
    │       ├── Label string
    │       ├── Approver ?[16]byte
    │       ├── Reference ?[32]byte
    │       ├── Signature ?[2700]byte
    │       └── MandateRef ?[32]byte
    ├── Lambda1 float64
    ├── Timestamp int64
    ├── Validators [*Dilithium3PK]
    ├── Sigs [*Dilithium3Sig] (PREPARE signatures)
    ├── Quorum {TotalValidators, RequiredSigs}
    ├── BlockHash [32]byte (SHA-256)
    ├── ProtocolVersion uint16 = 2
    ├── PrepareSigsBitmap []byte (bitfield)
    ├── PrepareSigs [*Dilithium3Sig] (active only)
    ├── CommitSig [2700]byte (leader's commit)
    ├── ExternalAnchors []string (URIs/CIDs)
    └── KeyRotationEpoch uint64

        │
        ▼ (transita)

NetworkState
    ├── Nodes [*NodeState]
    │       ├── UID [16]byte
    │       ├── Status float64
    │       ├── Consecutive uint64
    │       ├── Dilithium3PK [1952]byte
    │       └── VRFPK [32]byte
    ├── Lambda1 float64
    ├── Cycle uint64
    ├── ActiveMandates [*MandateEntry]
    ├── SupervisionRoot [32]byte
    └── ValidatorSet [*ValidatorInfo]

        │
        ▼ (publica)

AnchorProof
    ├── Found bool
    ├── BlockIndex uint64
    ├── BlockTime int64
    ├── StateRoot [32]byte
    ├── SMTProof [8192]byte
    ├── Submitter [16]byte
    └── Label string
```

### 3.2 Diagrama de Estados do Consenso (Máquina de Estados)

```
                    ┌─────────────────┐
                    │   CYCLE_START   │
                    │  (ticker fires  │
                    │   or manual)    │
                    └────────┬────────┘
                             │
              ┌──────────────┼──────────────┐
              │              │              │
              ▼              ▼              ▼
    ┌─────────────────┐ ┌──────────┐ ┌──────────────┐
    │  PREPARING      │ │ CYCLE_   │ │  (empty &    │
    │  (VRF election  │ │ ABORTED  │ │ SkipEmpty)   │
    │   + proposal +   │ │ (timeout │ │              │
    │   PREPARE sigs)  │ │  / no    │ │  CYCLE_SKIP  │
    └────────┬────────┘ │  quorum) │ └──────────────┘
             │          └────┬─────┘
             │               │
        ┌────┴────┐          │ entries retained
        │         │          │ in pending queue
   [Q >=          │          │
  ceil(2N/3)]     │          │
        │         │          │
        ▼         │          │
   ┌─────────┐    │          │
   │ PREPARED│◄───┘          │
   │(leader   │               │
   │ collects │               │
   │ quorum)  │               │
   └────┬────┘               │
        │                    │
        ▼                    │
   ┌───────────┐             │
   │ COMMITTING │             │
   │ (B_final   │             │
   │  broadcast │             │
   │  + COMMIT  │             │
   │  sigs)     │             │
   └─────┬─────┘             │
         │                    │
    ┌────┴────┐               │
    │         │               │
[Q COMMIT    │               │
 verified]    │               │
    │         │               │
    ▼         │               │
┌────────┐    │               │
│COMMITTED│   │               │
│(append  │   │               │
│ block,  │   │               │
│ transition│  │               │
│ state)  │   │               │
└────┬────┘   │               │
     │        │               │
     ▼        │               │
┌────────┐    │               │
│CYCLE_  │    │               │
│END     │────┘               │
└────────┘                    │
                              │
                              ▼
                        ┌──────────┐
                        │ next     │
                        │ CYCLE_   │
                        │ START    │
                        └──────────┘
```

### 3.3 Fluxo de Dados do Ciclo de Consenso

```
┌─────────────┐     ┌─────────────┐     ┌─────────────┐     ┌─────────────┐
│   ENTRADAS  │────▶│   ENGINE    │────▶│   GOSSIP    │────▶│   PEERS     │
│  (SubmitHash)│     │  (RunCycle) │     │  (MemoryBus)│     │             │
└─────────────┘     └──────┬──────┘     └─────────────┘     └──────┬──────┘
                           │                                        │
                           │                                        │
                           ▼                                        ▼
                    ┌─────────────┐                         ┌─────────────┐
                    │   STATE     │                         │   STATE     │
                    │  (Network   │◄────────────────────────│  (Network   │
                    │   State +   │     (gossip sync)       │   State +   │
                    │   SMT)      │                         │   SMT)      │
                    └──────┬──────┘                         └─────────────┘
                           │
                           ▼
                    ┌─────────────┐
                    │   BLOCK     │
                    │  (if final) │
                    └──────┬──────┘
                           │
              ┌────────────┼────────────┐
              │            │            │
              ▼            ▼            ▼
        ┌─────────┐  ┌─────────┐  ┌─────────┐
        │ Storage │  │Publisher│  │  gRPC   │
        │ (persist)│  │(IPFS/S3)│  │ (serve) │
        └─────────┘  └─────────┘  └─────────┘
```

---

## 4. Especificação de Interfaces entre Pacotes

### 4.1 `pkg/consensus` — Interface Pública

```go
// Engine é o núcleo do consenso. Apenas RunCycle() é público.
type Engine struct {
    // unexported fields
}

// RunCycle executa um ciclo completo de consenso (PREPARE + COMMIT).
// É a ÚNICA API pública de consenso. Não expõe fases internas.
func (e *Engine) RunCycle() error

// GetBlock retorna o bloco no índice especificado.
func (e *Engine) GetBlock(index uint64) (*chain.Block, error)

// GetPendingCount retorna o número de entradas na fila de pendentes.
func (e *Engine) GetPendingCount() int

// Enqueue adiciona uma entrada à fila de pendentes.
// A entrada deve ser validada antes (assinatura do submitter verificada).
func (e *Engine) Enqueue(entry chain.ProvenanceEntry) error

// StateRoot retorna a raiz SMT atual.
func (e *Engine) StateRoot() [32]byte

// ValidatorSet retorna o conjunto de validadores ativo.
func (e *Engine) ValidatorSet() []state.ValidatorInfo
```

**Invariantes do Engine:**
- Nunca appenda bloco sem quórum COMMIT verificado.
- Nunca descarte entradas pendentes em aborto de ciclo.
- Sempre use `StateRoot` do início do ciclo para computar `alpha` VRF.
- Sempre verifique VRF proof contra `VRFPK` do `NetworkState`, nunca local.

### 4.2 `pkg/state` — Interface Pública

```go
// NetworkState mantém o estado completo da rede.
type NetworkState struct {
    Nodes           map[string]NodeState   // key: hex(UID)
    Lambda1         float64
    Cycle           uint64
    ActiveMandates  []chain.MandateEntry
    SupervisionRoot [32]byte
    ValidatorSet    []ValidatorInfo         // ordenação canônica
}

type NodeState struct {
    UID          [16]byte
    Status       float64
    Consecutive  uint64
    Dilithium3PK [1952]byte
    VRFPK        [32]byte
}

type ValidatorInfo struct {
    ValidatorID  [16]byte
    Dilithium3PK [1952]byte
    VRFPK        [32]byte
    ContractHash [32]byte
}

// IncrementalLaplacian computa λ₁ de forma eficiente.
type IncrementalLaplacian struct {
    // implementation details
}

func (il *IncrementalLaplacian) Compute(state NetworkState) (float64, error)
func (il *IncrementalLaplacian) MarkDirty()
```

### 4.3 `pkg/identity` — Interface Pública

```go
// UIDZeroSoulbound representa uma identidade no protocolo 3CP.
type UIDZeroSoulbound struct {
    RootID         [16]byte
    PublicKey      [1952]byte   // Dilithium3
    SecretKey      []byte        // MUST NOT be transmitted
    VRFPublicKey   [32]byte
    VRFSecretKey   []byte        // MUST NOT be transmitted
    ContractHash   [32]byte
    FinalDigest    [32]byte
}

// NewUIDZero cria uma identidade v2.0 usando HKDF com NetworkID.
func NewUIDZero(entropySource string, networkID [32]byte, simulated bool) (*UIDZeroSoulbound, error)

// VRFProve gera uma prova ECVRF para o alpha dado.
func (uid *UIDZeroSoulbound) VRFProve(alpha []byte) ([]byte, error)

// VRFVerify verifica uma prova ECVRF.
func VRFVerify(publicKey [32]byte, alpha []byte, proof []byte) ([32]byte, error)

// Sign assina uma mensagem com Dilithium3.
func (uid *UIDZeroSoulbound) Sign(message []byte) ([]byte, error)

// VerifyBatch verifica múltiplas assinaturas em batch.
func VerifyBatch(messages [][]byte, signatures [][]byte, publicKeys [][]byte) ([]bool, error)
```

### 4.4 `pkg/publisher` — Interface Pública

```go
// Publisher publica blocos em storage externo.
type Publisher interface {
    Publish(ctx context.Context, blockData []byte) (location string, error)
    Scheme() string
}

// AnchorPublisherConfig define quem publica e com que redundância.
type AnchorPublisherConfig struct {
    Mode               string   // "all", "designated", "external"
    DesignatedPublishers [][16]byte // ValidatorIDs (modo "designated")
    MinRedundancy      uint
}
```

### 4.5 `pkg/storage` — Interface (existente, a manter)

```go
type EngineStorage interface {
    SaveBlock(block *chain.Block) error
    GetBlock(index uint64) (*chain.Block, error)
    SaveState(state *state.NetworkState) error
    GetState() (*state.NetworkState, error)
    SaveSMT(root []byte, tree *smt.SparseMerkleTree) error
    GetSMT(root []byte) (*smt.SparseMerkleTree, error)
    SavePending(entries []chain.ProvenanceEntry) error
    GetPending() ([]chain.ProvenanceEntry, error)
    SaveAnchorProof(proof *chain.AnchorProof) error
    GetAnchorProof(hash []byte) (*chain.AnchorProof, error)
}
```

---

## 5. Diagrama de Sequência: Ciclo de Consenso Bem-Sucedido

```
Peer A (Leader)          Peer B               Peer C              MemoryBus
    │                       │                    │                   │
    │─── RunCycle() ───────▶│                    │                   │
    │  ┌─────────────────┐  │                    │                   │
    │  │ VRFProve(alpha) │  │                    │                   │
    │  └─────────────────┘  │                    │                   │
    │─── Publish VRFProof ──▶│────────────────────▶───────────────────▶│
    │                       │                    │                   │
    │◀── VRFProof B ◀──────│                    │                   │
    │◀── VRFProof C ◀─────────────────────────────│                   │
    │                       │                    │                   │
    │  ┌─────────────────┐  │                    │                   │
    │  │ SelectProposer  │  │                    │                   │
    │  │ (min Gamma)     │  │                    │                   │
    │  └─────────────────┘  │                    │                   │
    │  → A is leader      │                    │                   │
    │                       │                    │                   │
    │─── Propose Block ─────▶│────────────────────▶───────────────────▶│
    │                       │                    │                   │
    │                       │─── Verify Block ───▶│                   │
    │                       │◀── Verify Block ────│                   │
    │                       │                    │                   │
    │◀── PREPARE-SIG B ◀────│                    │                   │
    │◀── PREPARE-SIG C ◀──────────────────────────│                   │
    │                       │                    │                   │
    │  ┌─────────────────┐  │                    │                   │
    │  │ Quorum reached? │  │                    │                   │
    │  │ (Q >= ceil(2N/3))│  │                    │                   │
    │  └─────────────────┘  │                    │                   │
    │  → Yes               │                    │                   │
    │                       │                    │                   │
    │─── B_final + COMMIT ──▶│────────────────────▶───────────────────▶│
    │                       │                    │                   │
    │                       │─── Verify Quorum ──▶│                   │
    │                       │◀── Verify Quorum ──│                   │
    │                       │                    │                   │
    │                       │─── Append Block ───▶│                   │
    │                       │◀── Append Block ────│                   │
    │                       │                    │                   │
    │  ┌─────────────────┐  │                    │                   │
    │  │ Append Block    │  │                    │                   │
    │  │ Transition State│  │                    │                   │
    │  └─────────────────┘  │                    │                   │
    │                       │                    │                   │
    │─── Publish to ────────▶│────────────────────▶───────────────────▶│
    │    Anchor Publishers  │                    │                   │
    │                       │                    │                   │
```

---

## 6. Diagrama de Sequência: Ciclo Abortado (Timeout)

```
Peer A (Leader)          Peer B               Peer C              MemoryBus
    │                       │                    │                   │
    │─── RunCycle() ───────▶│                    │                   │
    │─── Publish VRFProof ──▶│────────────────────▶───────────────────▶│
    │                       │                    │                   │
    │◀── VRFProof B ◀───────│                    │                   │
    │  (C is silent)        │                    │                   │
    │                       │                    │                   │
    │─── Propose Block ─────▶│────────────────────▶───────────────────▶│
    │                       │                    │                   │
    │◀── PREPARE-SIG B ◀────│                    │                   │
    │  (C does not respond) │                    │                   │
    │                       │                    │                   │
    │  ┌─────────────────┐  │                    │                   │
    │  │ Quorum reached? │  │                    │                   │
    │  │ (1 of 3 < ceil(2*3/3)=2)              │                   │
    │  └─────────────────┘  │                    │                   │
    │  → NO                │                    │                   │
    │                       │                    │                   │
    │  ┌─────────────────┐  │                    │                   │
    │  │ CycleTimeout    │  │                    │                   │
    │  │ expires         │  │                    │                   │
    │  └─────────────────┘  │                    │                   │
    │                       │                    │                   │
    │  CYCLE_ABORTED        │                    │                   │
    │  (entries retained)   │                    │                   │
    │                       │                    │                   │
    │─── (no block appended)│                   │                   │
    │                       │                    │                   │
```

---

## 7. Especificação do Formato de Mensagens Gossip

As mensagens trocadas entre nós via `MemoryBus` (ou transporte real em produção):

```
Message (CBOR canonical)
    ├── Type: uint8
    │       0x01 = VRFProofMsg
    │       0x02 = PrepareSigMsg
    │       0x03 = CommitSigMsg
    │       0x04 = BlockProposalMsg
    │       0x05 = BlockFinalMsg
    │
    ├── Sender: [16]byte (ValidatorID)
    ├── Cycle: uint64
    └── Payload: bytes

VRFProofMsg Payload:
    ├── Alpha: [32]byte (output of VRF_ProofToHash)
    ├── Proof: [96]byte (ECVRF proof)
    └── Gamma: [32]byte (VRF output)

PrepareSigMsg Payload:
    ├── BlockHash: [32]byte
    └── Signature: [2700]byte (Dilithium3)

CommitSigMsg Payload:
    ├── BlockHash: [32]byte
    └── Signature: [2700]byte (Dilithium3)

BlockProposalMsg Payload:
    └── Block: chain.Block (CBOR serialized, v2.0 format)

BlockFinalMsg Payload:
    └── Block: chain.Block (with PrepareSigs, CommitSig)
```

---

## 8. Blueprint do Sistema de Testes

### 8.1 Hierarquia de Testes

```
tests/
├── unit/                          # Testes de pacote isolado
│   ├── pkg/identity/              # Dilithium3, VRF, UID0 derivation
│   ├── pkg/smt/                   # SMT insert, prove, verify
│   ├── pkg/state/                 # Laplacian, state transition
│   └── pkg/chain/                 # Block serialization, CBOR
│
├── integration/                   # Testes multi-pacote
│   ├── consensus_single_node/     # 1 validator, smoke tests
│   ├── consensus_three_node/      # 3 validators, happy path
│   └── consensus_seven_node/      # 7 validators, BFT scenarios
│
├── adversarial/                   # Testes BFT (pkg/testnet)
│   ├── byzantine_double_propose/
│   ├── byzantine_invalid_vrf/
│   ├── byzantine_withhold_sig/
│   ├── network_partition/
│   └── sybil_submission/
│
├── conformance/                   # Suite v2.0 (cmd/conformance-test)
│   ├── TC-BFT-01..04/
│   ├── TC-NET-01..02/
│   ├── TC-ROT-01..02/
│   ├── TC-ZK-01/
│   ├── TC-PUB-01/
│   ├── TC-SCA-01/
│   └── TC-MEM-01/
│
└── benchmark/                     # Performance
    ├── smt_benchmark/
    ├── dilithium_batch_benchmark/
    └── laplacian_benchmark/
```

### 8.2 Harness de Teste Adversarial (`pkg/testnet`)

```
TestNetwork
    ├── SimulatedClock
    │       └── Now() → deterministic time
    │
    ├── SimulatedTransport
    │       ├── LatencyMatrix[peer][peer] → duration
    │       ├── Partitions → []Partition
    │       └── DropRate → float64
    │
    ├── Nodes[]
    │       ├── Engine
    │       ├── Behavior (HONEST / BYZANTINE_*)
    │       └── InjectedFaults
    │
    └── Orchestrator
            ├── RunCycles(count)
            ├── InjectPartition(Partition)
            ├── HealPartition()
            ├── InjectByzantine(nodeID, behavior)
            └── AssertConvergence()
```

**Comportamentos Bizantinos Implementáveis:**

| Comportamento | Efeito |
|---------------|--------|
| `HONEST` | Segue o protocolo corretamente |
| `BYZANTINE_SILENT` | Não envia mensagens |
| `BYZANTINE_LIAR` | Envia VRF proofs válidos mas propostas inconsistentes |
| `BYZANTINE_DOUBLE_PROPOSE` | Propõe dois blocos distintos no mesmo ciclo |
| `BYZANTINE_INVALID_SIG` | Envia assinaturas que não verificam |
| `BYZANTINE_INVALID_VRF` | Envia VRF proofs forjados |
| `BYZANTINE_DELAY` | Atrasa intencionalmente todas as mensagens |

---

## 9. Blueprint de Configuração

### 9.1 Arquivo de Configuração (`config.yaml`)

```yaml
# Gleipnir v2.0 Configuration

node:
  identity:
    entropy_source: "${UID0_ENTROPY}"  # min 128 bits entropy
    contract_hash: "${CONTRACT_HASH}"
    simulated: false

network:
  network_id: ""  # derived from genesis block if empty
  listen_address: "0.0.0.0:9090"
  peers:
    - "peer1.example.com:9090"
    - "peer2.example.com:9090"

consensus:
  base_interval_ms: 3000
  max_cycle_duration_ms: 10000
  cycle_timeout_ms: 8000
  lambda_interval: 10
  min_lambda1: 0.01
  grace_cycles: 10
  skip_empty_cycles: true
  max_pending_ttl: 100

validation:
  max_label_len: 256
  max_payload_bytes: 1048576  # 1 MiB
  rate_limit_per_minute: 5000

crypto:
  batch_verify_workers: 0  # 0 = auto (min 4, max 16)

publisher:
  mode: "designated"  # all, designated, external
  min_redundancy: 2
  backends:
    - type: "ipfs"
      endpoint: "http://localhost:5001"
      auth_token: "${IPFS_AUTH_TOKEN}"
      pin: true
    - type: "s3"
      endpoint: "s3.amazonaws.com"
      bucket: "3cp-anchors"
      region: "us-east-1"
      use_ssl: true
      path_style: false
    - type: "file"
      path: "/var/lib/gleipnir/anchors"

storage:
  type: "filesystem"
  path: "/var/lib/gleipnir/data"
  # type: "memory"  # for testing only

logging:
  level: "info"  # debug, info, warn, error
  format: "json"
```

---

## 10. Blueprint de Deploy e Operação

### 10.1 Topologia de Rede Recomendada

```
                    ┌─────────────────┐
                    │   Load Balancer │
                    │   (gRPC/HTTP)   │
                    └────────┬────────┘
                             │
           ┌─────────────────┼─────────────────┐
           │                 │                 │
    ┌──────▼──────┐  ┌──────▼──────┐  ┌──────▼──────┐
    │  Validator 0 │  │  Validator 1 │  │  Validator 2 │
    │   (Leader)   │  │              │  │              │
    │  ┌─────────┐ │  │  ┌─────────┐ │  │  ┌─────────┐ │
    │  │ Gleipnir│ │  │  │ Gleipnir│ │  │  │ Gleipnir│ │
    │  │  Node   │ │  │  │  Node   │ │  │  │  Node   │ │
    │  └────┬────┘ │  │  └────┬────┘ │  │  └────┬────┘ │
    │       │      │  │       │      │  │       │      │
    │  ┌────▼────┐ │  │  ┌────▼────┐ │  │  ┌────▼────┐ │
    │  │  IPFS   │ │  │  │  IPFS   │ │  │  │  IPFS   │ │
    │  │  Daemon │ │  │  │  Daemon │ │  │  │  Daemon │ │
    │  └────┬────┘ │  │  └────┬────┘ │  │  └────┬────┘ │
    └───────┼──────┘  └───────┼──────┘  └───────┼──────┘
            │                 │                 │
            └─────────────────┼─────────────────┘
                              │
                    ┌─────────▼─────────┐
                    │   IPFS Network    │
                    │  (public DHT)     │
                    └───────────────────┘
                              │
                    ┌─────────▼─────────┐
                    │   Light Clients   │
                    │   / Auditors      │
                    └───────────────────┘
```

### 10.2 Checklist de Bootstrap de Rede

1. **Gerar Genesis:**
   ```bash
   gleipnir genesis create      --validators validator0.yaml,validator1.yaml,validator2.yaml      --mandate genesis-mandate.yaml      --output genesis.cbor
   ```

2. **Distribuir Genesis:**
   - Copiar `genesis.cbor` para todos os nós
   - Verificar `NetworkID` consistente em todos

3. **Inicializar Nós:**
   ```bash
   gleipnir node start --genesis genesis.cbor --config config.yaml
   ```

4. **Verificar Convergência:**
   - Todos os nós devem produzir o mesmo bloco 0
   - `BlockHash` idêntico em todos

5. **Ativar Publishers:**
   - Verificar IPFS/S3 conectividade
   - Confirmar `ExternalAnchors` populado no bloco 1+

---

## 11. Matriz de Decisões de Design Críticas

| Decisão | Escolha | Alternativa Rejeitada | Justificativa |
|---------|---------|----------------------|---------------|
| Fases expostas na API? | Não (unexported) | `RunPreparePhase()` público | Previne violação de invariante atômico |
| Worker pool size | Configurável (4-16) | Fixo em 4 | Adapta-se a hardware variado |
| Lanczos vs QR completo | Lanczos para N>100 | Sempre QR | Performance em redes grandes |
| Publisher modo default | `designated` | `all` | Reduz custo operacional em produção |
| UID0 derivação | HKDF(NetworkID) | Hash simples | Resistência a colisão e previsibilidade |
| Ciclo vazio | Pulável (`SkipEmptyCycles`) | Sempre produz bloco | Economia de recursos |
| Degradação `N<4` | `1-of-N` + alerta | Recusar operação | Permite bootstrap e testes |

---

## 12. Glossário Arquitetural do Gleipnir

| Termo | Definição |
|-------|-----------|
| **Engine** | Máquina de consenso. Único componente com estado mutável de ciclo. |
| **Gossip** | Canal de comunicação entre nós. Transporta VRF proofs, assinaturas e blocos. |
| **Pending Queue** | Fila de entradas submetidas mas ainda não ancoradas. Persistente em abortos. |
| **Anchor** | Bloco final publicado em storage externo. Torn a cadeia acessível a terceiros. |
| **Cycle** | Unidade atômica de tempo do consenso. Produz zero ou um bloco. |
| **Phase** | Subdivisão interna do ciclo (PREPARE, COMMIT). Não é API pública. |
| **Slashing** | Penalização de validador por comportamento bizantino detectável. |
| **Overlap** | Período em que duas chaves de um validador são simultaneamente válidas. |

---

## 13. Referências Cruzadas

| Documento | Local no repo Gleipnir | Conteúdo |
|-----------|------------------------|----------|
| SPEC-3CP-V2.md | `../3CP/spec/SPEC-3CP-V2.md` (link externo) | Protocolo normativo |
| CDDLs | `../3CP/spec/schemas/` | Schemas de dados |
| Test Vectors | `../3CP/spec/examples/` | Vetores de teste |
| Conformance Suite | `cmd/conformance-test/` | Implementação dos 12 TCs v2.0 |

---

*Fim do documento.*

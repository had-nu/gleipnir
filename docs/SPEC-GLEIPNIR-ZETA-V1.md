# SPEC-GLEIPNIR-ZETA-V1.md
# Gleipnir — Reference Implementation of 3CP with Zeta Temporal Hardening
# Version: GLEIPNIR-ZETA-1.0.0-Draft
# Language: Go 1.22+
# Status: Pre-publication / Draft
# Author: André Ataíde
# Date: 2026-07-30

---

## 1. Resumo Executivo

Esta especificação define a implementação de referência do 3CP com a Zeta Temporal Hardening Layer (ZTHL) no Gleipnir. O Gleipnir é um nó 3CP escrito em Go que implementa o protocolo de consenso BFT, a camada de âncoras, o Sparse Merkle Tree (SMT), e agora a camada Zeta-VDF.

### 1.1 Escopo

- Implementação das estruturas de dados CBOR com `zeta_anchor`
- Integração do Zeta Oracle client
- Módulo VDF (Wesolowski)
- Alterações ao consenso BFT (validação de VDF antes de PREPARE)
- Testes de stress, fuzzing, e adversariais
- Benchmarks de performance

### 1.2 Arquitetura de Alto Nível

```
┌─────────────────────────────────────────────────────────────┐
│                        Gleipnir Node                       │
├─────────────────────────────────────────────────────────────┤
│  API Layer (gRPC)                                          │
│  ├── BlockService                                          │
│  ├── AnchorService                                         │
│  ├── LightClientService                                    │
│  └── ZetaService (novo)                                    │
├─────────────────────────────────────────────────────────────┤
│  Consensus Layer                                           │
│  ├── BFT Engine (PREPARE/COMMIT)                          │
│  ├── ECVRF Leader Election (seed = vdf_output)             │
│  └── Zeta Validator (novo)                                 │
├─────────────────────────────────────────────────────────────┤
│  State Layer                                               │
│  ├── Sparse Merkle Tree (BLAKE3, depth 256)               │
│  │   └── leaf_value = BLAKE3(data || vdf_output || class) │
│  ├── Mandate Registry                                     │
│  └── Key Rotation Journal                                  │
├─────────────────────────────────────────────────────────────┤
│  Cryptographic Layer                                       │
│  ├── Dilithium3 (signatures)                              │
│  ├── Kyber1024 (KEM)                                      │
│  ├── ECVRF (Ristretto255)                                 │
│  └── VDF (Wesolowski) — NOVO                              │
├─────────────────────────────────────────────────────────────┤
│  Zeta Layer (NOVO)                                         │
│  ├── Oracle Client (fetch, cache, verify Merkle)          │
│  ├── Zero Cache (LRU + persistent)                        │
│  └── Commitment Verifier                                  │
├─────────────────────────────────────────────────────────────┤
│  Storage Layer                                             │
│  ├── BadgerDB (SMT, blocks, anchors)                      │
│  └── WAL (consensus log)                                  │
└─────────────────────────────────────────────────────────────┘
```

---

## 2. Escolhas Arquiteturais e Justificações

### 2.1 Porquê Go?

- **Concorrência nativa**: goroutines e channels são ideais para o modelo de mensagens do BFT
- **Ecossistema criptográfico maduro**: `filippo.io/nistec`, `golang.org/x/crypto` para Ristretto255
- **Performance de rede**: gRPC/Protobuf nativo, excelente throughput
- **Operacionalidade**: binário único, cross-compile, fácil deploy

### 2.2 Porquê BadgerDB?

- LSM-tree com writes otimizados — ideal para append-only chain-of-custody
- Suporte a transactions — necessário para atomicidade de bloco + SMT + âncoras
- Iteradores eficientes — para scans de light clients

### 2.3 Porquê Wesolowski VDF?

| Critério | Wesolowski | Pietrzak | Justificação |
|---|---|---|---|
| Tamanho da proof | ~1KB | ~100KB | Menor overhead de rede |
| Tempo de verificação | O(1) grupos | O(log T) | Crítico para BFT PREPARE |
| Trusted setup | Não | Não | Ambos aceitáveis |
| Implementação madura | Sim (Chia, Ethereum) | Menos | Menor risco de bugs |

**Trade-off**: Wesolowski exige grupos de ordem desconhecida (RSA-2048 ou class groups). Escolhemos **class groups** (Chia VDF) para evitar trusted setup RSA.

### 2.4 Porquê Zeta Oracle out-of-band?

- Cálculo de zeros é caro e não paralelizável
- Amortização: calcula-se uma vez, usa-se muitas
- Descentralização: múltiplas fontes publicam o mesmo commitment; nós verificam consistência
- Separação de concerns: o protocolo não depende da disponibilidade do Oracle em tempo real, apenas do commitment bootstrapado

---

## 3. Estrutura de Pacotes

```
gleipnir/
├── cmd/
│   └── gleipnir/
│       └── main.go
├── pkg/
│   ├── api/                    # gRPC handlers
│   │   ├── block.go
│   │   ├── anchor.go
│   │   ├── lightclient.go
│   │   └── zeta.go             # NOVO
│   ├── consensus/
│   │   ├── bft.go              # ALTERADO: validação Zeta antes de PREPARE
│   │   ├── ecvrf.go            # ALTERADO: seed = vdf_output
│   │   ├── message.go
│   │   └── state.go
│   ├── zeta/                   # NOVO — camada Zeta
│   │   ├── oracle.go           # Cliente HTTP/gRPC do Zeta Oracle
│   │   ├── commitment.go       # Verificação Merkle de zeros
│   │   ├── cache.go            # LRU cache + persistência Badger
│   │   ├── validator.go        # Validação de zeta_anchor em blocos
│   │   └── bootstrap.go        # Cerimónia de bootstrap
│   ├── vdf/                    # NOVO — Verifiable Delay Functions
│   │   ├── interface.go        # VDF interface (Eval, Verify)
│   │   ├── wesolowski.go       # Implementação Wesolowski
│   │   ├── classgroup.go       # Operações em class groups (Chia)
│   │   └── params.go           # Parâmetros de dificuldade por epoch
│   ├── crypto/
│   │   ├── dilithium3.go
│   │   ├── kyber1024.go
│   │   ├── ecvrf.go
│   │   └── blake3.go
│   ├── smt/
│   │   ├── tree.go             # ALTERADO: leaf_value com salt
│   │   ├── node.go
│   │   └── proof.go
│   ├── anchor/
│   │   ├── mandate.go          # ALTERADO: validação de mandates críticos
│   │   ├── keyrotation.go      # ALTERADO: validação temporal
│   │   └── crosschain.go       # ALTERADO: zeta_nonce
│   ├── wire/
│   │   ├── cbor.go
│   │   └── schemas.go          # ALTERADO: zeta_anchor CDDL
│   ├── storage/
│   │   ├── badger.go
│   │   └── wal.go
│   └── config/
│       └── config.go
├── internal/
│   ├── testutil/               # Helpers de teste
│   └── fixtures/               # Vectores de teste
├── test/
│   ├── integration/            # Testes de integração
│   ├── stress/                 # Testes de stress
│   ├── fuzz/                   # Fuzzing
│   └── adversarial/            # Testes adversariais
├── scripts/
│   ├── bootstrap_zeta.sh       # Script de bootstrap do Zeta Oracle
│   └── benchmark_vdf.sh        # Benchmark de VDF
├── spec/                       # Mirror da SPEC normativa
│   └── SPEC-3CP-ZETA-V1.md
├── docs/
│   └── ARCHITECTURE.md
├── .gitignore                  # CRÍTICO — ver §9
├── go.mod
├── Makefile
└── Dockerfile
```

---

## 4. Implementação Detalhada

### 4.1 `pkg/zeta/oracle.go`

```go
package zeta

// OracleClient interface para múltiplas fontes
type OracleClient interface {
    // FetchZero obtém o zero ρ_n e o Merkle proof do commitment
    FetchZero(ctx context.Context, index uint64) (*ZeroEntry, error)

    // FetchCommitment obtém o commitment root mais recente
    FetchCommitment(ctx context.Context) (*Commitment, error)

    // VerifyConsistency verifica que múltiplas fontes concordam
    VerifyConsistency(ctx context.Context, entry *ZeroEntry) error
}

type ZeroEntry struct {
    Index           uint64
    Value           []byte      // Im(ρ_n) big-endian
    CommitmentRoot  []byte
    MerklePath      [][]byte
    SourceURI       string
    AttestedAt      time.Time
}

type Commitment struct {
    Root        []byte
    EpochRange  [2]uint64   // [start_epoch, end_epoch]
    Sources     []string
    Attestations [][]byte   // Dilithium3 sigs dos oracles
}
```

**Política de consistência**: Um nó só aceita um `ZeroEntry` se pelo menos **2 de 3** fontes independentes concordarem no `CommitmentRoot`.

### 4.2 `pkg/zeta/validator.go`

```go
package zeta

// Validator verifica zeta_anchors em blocos propostos
type Validator struct {
    oracle     OracleClient
    commitment *Commitment
    cache      *Cache
}

func (v *Validator) ValidateBlock(ctx context.Context, block *wire.Block) error {
    za := block.Header.ZetaAnchor

    // 1. Verificar epoch_id dentro do range do commitment
    if za.EpochID < v.commitment.EpochRange[0] || 
       za.EpochID > v.commitment.EpochRange[1] {
        return fmt.Errorf("epoch %d fora do range do commitment", za.EpochID)
    }

    // 2. Verificar Merkle proof
    if !merkle.Verify(za.ZeroValue, za.CommitmentRoot, za.MerklePath) {
        return errors.New("merkle proof inválido para zero")
    }

    // 3. Verificar consistência cross-source
    entry := &ZeroEntry{
        Index: za.ZeroIndex,
        Value: za.ZeroValue,
        CommitmentRoot: za.CommitmentRoot,
    }
    if err := v.oracle.VerifyConsistency(ctx, entry); err != nil {
        return fmt.Errorf("inconsistência de oracle: %w", err)
    }

    return nil
}
```

### 4.3 `pkg/vdf/wesolowski.go`

```go
package vdf

import (
    "github.com/chia-network/vdf-bindings/go/pkg/vdf"
)

// ClassGroupVDF implementa Wesolowski usando class groups (Chia)
type ClassGroupVDF struct {
    discriminantSize int
    iterations       uint64
}

func NewClassGroupVDF(discriminantSize int, iterations uint64) *ClassGroupVDF {
    return &ClassGroupVDF{
        discriminantSize: discriminantSize,
        iterations:       iterations,
    }
}

// Eval computa a VDF: y = x^(2^T) em class group
func (v *ClassGroupVDF) Eval(input []byte) (*Proof, error) {
    discriminant := vdf.CreateDiscriminant(input, v.discriminantSize)
    x := vdf.ByteSliceToClassGroup(input)

    y, proof, err := vdf.VerifyWesolowski(discriminant, x, input, v.iterations, nil)
    if err != nil {
        return nil, err
    }

    return &Proof{
        Output: y,
        Proof:  proof,
        Input:  input,
    }, nil
}

// Verify verifica a proof em tempo O(1)
func (v *ClassGroupVDF) Verify(input, output, proof []byte) error {
    discriminant := vdf.CreateDiscriminant(input, v.discriminantSize)
    return vdf.VerifyWesolowski(discriminant, 
        vdf.ByteSliceToClassGroup(input),
        input,
        v.iterations,
        proof)
}

type Proof struct {
    Output []byte
    Proof  []byte
    Input  []byte
}
```

**Parâmetros recomendados**:
- `discriminantSize`: 2048 bits
- `iterations`: 2^26 (~67 milhões) → ~10 minutos em CPU single-core moderno
- Ajustável por epoch via governance (§13 Mandates)

### 4.4 `pkg/consensus/bft.go` — Alterações

```go
func (b *BFT) handlePrepare(msg *PrepareMessage) error {
    block := msg.Block

    // NOVO: Validar zeta_anchor antes de tudo
    if err := b.zetaValidator.ValidateBlock(b.ctx, block); err != nil {
        b.logger.Warn("zeta validation failed", "error", err)
        return b.voteReject(block)
    }

    // NOVO: Verificar VDF proof
    vdfInput := blake3.Sum256(append(block.Header.ZetaAnchor.ZeroValue,
        append(uint64ToBE(block.Header.ZetaAnchor.EpochID),
            block.Header.PrevBlockHash...)...))

    if err := b.vdf.Verify(vdfInput[:], 
                           block.Header.ZetaAnchor.VdfOutput,
                           block.Header.ZetaAnchor.VdfProof); err != nil {
        b.logger.Warn("vdf verification failed", "error", err)
        return b.voteReject(block)
    }

    // EXISTENTE: Verificar ECVRF com seed = vdf_output
    epochSeed := blake3.Sum256(append(block.Header.ZetaAnchor.VdfOutput,
        uint64ToBE(block.Header.ZetaAnchor.EpochID)...))

    if err := b.ecvrf.Verify(block.ProposerPubKey, epochSeed[:], block.VRFProof); err != nil {
        return b.voteReject(block)
    }

    // EXISTENTE: Verificar SMT, mandates, etc.
    // ...

    return b.votePrepare(block)
}
```

### 4.5 `pkg/smt/tree.go` — Alterações

```go
func (t *Tree) LeafValue(event *wire.Event, zetaAnchor *wire.ZetaAnchor) []byte {
    // NOVO: leaf_value = BLAKE3(event_data || vdf_output || mandate_class || timestamp)
    h := blake3.New()
    h.Write(event.Data)
    h.Write(zetaAnchor.VdfOutput)
    h.Write([]byte(event.MandateClass))
    h.Write(uint64ToBE(event.Timestamp))
    return h.Sum(nil)
}
```

---

## 5. Testes

### 5.1 Testes Unitários

```
test/
├── unit/
│   ├── zeta/
│   │   ├── oracle_test.go
│   │   ├── commitment_test.go
│   │   ├── cache_test.go
│   │   └── validator_test.go
│   ├── vdf/
│   │   ├── wesolowski_test.go
│   │   ├── classgroup_test.go
│   │   └── params_test.go
│   ├── consensus/
│   │   ├── bft_zeta_test.go
│   │   └── ecvrf_seed_test.go
│   └── smt/
│       └── salted_leaf_test.go
```

**Cobertura mínima exigida**: 90% para `pkg/zeta/`, `pkg/vdf/`, `pkg/consensus/`

### 5.2 Testes de Integração

```go
// test/integration/zeta_consensus_test.go
func TestZetaConsensus_FullFlow(t *testing.T) {
    // Setup: 7 nós, 1 Bizantino
    cluster := NewTestCluster(t, 7, WithByzantineNodes(1))

    // Bootstrap Zeta Oracle com 1000 zeros
    oracle := NewMockOracle(t, 1000)
    cluster.SetZetaOracle(oracle)

    // Executar 10 epochs
    for epoch := uint64(1); epoch <= 10; epoch++ {
        block := cluster.ProposeBlock(epoch)
        require.NoError(t, cluster.ValidateBlock(block))
        require.NoError(t, cluster.CommitBlock(block))
    }

    // Verificar: nenhum bloco sem zeta_anchor foi aceite
    require.Equal(t, 10, cluster.AcceptedBlocks())
    require.Equal(t, 0, cluster.RejectedBlocks())
}
```

### 5.3 Testes Adversariais

```go
// test/adversarial/zeta_fraud_test.go
func TestZetaFraud_FakeVDF(t *testing.T) {
    cluster := NewTestCluster(t, 7)

    // Nó Bizantino propõe bloco com VDF falsa
    fakeBlock := cluster.CreateBlockWithFakeVDF()

    // Quorum honesto deve rejeitar
    result := cluster.ProposeAndVote(fakeBlock)
    require.Equal(t, Rejected, result)
    require.True(t, cluster.HasViewChange())
}

func TestZetaFraud_BackdatedMandate(t *testing.T) {
    cluster := NewTestCluster(t, 7)
    cluster.RunEpochs(5)

    // Tentar emitir mandate crítico com epoch_id = 2 (no passado)
    badMandate := &wire.MandateDeclaration{
        Class: "critical",
        ZetaAnchor: &wire.ZetaAnchor{EpochID: 2},
    }

    block := cluster.ProposeBlock(6, WithMandate(badMandate))
    require.Error(t, cluster.ValidateBlock(block))
}

func TestZetaFraud_GrindingAttack(t *testing.T) {
    cluster := NewTestCluster(t, 7)

    // Simular adversário tentando prever seeds
    adversary := NewAdversary(cluster)
    for i := 0; i < 10000; i++ {
        seed := adversary.GuessSeed()
        // Sem VDF, não pode prever seed válido
        require.False(t, cluster.IsValidSeed(seed))
    }
}
```

### 5.4 Testes de Stress

```go
// test/stress/vdf_stress_test.go
func TestVDF_StressSequential(t *testing.T) {
    vdf := NewClassGroupVDF(2048, 1<<26)

    // Avaliar 100 VDFs sequenciais
    start := time.Now()
    for i := 0; i < 100; i++ {
        input := make([]byte, 32)
        rand.Read(input)
        proof, err := vdf.Eval(input)
        require.NoError(t, err)
        require.NoError(t, vdf.Verify(input, proof.Output, proof.Proof))
    }
    elapsed := time.Since(start)

    t.Logf("100 VDFs em %v (média %v/VDF)", elapsed, elapsed/100)
    // Assert: média < 15 minutos por VDF em hardware de referência
}

// test/stress/consensus_stress_test.go
func TestConsensus_Stress100Nodes(t *testing.T) {
    cluster := NewTestCluster(t, 100, WithByzantineNodes(33))

    // Executar 1000 epochs
    done := make(chan struct{})
    go func() {
        cluster.RunEpochs(1000)
        close(done)
    }()

    select {
    case <-done:
        t.Logf("1000 epochs completados")
    case <-time.After(24 * time.Hour):
        t.Fatal("timeout — liveness violada")
    }

    // Assert: nenhum fork detectado
    require.Equal(t, 1, cluster.ForkCount())

    // Assert: todos os blocos têm zeta_anchor válido
    for _, block := range cluster.Blocks() {
        require.NotNil(t, block.Header.ZetaAnchor)
    }
}

// test/stress/network_partition_test.go
func TestConsensus_NetworkPartition(t *testing.T) {
    cluster := NewTestCluster(t, 10)
    cluster.RunEpochs(50)

    // Particionar rede em 2 grupos (6 + 4) durante 10 epochs
    cluster.Partition(6, 4)
    cluster.RunEpochs(10)

    // Healar partição
    cluster.Heal()
    cluster.RunEpochs(10)

    // Assert: chain recupera sem gaps temporais
    require.NoError(t, cluster.VerifyTemporalContinuity())
}
```

### 5.5 Fuzzing

```go
// test/fuzz/zeta_anchor_fuzz.go
// +build gofuzz

func FuzzZetaAnchor(data []byte) int {
    var za wire.ZetaAnchor
    if err := cbor.Unmarshal(data, &za); err != nil {
        return 0 // descartar
    }

    validator := zeta.NewValidator(mockOracle, mockCommitment)
    if err := validator.Validate(context.Background(), &za); err == nil {
        // Se passou na validação, verificar invariantes
        if za.EpochID == 0 {
            panic("epoch_id 0 não deveria ser aceite")
        }
    }
    return 1
}

// test/fuzz/vdf_input_fuzz.go
func FuzzVDFVerify(data []byte) int {
    if len(data) < 96 {
        return 0
    }
    input := data[:32]
    output := data[32:64]
    proof := data[64:]

    vdf := NewClassGroupVDF(2048, 1<<20) // iterações reduzidas para fuzzing
    vdf.Verify(input, output, proof) // não deve panicar
    return 1
}
```

**Execução**:
```bash
make fuzz-zeta-anchor
make fuzz-vdf-verify
# Mínimo: 24 horas de fuzzing contínuo antes de release
```

### 5.6 Benchmarks

```go
// test/bench/vdf_bench_test.go
func BenchmarkVDF_Eval(b *testing.B) {
    vdf := NewClassGroupVDF(2048, 1<<26)
    input := make([]byte, 32)
    rand.Read(input)

    b.ResetTimer()
    for i := 0; i < b.N; i++ {
        _, err := vdf.Eval(input)
        require.NoError(b, err)
    }
}

func BenchmarkZeta_ValidateBlock(b *testing.B) {
    validator := setupValidator()
    block := generateValidBlock()

    b.ResetTimer()
    for i := 0; i < b.N; i++ {
        validator.ValidateBlock(context.Background(), block)
    }
}
```

**Métricas de referência** (hardware: AMD EPYC 7763, 64 cores):
- VDF Eval: 8-12 minutos
- VDF Verify: < 100ms
- ZetaAnchor ValidateBlock: < 50ms (com cache)
- SMT Update com salt: < 10ms

---

## 6. Configuração

### 6.1 `config.yaml` (exemplo)

```yaml
node:
  id: "node-01"
  listen: ":50051"

consensus:
  bft:
    nodes: 7
    byzantine_threshold: 2
    epoch_timeout: "15m"

zeta:
  oracle:
    sources:
      - "https://zeta-oracle-1.example.com"
      - "https://zeta-oracle-2.example.com"
      - "https://zeta-oracle-3.example.com"
    consistency_threshold: 2
    cache_size: 10000
    cache_ttl: "24h"

  vdf:
    discriminant_size: 2048
    iterations: 67108864  # 2^26
    min_eval_time: "10m"
    max_eval_time: "15m"

  bootstrap:
    genesis_commitment: "base64:AQIDBAUG..."
    ceremony_timestamp: "2026-01-01T00:00:00Z"

crypto:
  dilithium3:
    private_key_path: "/secrets/dilithium3.key"  # NUNCA no git
  ecvrf:
    secret_key_path: "/secrets/ecvrf.key"          # NUNCA no git
```

---

## 7. Operações e Deployment

### 7.1 Bootstrap do Zeta Oracle

```bash
# 1. Gerar commitment dos primeiros 1M zeros
./scripts/bootstrap_zeta.sh   --count 1000000   --output ./zeta_commitment.json   --sign-with /secrets/genesis_key.pem

# 2. Distribuir commitment para nós (via secure channel, NÃO git)
scp zeta_commitment.json node-01:/etc/gleipnir/bootstrap/

# 3. Iniciar nós
 gleipnir --config /etc/gleipnir/config.yaml
```

### 7.2 Monitoramento

Métricas Prometheus expostas:
- `gleipnir_vdf_eval_duration_seconds`
- `gleipnir_vdf_verify_duration_seconds`
- `gleipnir_zeta_oracle_fetch_errors_total`
- `gleipnir_consensus_prepare_rejections_total` (com label `reason=zeta_invalid`)
- `gleipnir_smt_leaf_count`
- `gleipnir_mandate_critical_count`

Alertas:
- `vdf_eval_duration > 20m` → alerta de performance
- `zeta_oracle_fetch_errors > 5/5m` → alerta de disponibilidade
- `consensus_prepare_rejections{reason=zeta_invalid} > 10/1h` → possível ataque

---

## 8. Documentação

### 8.1 Documentos obrigatórios no repo

```
docs/
├── ARCHITECTURE.md           # Diagramas e decisões arquiteturais
├── ZETA_LAYER.md             # Documentação da camada Zeta
├── VDF_INTEGRATION.md        # Guia de integração da VDF
├── TESTING.md                # Como correr testes, benchmarks, fuzzing
├── DEPLOYMENT.md             # Guia de deployment e bootstrap
├── SECURITY.md               # Modelo de ameaças e responsável disclosure
├── PERFORMANCE.md            # Benchmarks e SLAs
└── TROUBLESHOOTING.md        # Problemas comuns e resolução
```

### 8.2 Documentação que NÃO deve estar no repo

- Credenciais de produção
- Diagramas de rede interna com IPs
- Playbooks de incident response detalhados
- Análises de vulnerabilidades não corrigidas

---

## 9. Arquivos que NUNCA devem ser pushados para repositório online

### 9.1 `.gitignore` completo

```gitignore
# ============================================
# GLEIPNIR — ARQUIVOS QUE NUNCA DEVEM SER COMMITADOS
# ============================================

# ─── CHAVES CRYPTOGRÁFICAS ───
*.pem
*.key
*.priv
*.secret
*.seed
/secrets/
/keys/
/node_keys/
/dilithium_private/
/kyber_private/
/ecvrf_private/
/genesis_keys/
*.p12
*.pfx

# ─── ESTADO E DADOS OPERACIONAIS ───
/data/
/db/
/wal/
/smt_cache/
/vdf_cache/
/zeta_cache/
/badger/
*.db
*.wal
*.snapshot
*.backup
/chain_data/
/evidence_store/

# ─── CONFIGURAÇÕES SENSÍVEIS ───
config.prod.yaml
config.staging.yaml
config.*.local.yaml
.env
.env.local
.env.production
.env.staging
.env.*
/secrets.yaml
/secrets.json
/vault/
/ansible/inventories/production/
/terraform/*.tfstate
/terraform/*.tfstate.*
/terraform/.terraform/

# ─── ARTEFACTOS ZK ───
*.r1cs
*.wasm
*.zkey
*.ptau
*.vk
*.pk
/proving_key/
/verification_key/
/circuits/build/
/circuits/target/

# ─── BUILD E DEPENDÊNCIAS ───
/bin/
/dist/
/vendor/
/target/                    # se houver código Rust híbrido
*.exe
*.dll
*.so
*.dylib

# ─── LOGS E EVIDÊNCIA ───
/logs/
*.log
*.audit
*.forensic
/chain_evidence/
/audit_trail/
*.core
*.dmp

# ─── DOCUMENTAÇÃO INTERNA ───
/notes/internal/
/meeting_notes/
/threat_model_drafts/
*.draft.md
*.internal.md
/SECURITY_CONTACTS.md
/INCIDENT_RESPONSE/
/PENTEST_REPORTS/

# ─── FERRAMENTAS E IDE ───
.idea/
.vscode/
*.swp
*.swo
*~
.DS_Store
```

### 9.2 Pre-commit hooks obrigatórios

```yaml
# .pre-commit-config.yaml
repos:
  - repo: https://github.com/pre-commit/pre-commit-hooks
    rev: v4.5.0
    hooks:
      - id: detect-private-key
      - id: check-added-large-files
        args: ['--maxkb=1000']

  - repo: local
    hooks:
      - id: check-secrets
        name: Check for secrets
        entry: scripts/check_secrets.sh
        language: script
        files: .*

      - id: check-gitignore
        name: Check .gitignore coverage
        entry: scripts/check_gitignore.sh
        language: script
```

### 9.3 Política de Secrets

| Tipo | Armazenamento | Rotação |
|---|---|---|
| Dilithium3 private key | HashiCorp Vault / AWS KMS | A cada rotação de epoch (§8) |
| ECVRF secret key | HSM (YubiHSM 2) | A cada rotação de epoch |
| Genesis signing key | Shamir Secret Sharing (3/5) | Nunca (cerimónia única) |
| Zeta Oracle API tokens | Vault KV v2 | A cada 90 dias |
| Anchor Publisher credentials | Vault KV v2 | A cada 90 dias |

---

## 10. Referências

- SPEC-3CP-ZETA-V1.md (normativo)
- SPEC-CARCOSA-ZETA-V1.md (ZK proofs)
- Chia VDF: https://github.com/Chia-Network/chiavdf
- Go Class Group: https://github.com/Chia-Network/vdf-bindings
- BadgerDB: https://dgraph.io/docs/badger/

---

*All Rights Reserved © 2026 — André Ataíde*
*Pre-publication draft — do not distribute*

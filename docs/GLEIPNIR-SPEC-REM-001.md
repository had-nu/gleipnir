# GLEIPNIR v2.0 — SPEC DE REMEDIAÇÃO

**ID:** GLEIPNIR-SPEC-REM-001  
**Versão:** 1.0  
**Data:** 2026-07-29  
**Status:** DRAFT  
**Autor:** Análise automatizada via API GitHub  
**Escopo:** Remediação completa dos problemas identificados no commit `f9c74d9` (v2.0)  
**Prioridade:** P0 → P1 → P2 (bloqueante → alto → médio)

---

## 1. RESUMO EXECUTIVO

Esta SPEC define as mudanças necessárias para tornar o Gleipnir v2.0 pronto para produção. Os problemas estão organizados em três níveis de prioridade:

| Prioridade | Quantidade | Impacto se não resolvido |
|------------|------------|--------------------------|
| **P0 — CRÍTICO** | 3 | Build quebrado, non-repudiation comprometida, auditabilidade impossível |
| **P1 — ALTO** | 5 | Segurança não verificada em CI, cobertura de testes incompleta, UX degradada |
| **P2 — MÉDIO** | 5 | Escalabilidade limitada, manutenibilidade reduzida, visibilidade operacional |

**Estimativa total de esforço:** 3–5 sprints (2 semanas cada)  
**Bloqueantes para produção:** Apenas P0 (Sprint 1)  
**Recomendação:** Não fazer deploy de nenhum nó em rede pública antes de P0 completo.

---

## 2. P0 — CRÍTICO (Bloqueante para Produção)

---

### P0.1 — Corrigir Versões Go Inexistentes

**Problema:**  
- `go.mod` declara `go 1.25.7` — versão inexistente  
- `Dockerfile` usa `golang:1.26-alpine` — imagem inexistente  
- `.github/workflows/ci.yml` usa `GO_VERSION: "1.25"` — inconsistente

**Impacto:** Build impossível em qualquer ambiente. Go 1.24 é a versão estável em 2026-07.

**Solução:**

```
┌─────────────────────────────────────────────────────────────────────────┐
│  ARQUIVO          │  ATUAL              │  CORREÇÃO                     │
├─────────────────────────────────────────────────────────────────────────┤
│  go.mod           │  go 1.25.7          │  go 1.24                      │
│  Dockerfile       │  golang:1.26-alpine │  golang:1.24-alpine           │
│  ci.yml           │  GO_VERSION: "1.25" │  GO_VERSION: "1.24"           │
│  README.md        │  badge go-1.24+     │  (já correto, manter)         │
└─────────────────────────────────────────────────────────────────────────┘
```

**Critérios de Aceitação:**
- [ ] `go mod tidy` executa sem erros
- [ ] `docker build .` completa com sucesso
- [ ] CI passa em todas as jobs (lint, build, test, race, vet)
- [ ] `go version` no container retorna `go1.24.x`

**Estimativa:** 0.5 dia

---

### P0.2 — Implementar Verificação Server-Side de Per-Entry Signatures

**Problema:**  
O campo `Signature` em `ProvenanceEntry` é aceito pelo gRPC server mas **não é verificado**. Qualquer cliente pode submeter uma assinatura inválida ou forjada, comprometendo a non-repudiation — o propósito central do 3CP.

**Impacto:**  
A cadeia pode conter entradas com assinaturas falsas. Um auditor não pode confiar que o submitter listado realmente assinou o hash.

**Solução — Arquitetura:**

```
┌─────────────────────────────────────────────────────────────────────────┐
│  FLUXO DE VERIFICAÇÃO DE ASSINATURA                                     │
├─────────────────────────────────────────────────────────────────────────┤
│                                                                         │
│  1. Cliente chama SubmitHash(ctx, &SubmitRequest{                        │
│       Hash, Submitter, Signature, ... })                                │
│                                                                         │
│  2. Server extrai Submitter (RootID) e busca chave pública            │
│     em IdentityRegistry (BoltDB ou memória + cache)                    │
│                                                                         │
│  3. Se Submitter não registrado → retorna SUBMITTER_MISMATCH           │
│                                                                         │
│  4. Server reconstrói payload assinado:                                │
│     payload = Hash || Submitter || Timestamp || Label                  │
│     (formato canonizado, ex: CBOR ou protobuf wire)                   │
│                                                                         │
│  5. Verifica Signature com Dilithium3.Verify(pk, payload, sig)         │
│                                                                         │
│  6. Se falha → retorna INVALID_SIGNATURE                               │
│                                                                         │
│  7. Se sucesso → prossegue para rate-limiting e enfileiramento        │
│                                                                         │
└─────────────────────────────────────────────────────────────────────────┘
```

**Mudanças no Código:**

1. **Novo pacote:** `pkg/identity/registry.go`
```go
package identity

import (
    "sync"
    "go.etcd.io/bbolt"
)

type Registry struct {
    db     *bbolt.DB
    cache  map[string]*PublicKey  // LRU cache
    mu     sync.RWMutex
}

func (r *Registry) Register(rootID string, pubKey []byte) error
func (r *Registry) Lookup(rootID string) (*PublicKey, error)
func (r *Registry) Exists(rootID string) bool
```

2. **Modificar `pkg/server/server.go`:**
```go
func (s *Server) SubmitHash(ctx context.Context, req *pb.SubmitRequest) (*pb.SubmitResponse, error) {
    // 1. Validar hash não-zero
    if isZeroHash(req.Hash) {
        return nil, status.Error(codes.InvalidArgument, "INVALID_HASH")
    }

    // 2. Verificar submitter registrado
    pubKey, err := s.identityRegistry.Lookup(req.Submitter)
    if err != nil {
        return nil, status.Error(codes.PermissionDenied, "SUBMITTER_MISMATCH")
    }

    // 3. Reconstruir payload canonizado
    payload := canonicalPayload(req.Hash, req.Submitter, req.Timestamp, req.Label)

    // 4. Verificar assinatura Dilithium3
    if !dilithium3.Verify(pubKey, payload, req.Signature) {
        return nil, status.Error(codes.InvalidArgument, "INVALID_SIGNATURE")
    }

    // 5. Prosseguir com rate-limiting e enfileiramento
    ...
}
```

3. **Novo arquivo:** `pkg/identity/signature.go`
```go
package identity

import (
    "github.com/cloudflare/circl/sign/dilithium"
)

func canonicalPayload(hash []byte, submitter string, timestamp int64, label string) []byte {
    // Formato determinístico para evitar ambiguidade
    // Usar CBOR ou protobuf canonical encoding
}

func VerifySignature(pubKey []byte, payload []byte, sig []byte) bool {
    // Usar circl/dilithium mode3
}
```

4. **Bootstrap de registry:** No `cmd/provectl init`, gerar e registrar as chaves públicas dos validadores iniciais.

**Testes Necessários:**
- [ ] Teste: assinatura válida → aceita
- [ ] Teste: assinatura inválida → rejeitada com INVALID_SIGNATURE
- [ ] Teste: submitter não registrado → rejeitada com SUBMITTER_MISMATCH
- [ ] Teste: replay de assinatura (timestamp antigo) → rejeitada
- [ ] Teste: assinatura de outro submitter (key swap) → rejeitada
- [ ] Teste: payload canonizado modificado → rejeitada
- [ ] Teste: race condition em lookup concorrente → estável

**Estimativa:** 3–4 dias

---

### P0.3 — Adicionar BlockHash na Resposta do Bloco

**Problema:**  
A resposta `GetBlock` não inclui o hash do próprio bloco. Um cliente não pode verificar independentemente o encadeamento (se o `PrevHash` do bloco N+1 realmente aponta para o hash do bloco N).

**Impacto:**  
Auditabilidade comprometida. Clientes devem confiar no servidor ou recalcular o hash localmente.

**Solução:**

1. **Modificar `pkg/server/api.proto`:**
```protobuf
message Block {
    uint64 index = 1;
    bytes  prev_hash = 2;
    bytes  merkle_root = 3;
    bytes  state_root = 4;
    int64  timestamp = 5;
    repeated ProvenanceEntry entries = 6;

    // NOVO CAMPO
    bytes  block_hash = 7;  // hash do bloco completo (Blake3)
}
```

2. **Modificar `pkg/chain/block.go`:**
```go
func (b *Block) ComputeHash() []byte {
    // Hash canonizado do bloco (excluindo block_hash e signatures)
    h := blake3.New()
    binary.Write(h, binary.BigEndian, b.Index)
    h.Write(b.PrevHash)
    h.Write(b.MerkleRoot)
    h.Write(b.StateRoot)
    binary.Write(h, binary.BigEndian, b.Timestamp)
    for _, e := range b.Entries {
        h.Write(e.Hash)
    }
    return h.Sum(nil)
}

func (b *Block) VerifyHash() bool {
    return bytes.Equal(b.BlockHash, b.ComputeHash())
}
```

3. **Modificar `pkg/server/server.go`:**
```go
func (s *Server) GetBlock(ctx context.Context, req *pb.BlockRequest) (*pb.BlockResponse, error) {
    block := s.chain.GetBlock(req.Index)
    return &pb.BlockResponse{
        Block: &pb.Block{
            Index:      block.Index,
            PrevHash:   block.PrevHash,
            MerkleRoot: block.MerkleRoot,
            StateRoot:  block.StateRoot,
            Timestamp:  block.Timestamp,
            Entries:    convertEntries(block.Entries),
            BlockHash:  block.ComputeHash(), // NOVO
        },
    }, nil
}
```

**Testes Necessários:**
- [ ] Teste: GetBlock retorna BlockHash correto
- [ ] Teste: BlockHash é determinístico (mesmo bloco, mesmo hash)
- [ ] Teste: Modificar qualquer campo do bloco altera BlockHash
- [ ] Teste: Verificação de encadeamento: BlockHash(N) == PrevHash(N+1)
- [ ] Teste: BlockHash verificável por cliente externo (recalcular localmente)

**Estimativa:** 1–2 dias

---

## 3. P1 — ALTO (Segurança e Qualidade)

---

### P1.1 — Adicionar `make audit` (gosec) ao CI

**Problema:**  
O Makefile define `make audit` (gosec), mas o CI não o executa. Vulnerabilidades de segurança podem passar despercebidas.

**Solução:**

```yaml
# .github/workflows/ci.yml (novo job)
  audit:
    runs-on: ubuntu-latest
    needs: [build]
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-go@v5
        with:
          go-version: ${{ env.GO_VERSION }}
      - name: Security audit
        run: |
          go install github.com/securego/gosec/v2/cmd/gosec@latest
          gosec -quiet -confidence medium -fmt sarif -out gosec.sarif ./...
      - name: Upload SARIF
        uses: github/codeql-action/upload-sarif@v3
        if: always()
        with:
          sarif_file: gosec.sarif
```

**Critérios:**
- [ ] Job `audit` executa em todo PR/push
- [ ] Falha em severity HIGH ou CRITICAL bloqueia merge
- [ ] SARIF report é anexado aos security alerts do GitHub

**Estimativa:** 0.5 dia

---

### P1.2 — Expandir Cobertura de Testes no CI

**Problema:**  
Testes de CI limitados a `./pkg/...`. Binários em `cmd/`, `client/`, `bench/` não são testados.

**Solução:**

```yaml
# ci.yml — modificar jobs test e test-race
      - name: Test all packages
        run: go test ./... -v -count=1 -timeout=300s

      - name: Test with race detection
        run: go test -race -short ./... -count=1 -timeout=600s
```

**Exceções justificáveis:**
- `frontend-test/` pode ser excluído se não for Go
- `bench/` pode rodar com timeout maior (900s)

**Critérios:**
- [ ] `go test ./...` passa no CI
- [ ] `go test -race ./...` passa no CI
- [ ] Coverage report gerado e publicado (codecov ou similar)

**Estimativa:** 0.5 dia

---

### P1.3 — Corrigir `actions/checkout@3` → `@v4` no Job `vet`

**Problema:**  
Inconsistência de versão da action. `@v3` pode ter vulnerabilidades conhecidas ou ser descontinuada.

**Solução:**
```yaml
# ci.yml — job vet
      - uses: actions/checkout@v4  # era @v3
```

**Estimativa:** 5 minutos

---

### P1.4 — Implementar SubmitResponse com BlockIndex/BlockTime Reais

**Problema:**  
`SubmitResponse` retorna `block_index=0` e `block_time=0` sempre. Clientes não sabem quando o hash será ancorado.

**Solução:**

1. **Modificar `pkg/server/api.proto`:**
```protobuf
message SubmitResponse {
    bytes  tx_id = 1;           // hash da transação (para rastreamento)
    uint64 block_index = 2;     // 0 = ainda não ancorado
    int64  block_time = 3;      // 0 = pendente
    string status = 4;            // "PENDING" | "ANCHORED" | "REJECTED"
}
```

2. **Modificar `pkg/server/server.go`:**
```go
func (s *Server) SubmitHash(...) (*pb.SubmitResponse, error) {
    // ... validação ...

    txID := hashTx(req)
    s.pendingQueue.Enqueue(txID, req)

    return &pb.SubmitResponse{
        TxId:       txID,
        BlockIndex: 0,
        BlockTime:  0,
        Status:     "PENDING",
    }, nil
}

// Callback quando bloco é finalizado
func (s *Server) onBlockFinalized(block *chain.Block) {
    for _, entry := range block.Entries {
        txID := hashTxFromEntry(entry)
        s.pendingQueue.UpdateStatus(txID, "ANCHORED", block.Index, block.Timestamp)
    }
}
```

3. **Novo endpoint:** `WaitForAnchor` (já mencionado no INTEGRATION_GUIDE)
```go
func (s *Server) WaitForAnchor(ctx context.Context, req *pb.WaitRequest) (*pb.WaitResponse, error) {
    // Polling ou streaming até o hash ser ancorado
    // Timeout: 30s (configurável)
}
```

**Testes:**
- [ ] Submit retorna status PENDING com tx_id
- [ ] Após ancoragem, GetBlock mostra o hash
- [ ] WaitForAnchor retorna após confirmação
- [ ] Timeout de WaitForAnchor funciona corretamente

**Estimativa:** 2–3 dias

---

### P1.5 — Adicionar `govulncheck` e Dependabot ao CI

**Problema:**  
Sem detecção automática de vulnerabilidades em dependências.

**Solução:**

```yaml
# .github/workflows/ci.yml (novo job)
  vulncheck:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-go@v5
        with:
          go-version: ${{ env.GO_VERSION }}
      - name: govulncheck
        run: |
          go install golang.org/x/vuln/cmd/govulncheck@latest
          govulncheck ./...
```

**Dependabot:**
```yaml
# .github/dependabot.yml
version: 2
updates:
  - package-ecosystem: "gomod"
    directory: "/"
    schedule:
      interval: "weekly"
    open-pull-requests-limit: 10
    reviewers:
      - "had-nu"
```

**Estimativa:** 0.5 dia

---

## 4. P2 — MÉDIO (Escalabilidade e Manutenibilidade)

---

### P2.1 — Implementar StreamBlocks (gRPC Streaming)

**Problema:**  
Clientes precisam fazer polling via `GetBlock(i)`. Ineficiente para aplicações em tempo real.

**Solução:**

```protobuf
// api.proto
service ProvenanceAnchor {
    rpc StreamBlocks(StreamRequest) returns (stream Block);
}

message StreamRequest {
    uint64 from_index = 1;  // 0 = desde o genesis
}
```

```go
// pkg/server/server.go
func (s *Server) StreamBlocks(req *pb.StreamRequest, stream pb.ProvenanceAnchor_StreamBlocksServer) error {
    sub := s.chain.Subscribe(req.FromIndex)
    defer sub.Unsubscribe()

    for block := range sub.Ch {
        if err := stream.Send(convertBlock(block)); err != nil {
            return err
        }
    }
    return nil
}
```

**Estimativa:** 1–2 dias

---

### P2.2 — Expor SubChainManager via gRPC

**Problema:**  
Cross-chain proofs não são acessíveis externamente. Sub-chains só existem internamente.

**Solução:**

```protobuf
// api.proto
service ProvenanceAnchor {
    rpc RegisterSubChain(RegisterSubChainRequest) returns (RegisterSubChainResponse);
    rpc AnchorSubChain(AnchorSubChainRequest) returns (AnchorSubChainResponse);
    rpc VerifyCrossChain(VerifyCrossChainRequest) returns (VerifyCrossChainResponse);
}

message RegisterSubChainRequest {
    string service_id = 1;
    bytes  genesis_hash = 2;
}

message AnchorSubChainRequest {
    string service_id = 1;
    bytes  state_root = 2;
    bytes  proof = 3;
}
```

**Estimativa:** 3–4 dias

---

### P2.3 — Adicionar Fuzzing ao CI

**Problema:**  
Sem testes fuzz para parsing de protobuf, validação de assinaturas, e mensagens P2P.

**Solução:**

```go
// pkg/server/fuzz_test.go
func FuzzSubmitRequest(f *testing.F) {
    f.Add([]byte("valid_cbor_payload"))
    f.Fuzz(func(t *testing.T, data []byte) {
        var req pb.SubmitRequest
        if err := proto.Unmarshal(data, &req); err != nil {
            return // invalid input, skip
        }
        // Should not panic
        _ = server.ValidateSubmitRequest(&req)
    })
}
```

```yaml
# ci.yml
  fuzz:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-go@v5
      - name: Fuzz tests
        run: go test -fuzz=FuzzSubmitRequest -fuzztime=60s ./pkg/server/...
```

**Estimativa:** 1–2 dias

---

### P2.4 — Adicionar Benchmarks de Throughput de Consenso

**Problema:**  
Sem métricas de performance do consenso.

**Solução:**

```go
// pkg/consensus/bench_test.go
func BenchmarkConsensusCycle(b *testing.B) {
    engine := NewTestEngine(5) // 5 validators
    for i := 0; i < b.N; i++ {
        engine.RunCycle()
    }
}

func BenchmarkSubmitThroughput(b *testing.B) {
    server := NewTestServer()
    b.RunParallel(func(pb *testing.PB) {
        for pb.Next() {
            server.SubmitHash(ctx, randomValidRequest())
        }
    })
}
```

**Estimativa:** 1 dia

---

### P2.5 — Trocar Badge Estático por Badge Dinâmico do GitHub Actions

**Problema:**  
Badge "build-passing" no README é estático e não reflete o CI real.

**Solução:**

```markdown
<!-- README.md -->
<!-- REMOVER: -->
<img src="https://img.shields.io/badge/build-passing-brightgreen" alt="Build">

<!-- ADICIONAR: -->
[![CI](https://github.com/had-nu/gleipnir/actions/workflows/ci.yml/badge.svg?branch=main)](https://github.com/had-nu/gleipnir/actions/workflows/ci.yml)
```

**Estimativa:** 5 minutos

---

## 5. CRONOGRAMA SUGERIDO

```
Sprint 1 (Semanas 1–2): P0 — Bloqueantes
├── Dia 1–2:  P0.1 Corrigir versões Go
├── Dia 3–6:  P0.2 Implementar verificação server-side de assinaturas
├── Dia 7–8:  P0.3 Adicionar BlockHash na resposta
└── Dia 9–10: Testes de integração end-to-end + revisão

Sprint 2 (Semanas 3–4): P1 — Segurança e Qualidade
├── Dia 1:    P1.1 gosec no CI
├── Dia 2:    P1.2 Expandir testes CI + coverage
├── Dia 3:    P1.3 Corrigir checkout@v4
├── Dia 4–6:  P1.4 SubmitResponse com status real + WaitForAnchor
└── Dia 7–10: P1.5 govulncheck + Dependabot + revisão

Sprint 3 (Semanas 5–6): P2 — Escalabilidade
├── Dia 1–2:  P2.1 StreamBlocks
├── Dia 3–6:  P2.2 SubChainManager gRPC
├── Dia 7:    P2.3 Fuzzing
├── Dia 8:    P2.4 Benchmarks
└── Dia 9–10: P2.5 Badge dinâmico + revisão final
```

---

## 6. CRITÉRIOS DE ACEITAÇÃO GLOBAIS

Antes de marcar qualquer item como DONE, todos os critérios abaixo devem ser atendidos (conforme VERIFICATION.md):

- [ ] **Commit range existe.** O PR descreve o range exato de commits.
- [ ] **Todo arquivo modificado está presente.** `git show <commit>:<path>` retorna o arquivo esperado.
- [ ] **Testes cobrem o caso adversarial.** Não apenas happy path.
- [ ] **CI output anexado.** URL do job do GitHub Actions, não terminal paste.
- [ ] **`go test -race ./...` passa.** Obrigatório para mudanças criptográficas/quorum.
- [ ] **Dead-code quarantine confirmada.** `grep` prova que código legado não é alcançável.
- [ ] **Verification ledger preenchido.** Cada entrada do spec de remediação tem referência real.

---

## 7. CHECKLIST DE IMPLEMENTAÇÃO

### P0
- [ ] P0.1 go.mod → `go 1.24`
- [ ] P0.1 Dockerfile → `golang:1.24-alpine`
- [ ] P0.1 ci.yml → `GO_VERSION: "1.24"`
- [ ] P0.2 `pkg/identity/registry.go` criado
- [ ] P0.2 `pkg/identity/signature.go` criado
- [ ] P0.2 `SubmitHash` verifica assinatura server-side
- [ ] P0.2 Testes de assinatura passam (6 cenários)
- [ ] P0.3 `api.proto` adiciona `block_hash`
- [ ] P0.3 `Block.ComputeHash()` implementado
- [ ] P0.3 `GetBlock` retorna BlockHash
- [ ] P0.3 Testes de encadeamento passam

### P1
- [ ] P1.1 Job `audit` no CI com gosec
- [ ] P1.1 SARIF upload configurado
- [ ] P1.2 `go test ./...` no CI
- [ ] P1.2 Coverage report publicado
- [ ] P1.3 `actions/checkout@v4` no job vet
- [ ] P1.4 `SubmitResponse` com status real
- [ ] P1.4 `WaitForAnchor` implementado
- [ ] P1.4 Testes de lifecycle passam
- [ ] P1.5 Job `vulncheck` no CI
- [ ] P1.5 `dependabot.yml` criado

### P2
- [ ] P2.1 `StreamBlocks` implementado
- [ ] P2.1 Testes de streaming passam
- [ ] P2.2 `RegisterSubChain` gRPC
- [ ] P2.2 `AnchorSubChain` gRPC
- [ ] P2.2 `VerifyCrossChain` gRPC
- [ ] P2.3 Fuzz tests adicionados
- [ ] P2.3 Job fuzz no CI
- [ ] P2.4 Benchmarks de consenso
- [ ] P2.4 Benchmarks de submit
- [ ] P2.5 Badge dinâmico no README

---

## 8. REFERÊNCIAS

1. Commit analisado: `f9c74d9d6854d85a8542c54cb27f1ae9f4196497`
2. Protocolo 3CP: https://github.com/had-nu/3CP
3. Go Version Policy: https://go.dev/doc/devel/release
4. Dilithium3 (CRYSTALS-Dilithium): https://pq-crystals.org/dilithium/
5. RFC 9381 (ECVRF): https://datatracker.ietf.org/doc/html/rfc9381
6. gosec: https://github.com/securego/gosec
7. govulncheck: https://pkg.go.dev/golang.org/x/vuln/cmd/govulncheck

---

*SPEC gerada em 2026-07-29 como resultado da análise automatizada do repositório had-nu/gleipnir.*

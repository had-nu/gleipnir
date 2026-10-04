# **SPEC-GLEIPNIR-GAPS-V2.1-PART2.md**
# Continuação: Light Client Service + Plano de Implementação

**Parte:** 2 de 2  
**Documento Principal:** SPEC-GLEIPNIR-GAPS-V2.1.md  
**Foco:** Light Client Service + Plano de Implementação Completo

---

# **🌐 GAP #3: LIGHT CLIENT SERVICE (Continuação)**

## **3.2 gRPC Service Definition**

### **3.2.1 `pkg/lightclient/api.proto` (NOVO ARQUIVO - ~150 linhas)**

```protobuf
syntax = "proto3";

package lightclient;

option go_package = "./pkg/lightclient";

// LightClientService - Operações de light client para verificação 3CP
service LightClient {
    // GetBlock - Obtém um bloco pelo índice
    rpc GetBlock(GetBlockRequest) returns (GetBlockResponse);
    
    // StreamBlocks - Stream de blocos a partir de um índice
    rpc StreamBlocks(StreamBlocksRequest) returns (stream Block);
    
    // GetValidatorSet - Obtém ValidatorSet para um ciclo
    rpc GetValidatorSet(GetValidatorSetRequest) returns (GetValidatorSetResponse);
    
    // GetMerkleProof - Obtém prova SMT
    rpc GetMerkleProof(GetMerkleProofRequest) returns (GetMerkleProofResponse);
    
    // VerifyBlock - Verifica um bloco
    rpc VerifyBlock(VerifyBlockRequest) returns (VerifyBlockResponse);
    
    // VerifyMerkleProof - Verifica uma prova SMT
    rpc VerifyMerkleProof(VerifyMerkleProofRequest) returns (VerifyMerkleProofResponse);
}

// Request/Response Messages

message GetBlockRequest {
    uint64 index = 1;
}

message GetBlockResponse {
    bytes block = 1;  // Block serializado em CBOR
}

message StreamBlocksRequest {
    uint64 start_index = 1;
    uint64 max_blocks = 2;  // Limite opcional
}

message GetValidatorSetRequest {
    uint64 cycle = 1;
}

message GetValidatorSetResponse {
    repeated ValidatorInfo validators = 1;
}

message GetMerkleProofRequest {
    bytes key = 1;      // 32 bytes
    uint64 block_index = 2;
}

message GetMerkleProofResponse {
    repeated bytes proof = 1;  // Array de 32-byte hashes
}

message VerifyBlockRequest {
    bytes block = 1;  // Block serializado em CBOR
}

message VerifyBlockResponse {
    bool valid = 1;
    string error = 2;  // Erro se inválido
}

message VerifyMerkleProofRequest {
    bytes key = 1;      // 32 bytes
    bytes value = 2;    // Valor correspondente
    bytes root = 3;     // 32 bytes - root da SMT
    repeated bytes proof = 4;  // Prova SMT
}

message VerifyMerkleProofResponse {
    bool valid = 1;
}

// Types

message ValidatorInfo {
    bytes validator_id = 1;      // 16 bytes
    bytes dilithium3_pk = 2;     // 1952 bytes
    bytes vrf_pk = 3;           // 32 bytes
    bytes contract_hash = 4;    // 32 bytes
}

message Block {
    uint64 index = 1;
    bytes prev_hash = 2;
    bytes state_root = 3;
    bytes proposer = 4;
    bytes block_hash = 5;
    bytes prepare_sigs_bitmap = 6;
    repeated bytes prepare_sigs = 7;
    bytes commit_sig = 8;
    repeated ValidatorInfo validators = 9;
    uint64 protocol_version = 10;
}
```

---

### **3.2.2 `pkg/lightclient/server.go` (NOVO ARQUIVO - ~200 linhas)**

```go
package lightclient

import (
    "context"
    "fmt"
    "net"
    "log"

    "google.golang.org/grpc"
    
    "github.com/had-nu/gleipnir/pkg/chain"
    "github.com/had-nu/gleipnir/pkg/consensus"
    "github.com/had-nu/gleipnir/pkg/storage"
    api "github.com/had-nu/gleipnir/pkg/lightclient" // Gerado pelo protoc
)

// Server - Implementa LightClientService gRPC
type Server struct {
    service *LightClientService
    api.UnimplementedLightClientServer
}

// NewServer - Cria novo servidor gRPC
func NewServer(engine *consensus.Engine, storage storage.EngineStorage) *Server {
    return &Server{
        service: NewLightClientService(engine, storage),
    }
}

// Start - Inicia servidor gRPC
func (s *Server) Start(addr string) error {
    lis, err := net.Listen("tcp", addr)
    if err != nil {
        return fmt.Errorf("failed to listen: %v", err)
    }
    
    grpcServer := grpc.NewServer()
    api.RegisterLightClientServer(grpcServer, s)
    
    log.Printf("Light Client gRPC server listening at %s", addr)
    return grpcServer.Serve(lis)
}

// GetBlock - Implementa GetBlock
func (s *Server) GetBlock(ctx context.Context, req *api.GetBlockRequest) (*api.GetBlockResponse, error) {
    block, err := s.service.GetBlock(ctx, req.Index)
    if err != nil {
        return nil, err
    }
    
    blockBytes, err := chain.MarshalCBOR(block)
    if err != nil {
        return nil, err
    }
    
    return &api.GetBlockResponse{Block: blockBytes}, nil
}

// StreamBlocks - Implementa StreamBlocks
func (s *Server) StreamBlocks(req *api.StreamBlocksRequest, stream api.LightClient_StreamBlocksServer) error {
    blockCh, err := s.service.StreamBlocks(stream.Context(), req.StartIndex)
    if err != nil {
        return err
    }
    
    for block := range blockCh {
        blockBytes, err := chain.MarshalCBOR(block)
        if err != nil {
            return err
        }
        
        if err := stream.Send(&api.Block{Data: blockBytes}); err != nil {
            return err
        }
    }
    return nil
}

// GetValidatorSet - Implementa GetValidatorSet
func (s *Server) GetValidatorSet(ctx context.Context, req *api.GetValidatorSetRequest) (*api.GetValidatorSetResponse, error) {
    validators, err := s.service.GetValidatorSet(ctx, req.Cycle)
    if err != nil {
        return nil, err
    }
    
    resp := &api.GetValidatorSetResponse{}
    for _, v := range validators {
        resp.Validators = append(resp.Validators, &api.ValidatorInfo{
            ValidatorId: v.ValidatorID[:],
            Dilithium3Pk: v.Dilithium3PK[:],
            VrfPk: v.VRFPK[:],
            ContractHash: v.ContractHash[:],
        })
    }
    return resp, nil
}

// GetMerkleProof - Implementa GetMerkleProof
func (s *Server) GetMerkleProof(ctx context.Context, req *api.GetMerkleProofRequest) (*api.GetMerkleProofResponse, error) {
    var key [32]byte
    copy(key[:], req.Key)
    
    proof, err := s.service.GetMerkleProof(ctx, key, req.BlockIndex)
    if err != nil {
        return nil, err
    }
    
    resp := &api.GetMerkleProofResponse{}
    for _, p := range proof {
        resp.Proof = append(resp.Proof, p[:])
    }
    return resp, nil
}

// VerifyBlock - Implementa VerifyBlock
func (s *Server) VerifyBlock(ctx context.Context, req *api.VerifyBlockRequest) (*api.VerifyBlockResponse, error) {
    var block chain.Block
    if err := chain.UnmarshalCBOR(req.Block, &block); err != nil {
        return nil, err
    }
    
    err := s.service.VerifyBlock(ctx, &block)
    if err != nil {
        return &api.VerifyBlockResponse{Valid: false, Error: err.Error()}, nil
    }
    
    return &api.VerifyBlockResponse{Valid: true}, nil
}

// VerifyMerkleProof - Implementa VerifyMerkleProof
func (s *Server) VerifyMerkleProof(ctx context.Context, req *api.VerifyMerkleProofRequest) (*api.VerifyMerkleProofResponse, error) {
    var key, root [32]byte
    copy(key[:], req.Key)
    copy(root[:], req.Root)
    
    var proof [][32]byte
    for i := 0; i < len(req.Proof); i += 32 {
        var p [32]byte
        copy(p[:], req.Proof[i:i+32])
        proof = append(proof, p)
    }
    
    valid := s.service.VerifyMerkleProof(key, req.Value, root, proof)
    return &api.VerifyMerkleProofResponse{Valid: valid}, nil
}
```

---

### **3.2.3 `pkg/lightclient/rest.go` (NOVO ARQUIVO - ~150 linhas - OPCIONAL)**

```go
package lightclient

import (
    "encoding/json"
    "net/http"
    "strconv"
    
    "github.com/gorilla/mux"
)

// RESTServer - API REST para light client
type RESTServer struct {
    service *LightClientService
}

// NewRESTServer - Cria novo servidor REST
func NewRESTServer(service *LightClientService) *RESTServer {
    return &RESTServer{service: service}
}

// RegisterRoutes - Registra rotas
func (s *RESTServer) RegisterRoutes(r *mux.Router) {
    r.HandleFunc("/api/v1/blocks/{index}", s.getBlockHandler).Methods("GET")
    r.HandleFunc("/api/v1/blocks", s.streamBlocksHandler).Methods("GET")
    r.HandleFunc("/api/v1/validatorset/{cycle}", s.getValidatorSetHandler).Methods("GET")
    r.HandleFunc("/api/v1/merkleproof", s.getMerkleProofHandler).Methods("GET")
    r.HandleFunc("/api/v1/verify/block", s.verifyBlockHandler).Methods("POST")
    r.HandleFunc("/api/v1/verify/merkleproof", s.verifyMerkleProofHandler).Methods("POST")
}

func (s *RESTServer) getBlockHandler(w http.ResponseWriter, r *http.Request) {
    vars := mux.Vars(r)
    index, err := strconv.ParseUint(vars["index"], 10, 64)
    if err != nil {
        http.Error(w, "invalid block index", http.StatusBadRequest)
        return
    }
    
    block, err := s.service.GetBlock(r.Context(), index)
    if err != nil {
        http.Error(w, err.Error(), http.StatusNotFound)
        return
    }
    
    blockBytes, _ := chain.MarshalCBOR(block)
    w.Header().Set("Content-Type", "application/cbor")
    w.Write(blockBytes)
}

func (s *RESTServer) verifyBlockHandler(w http.ResponseWriter, r *http.Request) {
    var req struct {
        Block []byte `json:"block"` // CBOR encoded
    }
    if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
        http.Error(w, err.Error(), http.StatusBadRequest)
        return
    }
    
    var block chain.Block
    if err := chain.UnmarshalCBOR(req.Block, &block); err != nil {
        http.Error(w, err.Error(), http.StatusBadRequest)
        return
    }
    
    err := s.service.VerifyBlock(r.Context(), &block)
    if err != nil {
        http.Error(w, err.Error(), http.StatusBadRequest)
        return
    }
    
    w.Write([]byte(`{"valid": true}`))
}
```

---

### **3.2.4 Integração com Provenanced**

**Modificações em `cmd/provenanced/main.go`:**

```go
// Adicionar flags
var (
    lightClientAddr string
    lightClientRESTAddr string
)

func init() {
    flag.StringVar(&lightClientAddr, "lightclient-addr", ":50051", "Light client gRPC server address")
    flag.StringVar(&lightClientRESTAddr, "lightclient-rest-addr", "", "Light client REST server address (optional)")
}

func main() {
    // ... código existente ...
    
    // Inicializar light client server
    if lightClientAddr != "" {
        lightClientService := lightclient.NewLightClientService(engine, storage)
        lightClientServer := lightclient.NewServer(lightClientService)
        
        go func() {
            if err := lightClientServer.Start(lightClientAddr); err != nil {
                log.Fatalf("Light client gRPC server failed: %v", err)
            }
        }()
        
        log.Printf("Light client gRPC server started at %s", lightClientAddr)
    }
    
    // Inicializar REST server (opcional)
    if lightClientRESTAddr != "" {
        restServer := lightclient.NewRESTServer(lightClientService)
        router := mux.NewRouter()
        restServer.RegisterRoutes(router)
        
        go func() {
            log.Printf("Light client REST server started at %s", lightClientRESTAddr)
            log.Fatal(http.ListenAndServe(lightClientRESTAddr, router))
        }()
    }
    
    // ... resto do código ...
}
```

---

### **3.2.5 Testes (TC-ZK-01)**

**`pkg/lightclient/service_test.go` (NOVO ARQUIVO - ~250 linhas)**

```go
func TestLightClientVerification(t *testing.T) {
    engine := getTestEngine()
    service := NewLightClientService(engine, nil)
    
    // Teste 1: GetBlock
    t.Run("GetBlock", func(t *testing.T) {
        block := getTestBlock()
        retrieved, err := service.GetBlock(context.Background(), block.Index)
        assert.NoError(t, err)
        assert.Equal(t, block.Index, retrieved.Index)
    })
    
    // Teste 2: GetValidatorSet
    t.Run("GetValidatorSet", func(t *testing.T) {
        block := getTestBlock()
        validators, err := service.GetValidatorSet(context.Background(), block.Index)
        assert.NoError(t, err)
        assert.Len(t, validators, len(block.Validators))
    })
    
    // Teste 3: VerifyBlock - válido
    t.Run("VerifyBlockValid", func(t *testing.T) {
        block := getTestBlock()
        err := service.VerifyBlock(context.Background(), block)
        assert.NoError(t, err)
    })
    
    // Teste 4: VerifyBlock - assinatura inválida
    t.Run("VerifyBlockInvalidSignature", func(t *testing.T) {
        block := getTestBlock()
        block.CommitSig = [2700]byte{0x00}
        err := service.VerifyBlock(context.Background(), block)
        assert.Error(t, err)
        assert.Contains(t, err.Error(), "COMMIT signature")
    })
    
    // Teste 5: VerifyBlock - quorum insuficiente
    t.Run("VerifyBlockInsufficientQuorum", func(t *testing.T) {
        block := getTestBlock()
        block.PrepareSigs = [][]byte{}
        err := service.VerifyBlock(context.Background(), block)
        assert.Error(t, err)
        assert.Contains(t, err.Error(), "quorum")
    })
    
    // Teste 6: VerifyBlock - PrevHash inválido
    t.Run("VerifyBlockInvalidPrevHash", func(t *testing.T) {
        block := getTestBlock()
        block.PrevHash = [32]byte{0x00}
        err := service.VerifyBlock(context.Background(), block)
        assert.Error(t, err)
        assert.Contains(t, err.Error(), "PrevHash")
    })
    
    // Teste 7: GetMerkleProof
    t.Run("GetMerkleProof", func(t *testing.T) {
        key := [32]byte{0x01, 0x02, 0x03}
        proof, err := service.GetMerkleProof(context.Background(), key, 0)
        assert.NoError(t, err)
        assert.NotEmpty(t, proof)
    })
    
    // Teste 8: VerifyMerkleProof
    t.Run("VerifyMerkleProof", func(t *testing.T) {
        key := [32]byte{0x01, 0x02, 0x03}
        value := []byte("test value")
        
        engine.st.Insert(key[:], value)
        root := engine.st.Root()
        proof, _ := engine.st.Prove(key[:])
        
        valid := service.VerifyMerkleProof(key, value, root, proof)
        assert.True(t, valid)
    })
}

// TC-ZK-01: Prova SMT verificável por light client
func TestSMTProofVerifiableByLightClient(t *testing.T) {
    engine := getTestEngine()
    service := NewLightClientService(engine, nil)
    
    entry := chain.ProvenanceEntry{
        Hash: [32]byte{0x01, 0x02, 0x03},
        Submitter: [16]byte{0x01},
        Timestamp: time.Now().UnixNano(),
        Label: "test:entry",
    }
    
    engine.st.Insert(entry.Hash[:], entry.Hash[:])
    root := engine.st.Root()
    
    proof, err := service.GetMerkleProof(context.Background(), entry.Hash, engine.Cycle())
    assert.NoError(t, err)
    
    valid := service.VerifyMerkleProof(entry.Hash, entry.Hash[:], root, proof)
    assert.True(t, valid)
}
```

---

# **📊 PLANO DE IMPLEMENTAÇÃO COMPLETO**

## **🎯 Priorização e Cronograma**

### **Fase 1: Key Rotation (2-3 dias) - PRIORIDADE CRÍTICA**

| Dia | Tarefa | Arquivos | Linhas | Status |
|-----|--------|---------|-------|--------|
| 1 | Infraestrutura básica | `key_rotation.go`, `key_rotation_validator.go` | ~350 | ⬜ |
| 1 | Integração no Engine | `engine.go` (modificações) | ~50 | ⬜ |
| 2 | Validação das 5 regras | `key_rotation.go` (Validate) | ~100 | ⬜ |
| 2 | Overlap period handling | `key_rotation_validator.go` (GetActivePublicKey) | ~50 | ⬜ |
| 2 | Endpoint gRPC | `api.proto`, `api.pb.go` | ~120 | ⬜ |
| 3 | Testes (TC-ROT-01, TC-ROT-02) | `key_rotation_test.go` | ~250 | ⬜ |
| 3 | Integração final | Testes de integração | ~50 | ⬜ |

**Total Fase 1:** ~970 linhas | **2-3 dias**

---

### **Fase 2: Mandate Compliance (3-5 dias) - PRIORIDADE ALTA**

| Dia | Tarefa | Arquivos | Linhas | Status |
|-----|--------|---------|-------|--------|
| 1 | Mandate Resolver | `mandate_resolver.go` | ~150 | ⬜ |
| 1-2 | Mandate Validator | `mandate_validator.go` | ~200 | ⬜ |
| 2-3 | Compliance Checker | `compliance_checker.go` | ~300 | ⬜ |
| 3 | Integração no Engine | `engine.go` (Enqueue) | ~30 | ⬜ |
| 4 | Endpoints gRPC | `api.proto`, `api.pb.go` | ~100 | ⬜ |
| 4-5 | Implementação endpoints | `server.go` (modificações) | ~100 | ⬜ |
| 5 | Testes | `compliance_test.go` | ~300 | ⬜ |

**Total Fase 2:** ~1,180 linhas | **3-5 dias**

---

### **Fase 3: Light Client Service (2-3 dias) - PRIORIDADE MÉDIA**

| Dia | Tarefa | Arquivos | Linhas | Status |
|-----|--------|---------|-------|--------|
| 1 | Light Client Service | `service.go` | ~300 | ⬜ |
| 1 | Protobuf definition | `api.proto` | ~150 | ⬜ |
| 2 | gRPC Server | `server.go` | ~200 | ⬜ |
| 2 | Integração com provenanced | `main.go` (modificações) | ~20 | ⬜ |
| 3 | REST API (opcional) | `rest.go` | ~150 | ⬜ |
| 3 | Testes (TC-ZK-01) | `service_test.go` | ~250 | ⬜ |

**Total Fase 3:** ~1,070 linhas | **2-3 dias**

---

## **📈 Métricas de Sucesso**

### **Após Cada Fase:**

| Fase | Compliance | Funcionalidades Habilitadas |
|------|------------|-------------------------------|
| **Base (Atual)** | ~92% | Criptografia, Consenso, SMT, Anchor Publishers |
| **Fase 1 (Key Rotation)** | ~95% | ✅ Rotação de chaves sem downtime |
| **Fase 2 (Mandate Compliance)** | ~98% | ✅ Validação de mandatos, Detecção de omissões |
| **Fase 3 (Light Client)** | **100%** | ✅ Verificação por terceiros |

---

## **🎯 Checklist de Entrega**

### **🔐 Key Rotation (Gap #1)**
- [ ] `pkg/chain/key_rotation.go` - Tipo KeyRotationEntry
- [ ] `pkg/validation/key_rotation.go` - Validador com 5 regras
- [ ] `pkg/consensus/engine.go` - Integração (processKeyRotationEntries, verifySignatureWithOverlap)
- [ ] `pkg/server/api.proto` - Endpoint SubmitKeyRotation
- [ ] `pkg/server/api.pb.go` - Implementação do endpoint
- [ ] `pkg/validation/key_rotation_test.go` - Testes (TC-ROT-01, TC-ROT-02)
- [ ] Documentação atualizada

### **📜 Mandate Compliance (Gap #2)**
- [ ] `pkg/validation/mandate_resolver.go` - Resolver de mandatos
- [ ] `pkg/validation/mandate_validator.go` - Validador de mandatos
- [ ] `pkg/validation/compliance_checker.go` - Checker de conformidade
- [ ] `pkg/consensus/engine.go` - Integração no Enqueue
- [ ] `pkg/server/api.proto` - Endpoints CheckCompliance, GetActiveMandates
- [ ] `pkg/server/api.pb.go` - Implementação dos endpoints
- [ ] `pkg/validation/compliance_test.go` - Testes
- [ ] Documentação atualizada

### **🌐 Light Client Service (Gap #3)**
- [ ] `pkg/lightclient/service.go` - Serviço principal
- [ ] `pkg/lightclient/api.proto` - Definição protobuf
- [ ] `pkg/lightclient/server.go` - Servidor gRPC
- [ ] `cmd/provenanced/main.go` - Integração
- [ ] `pkg/lightclient/rest.go` - API REST (opcional)
- [ ] `pkg/lightclient/service_test.go` - Testes (TC-ZK-01)
- [ ] Documentação atualizada

---

## **🔧 Dependências e Pré-requisitos**

### **Dependências Externas (já existentes):**
```bash
# Verificar dependências
go list -m all | grep -E "cbor|blake3|circl|grpc|gorilla"
```

### **Ferramentas Necessárias:**
```bash
# Instalar protobuf compiler
go install google.golang.org/protobuf/cmd/protoc-gen-go@latest
go install google.golang.org/grpc/cmd/protoc-gen-go-grpc@latest

# Gerar código protobuf
protoc --go_out=. --go_opt=paths=source_relative \
    --go-grpc_out=. --go-grpc_opt=paths=source_relative \
    pkg/lightclient/api.proto pkg/server/api.proto
```

---

## **📋 Resumo de Arquivos e Linhas**

| Gap | Arquivos Novos | Arquivos Modificados | Total Linhas | Esforço |
|-----|----------------|---------------------|--------------|---------|
| **Key Rotation** | 4 | 2 | ~970 | 2-3 dias |
| **Mandate Compliance** | 4 | 3 | ~1,180 | 3-5 dias |
| **Light Client** | 5 | 2 | ~1,070 | 2-3 dias |
| **TOTAL** | **13** | **7** | **~3,220** | **5-10 dias** |

---

## **🎉 Conclusão**

**O Gleipnir está a apenas 5-10 dias de 100% compliance com 3CP v2.0.**

### **O que já está pronto (92% compliance):**
- ✅ **Todas as primitivas criptográficas** (Dilithium3, Kyber1024, VRF, BLAKE3, ChaCha20-Poly1305)
- ✅ **Wire format** (CBOR canonical, todos os campos v2.0)
- ✅ **Consenso BFT** (2-phase, VRF leader, quorum ceil(2N/3), degraded mode)
- ✅ **Sparse Merkle Tree** (depth 256, BLAKE3-256, proofs)
- ✅ **Anchor Publishers** (filesystem, IPFS, S3)
- ✅ **Adaptive Cycle** (EWMA RTT, SafetyFactor)
- ✅ **UID0 Identity** (HKDF-SHA256, NetworkID)
- ✅ **Laplacian λ₁** (incremental, Lanczos)

### **O que falta (8% compliance):**
1. **Key Rotation** (2-3 dias) - Rotação de chaves sem downtime
2. **Mandate Compliance** (3-5 dias) - **INOVAÇÃO PRIMÁRIA** - Detecção de omissões
3. **Light Client** (2-3 dias) - Verificação por terceiros

### **Próximos Passos:**
1. **Comece pelo Key Rotation** - É o mais simples e desbloqueia funcionalidade crítica
2. **Prossiga para Mandate Compliance** - Habilita a inovação principal do 3CP
3. **Finalize com Light Client** - Habilita verificação por terceiros

**Com esta spec, o OpenCode (ou você) tem todo o detalhamento técnico necessário para implementar os 3 gaps com precisão.**

---

## **📚 Documentação de Referência**

- **Especificação Principal:** `SPEC-3CP-V2.md` (3CP v2.0)
- **Compliance Report:** `gleipnir_compliance_report.md`
- **Este Documento:** `SPEC-GLEIPNIR-GAPS-V2.1.md` + `SPEC-GLEIPNIR-GAPS-V2.1-PART2.md`

---

**Documento gerado:** 2026-08-25  
**Autor:** Vibe Code (Mistral AI)  
**Status:** ✅ **Pronto para implementação com OpenCode**  
**Versão:** 2.1.0

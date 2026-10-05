# **SPEC-GLEIPNIR-GAPS-V2.1.md**
# Especificação para Fechamento de Gaps - Gleipnir 3CP v2.0

**Título:** Gleipnir Gap Closure Specification v2.1
**Status:** NORMATIVA (para implementação imediata)
**Versão:** 2.1.0
**Data:** 2026-08-25
**Base:** 3CP Protocol v2.0 (SPEC-3CP-V2.md) + Gleipnir Analysis
**Objetivo:** Fechar os 3 gaps críticos para 100% compliance com 3CP v2.0

---

## Sumário Executivo

Este documento define **especificações técnicas detalhadas** para implementar os 3 gaps críticos identificados no Gleipnir.

| Gap | Prioridade | Esforço Estimado | Status Alvo |
|-----|-----------|------------------|--------------|
| **Key Rotation Protocol** | CRÍTICA (#1) | 2-3 dias | 100% |
| **Mandate Compliance Verification** | ALTA (#2) | 3-5 dias | 100% |
| **Light Client Service** | MÉDIA (#3) | 2-3 dias | 100% |

**Total Estimado:** **5-10 dias** para 100% compliance

---

# GAP #1: KEY ROTATION PROTOCOL
**Prioridade: CRÍTICA | Esforço: 2-3 dias | Impacto: BLOCKING**

## **1.1 Arquivos a Criar/Modificar**

### **1.1.1 `pkg/chain/key_rotation.go` (NOVO - ~200 linhas)**

```go
// KeyRotationEntry - SPEC-3CP-V2.md §8.1
type KeyRotationEntry struct {
    Hash           [32]byte  `cbor:"0,keyasint"`
    Submitter      [16]byte  `cbor:"1,keyasint"`
    Timestamp      int64     `cbor:"2,keyasint"`
    Label          string    `cbor:"3,keyasint"` // "3cp:key-rotation:v1"
    NewPublicKey   [1952]byte `cbor:"20,keyasint"`
    NewVRFPublicKey [32]byte  `cbor:"21,keyasint"`
    EffectiveCycle  uint64    `cbor:"22,keyasint"`
    ExpiryCycle     uint64    `cbor:"23,keyasint"`
    SignatureOld    [3309]byte `cbor:"24,keyasint"`
    SignatureNew    [3309]byte `cbor:"25,keyasint"`
}

// NewKeyRotationEntry - Cria entrada com validação das 5 regras (SPEC §8.2)
func NewKeyRotationEntry(submitter [16]byte, currentDilithiumSK []byte,
    newDilithiumPK [1952]byte, newVRFPK [32]byte, newDilithiumSK []byte,
    effectiveCycle, expiryCycle, currentCycle uint64) (*KeyRotationEntry, error) {
    
    // Validar EffectiveCycle >= currentCycle + KeyRotationLeadTime (Regra 3)
    if effectiveCycle < currentCycle + 10 {
        return nil, validation.ErrKeyRotationLeadTime
    }
    
    // Validar ExpiryCycle >= EffectiveCycle + MinKeyOverlap (Regra 4)
    if expiryCycle < effectiveCycle + 10 {
        return nil, validation.ErrKeyRotationOverlap
    }
    
    // Criar payload para assinatura
    payload := KeyRotationPayload{submitter, newDilithiumPK, newVRFPK, effectiveCycle, expiryCycle}
    payloadBytes, _ := deterministicMode.Marshal(payload)
    
    // Assinar com chave antiga (Regra 1)
    sigOld := identity.SignDilithium(currentDilithiumSK, payloadBytes)
    
    // Assinar com chave nova (Regra 2)
    sigNew := identity.SignDilithium(newDilithiumSK, payloadBytes)
    
    // Calcular hash
    entry := KeyRotationEntry{...}
    entryBytes, _ := deterministicMode.Marshal(entry)
    entry.Hash = identity.Blake3Hash(entryBytes)
    
    return &entry, nil
}
```

---

### **1.1.2 `pkg/validation/key_rotation.go` (NOVO - ~150 linhas)**

```go
// KeyRotationValidator - Valida entradas de rotação de chaves
func (v *KeyRotationValidator) Validate(entry *chain.KeyRotationEntry) error {
    // Regra 1: SignatureOld verifica contra Dilithium3PK ativa do Submitter
    validatorInfo := v.findValidatorByID(entry.Submitter)
    if !identity.VerifyDilithium(validatorInfo.Dilithium3PK[:], payloadBytes, entry.SignatureOld[:]) {
        return validation.ErrKeyRotationInvalidOldSig
    }
    
    // Regra 2: SignatureNew verifica contra NewPublicKey
    if !identity.VerifyDilithium(entry.NewPublicKey[:], payloadBytes, entry.SignatureNew[:]) {
        return validation.ErrKeyRotationInvalidNewSig
    }
    
    // Regra 3: EffectiveCycle >= currentCycle + KeyRotationLeadTime
    minEffective := v.currentCycle + v.cfg.KeyRotationLeadTime
    if entry.EffectiveCycle < minEffective {
        return validation.ErrKeyRotationLeadTime
    }
    
    // Regra 4: ExpiryCycle >= EffectiveCycle + MinKeyOverlap
    minExpiry := entry.EffectiveCycle + v.cfg.MinKeyOverlap
    if entry.ExpiryCycle < minExpiry {
        return validation.ErrKeyRotationOverlap
    }
    
    // Regra 5: EffectiveCycle > lastRotationCycle do mesmo validador
    lastCycle, hasPrevious := v.getLastRotationCycle(entry.Submitter)
    if hasPrevious && entry.EffectiveCycle <= lastCycle {
        return validation.ErrKeyRotationDuplicate
    }
    
    return nil
}

// GetActivePublicKey - Retorna chave(s) ativa(s) para um validador em um ciclo
func (v *KeyRotationValidator) GetActivePublicKey(validatorID [16]byte, cycle uint64) ([][1952]byte, error) {
    // Durante [EffectiveCycle, ExpiryCycle], retornar ambas as chaves
    // Após ExpiryCycle, retornar apenas a nova
    // Antes de EffectiveCycle, retornar apenas a antiga
}
```

---

### **1.1.3 Modificações em `pkg/consensus/engine.go`**

```go
// Adicionar ao Engine struct
type Engine struct {
    keyRotationValidator *validation.KeyRotationValidator
    activeKeyRotations   map[[16]byte]*chain.KeyRotationEntry
}

// Modificar NewEngine
func newEngine(...) *Engine {
    eng := &Engine{
        keyRotationValidator: validation.NewKeyRotationValidator(&eng.state, 0, state.DefaultConfig),
        activeKeyRotations:   make(map[[16]byte]*chain.KeyRotationEntry),
        // ...
    }
}

// processKeyRotationEntries - Processa entradas de rotação pendentes
func (e *Engine) processKeyRotationEntries() {
    for _, entry := range e.pending {
        if entry.Label == "3cp:key-rotation:v1" {
            var krEntry chain.KeyRotationEntry
            if err := cbor.Unmarshal(entry.Hash[:], &krEntry); err == nil {
                if err := e.keyRotationValidator.Validate(&krEntry); err == nil {
                    e.activeKeyRotations[entry.Submitter] = &krEntry
                }
            }
        }
    }
}

// verifySignatureWithOverlap - Verifica assinatura considerando overlap
func (e *Engine) verifySignatureWithOverlap(validatorID [16]byte, msg []byte, sig []byte, cycle uint64) bool {
    activeKeys, _ := e.keyRotationValidator.GetActivePublicKey(validatorID, cycle)
    for _, pk := range activeKeys {
        if identity.VerifyDilithium(pk[:], msg, sig) {
            return true
        }
    }
    return false
}
```

---

### **1.1.4 Endpoint gRPC em `pkg/server/api.proto`**

```protobuf
message KeyRotationRequest {
    bytes new_dilithium_public_key = 1;  // 1952 bytes
    bytes new_vrf_public_key = 2;       // 32 bytes
    uint64 effective_cycle = 3;
    uint64 expiry_cycle = 4;
}

message KeyRotationResponse {
    bytes entry_hash = 1;
    string status = 2;     // "pending", "accepted", "rejected"
    string error = 3;
}

service Provenance {
    rpc SubmitKeyRotation(KeyRotationRequest) returns (KeyRotationResponse);
}
```

---

### **1.1.5 Implementação do Endpoint em Go**

```go
func (s *Server) SubmitKeyRotation(ctx context.Context, req *api.KeyRotationRequest) (*api.KeyRotationResponse, error) {
    // Validar sizes
    if len(req.NewDilithiumPublicKey) != 1952 {
        return nil, status.Errorf(codes.InvalidArgument, "invalid Dilithium3 public key size")
    }
    
    // Criar entrada
    entry, err := chain.NewKeyRotationEntry(
        s.engine.node.UID.RootID,
        s.engine.node.UID.SecretKey,
        [1952]byte(req.NewDilithiumPublicKey),
        [32]byte(req.NewVrfPublicKey),
        nil, // Nova SK
        req.EffectiveCycle,
        req.ExpiryCycle,
        s.engine.Cycle(),
    )
    
    // Validar
    if err := s.engine.keyRotationValidator.Validate(entry); err != nil {
        return &api.KeyRotationResponse{
            EntryHash: entry.Hash[:],
            Status:   "rejected",
            Error:    err.Error(),
        }, nil
    }
    
    // Submeter
    s.engine.Enqueue(chain.ProvenanceEntry{
        Hash:      entry.Hash,
        Submitter: entry.Submitter,
        Timestamp: entry.Timestamp,
        Label:     entry.Label,
    })
    
    return &api.KeyRotationResponse{
        EntryHash: entry.Hash[:],
        Status:   "pending",
    }, nil
}
```

---

### **1.1.6 Testes (TC-ROT-01, TC-ROT-02)**

```go
func TestKeyRotationValidation(t *testing.T) {
    validator := NewKeyRotationValidator(getTestState(), 100, state.DefaultConfig)
    
    // Teste 1: Assinatura antiga inválida
    t.Run("InvalidOldSignature", func(t *testing.T) {
        entry := &chain.KeyRotationEntry{
            SignatureOld: [3309]byte{0x00},
            SignatureNew: getValidSignature(),
        }
        err := validator.Validate(entry)
        assert.Equal(t, validation.ErrKeyRotationInvalidOldSig, err)
    })
    
    // Teste 2: EffectiveCycle muito cedo
    t.Run("EffectiveCycleTooEarly", func(t *testing.T) {
        entry := &chain.KeyRotationEntry{
            EffectiveCycle: 105, // current=100, LeadTime=10 → min=110
            ExpiryCycle: 120,
            SignatureOld: getValidSignature(),
            SignatureNew: getValidSignature(),
        }
        err := validator.Validate(entry)
        assert.Equal(t, validation.ErrKeyRotationLeadTime, err)
    })
}

// TC-ROT-01: Rotação válida - ambas as chaves aceitas no overlap
func TestKeyRotationOverlapPeriod(t *testing.T) {
    validator := NewKeyRotationValidator(getTestState(), 100, state.DefaultConfig)
    entry := getValidKeyRotationEntry()
    
    for cycle := entry.EffectiveCycle; cycle <= entry.ExpiryCycle; cycle++ {
        activeKeys, _ := validator.GetActivePublicKey(entry.Submitter, cycle)
        assert.Len(t, activeKeys, 2) // Ambas as chaves
    }
    
    activeKeys, _ := validator.GetActivePublicKey(entry.Submitter, entry.ExpiryCycle+1)
    assert.Len(t, activeKeys, 1) // Apenas nova
}

// TC-ROT-02: Rotação com EffectiveCycle cedo - rejeitada
func TestKeyRotationEarlyEffectiveCycle(t *testing.T) {
    validator := NewKeyRotationValidator(getTestState(), 100, state.DefaultConfig)
    entry := &chain.KeyRotationEntry{
        EffectiveCycle: 105, // Muito cedo
        ExpiryCycle: 120,
        SignatureOld: getValidSignature(),
        SignatureNew: getValidSignature(),
    }
    err := validator.Validate(entry)
    assert.Equal(t, validation.ErrKeyRotationLeadTime, err)
}
```

---

## GAP #2: MANDATE COMPLIANCE VERIFICATION
**Prioridade: ALTA | Esforço: 3-5 dias | Impacto: CORE INNOVATION**

## **2.1 Arquivos a Criar/Modificar**

### **2.1.1 `pkg/validation/mandate_resolver.go` (NOVO - ~150 linhas)**

```go
// MandateResolver - Resolve mandatos ativos em um timestamp
type MandateResolver struct {
    smt *smt.SparseMerkleTree
    state *state.NetworkState
    mandateCache map[[32]byte]*chain.MandateEntry
}

// GetActiveMandates - Retorna todos os mandatos ativos em um timestamp
func (r *MandateResolver) GetActiveMandates(timestamp int64) ([]*chain.MandateEntry, error) {
    var activeMandates []*chain.MandateEntry
    
    // Iterar sobre todos os blocos
    for _, block := range r.state.Blocks {
        for _, entry := range block.Anchored {
            if entry.Label == "3cp:mandate:v1" {
                var mandate chain.MandateEntry
                if err := cbor.Unmarshal(entry.Hash[:], &mandate); err == nil {
                    if mandate.ValidFrom <= timestamp && timestamp <= mandate.ValidUntil {
                        activeMandates = append(activeMandates, &mandate)
                    }
                }
            }
        }
    }
    return activeMandates, nil
}

// GetMandateByID - Obtém mandato pelo ID (hash)
func (r *MandateResolver) GetMandateByID(mandateID [32]byte) (*chain.MandateEntry, bool) {
    if mandate, ok := r.mandateCache[mandateID]; ok {
        return mandate, true
    }
    value, err := r.smt.Get(mandateID[:])
    if err != nil {
        return nil, false
    }
    var mandate chain.MandateEntry
    if err := cbor.Unmarshal(value, &mandate); err != nil {
        return nil, false
    }
    r.mandateCache[mandateID] = &mandate
    return &mandate, true
}
```

---

### **2.1.2 `pkg/validation/mandate_validator.go` (NOVO - ~200 linhas)**

```go
// MandateValidator - Valida entradas contra mandatos
type MandateValidator struct {
    resolver *MandateResolver
    state *state.NetworkState
}

// ValidateEntryAgainstMandates - Valida entrada contra mandatos ativos
func (v *MandateValidator) ValidateEntryAgainstMandates(
    entry *chain.ProvenanceEntry, cycle uint64, timestamp int64) error {
    
    // Se não tem MandateRef, não há validação
    if entry.MandateRef == nil {
        return nil
    }
    
    // Obter mandato
    mandate, ok := v.resolver.GetMandateByID(*entry.MandateRef)
    if !ok {
        return validation.ErrMandateNotFound
    }
    
    // Verificar se mandato está ativo
    if mandate.ValidFrom > timestamp || timestamp > mandate.ValidUntil {
        return validation.ErrMandateExpired
    }
    
    // Validar contra todas as regras
    for _, rule := range mandate.Rules {
        if err := v.validateRule(&rule, entry); err != nil {
            return err
        }
    }
    return nil
}

// validateRule - Valida entrada contra uma regra
func (v *MandateValidator) validateRule(rule *chain.Rule, entry *chain.ProvenanceEntry) error {
    // Regra: RequiredFields
    for _, field := range rule.RequiredFields {
        if !entryHasField(entry, field) {
            return fmt.Errorf("%w: missing field %s",
                validation.ErrMandateMissingRequiredField, field)
        }
    }
    return nil
}

// entryHasField - Verifica se entrada tem um campo
func entryHasField(entry *chain.ProvenanceEntry, field string) bool {
    switch field {
    case "Approver": return entry.Approver != nil
    case "Reference": return entry.Reference != nil
    case "Signature": return len(entry.Signature) > 0
    case "MandateRef": return entry.MandateRef != nil
    default: return true
    }
}
```

---

### **2.1.3 `pkg/validation/compliance_checker.go` (NOVO - ~300 linhas)**

```go
// ComplianceChecker - Verifica conformidade de mandatos
type ComplianceChecker struct {
    resolver *MandateResolver
    smt *smt.SparseMerkleTree
    state *state.NetworkState
}

// ComplianceReport - Relatório de conformidade
type ComplianceReport struct {
    MandateID     [32]byte
    MandateLabel  string
    CheckWindow   ComplianceWindow
    TotalExpected int
    TotalFound    int
    ComplianceRate float64
    Gaps          []ComplianceGap
    Timestamp     int64
}

type ComplianceWindow struct {
    StartTimestamp int64
    EndTimestamp   int64
    StartCycle     uint64
    EndCycle       uint64
}

type ComplianceGap struct {
    RuleIndex     int
    RuleLabel     string
    ExpectedEvent string
    ExpectedAt    int64
    Status        string // "missing", "late", "invalid_fields"
    MissingFields []string
}

// CheckCompliance - Verifica conformidade de um mandato em uma janela
func (c *ComplianceChecker) CheckCompliance(
    mandateID [32]byte, window ComplianceWindow) (*ComplianceReport, error) {
    
    mandate, ok := c.resolver.GetMandateByID(mandateID)
    if !ok {
        return nil, validation.ErrMandateNotFound
    }
    
    report := &ComplianceReport{
        MandateID: mandateID,
        MandateLabel: mandate.Label,
        CheckWindow: window,
        Timestamp: time.Now().UnixNano(),
    }
    
    // Para cada regra mandatória
    for i, rule := range mandate.Rules {
        if !rule.Mandatory {
            continue
        }
        
        expectedEvents := c.getExpectedEvents(&rule, window)
        report.TotalExpected += len(expectedEvents)
        
        for _, expected := range expectedEvents {
            if found := c.findMatchingEntry(&rule, expected, window); found {
                report.TotalFound++
            } else {
                report.Gaps = append(report.Gaps, ComplianceGap{
                    RuleIndex: i,
                    RuleLabel: rule.EventClass,
                    ExpectedEvent: expected.EventClass,
                    ExpectedAt: expected.Timestamp,
                    Status: "missing",
                    MissingFields: rule.RequiredFields,
                })
            }
        }
    }
    
    if report.TotalExpected > 0 {
        report.ComplianceRate = float64(report.TotalFound) / float64(report.TotalExpected)
    }
    
    return report, nil
}

// getExpectedEvents - Gera eventos esperados para uma regra
func (c *ComplianceChecker) getExpectedEvents(rule *chain.Rule, window ComplianceWindow) []ExpectedEvent {
    var events []ExpectedEvent
    startDay := time.Unix(window.StartTimestamp, 0).Truncate(24 * time.Hour)
    endDay := time.Unix(window.EndTimestamp, 0).Truncate(24 * time.Hour)
    
    for day := startDay; !day.After(endDay); day = day.Add(24 * time.Hour) {
        events = append(events, ExpectedEvent{
            EventClass: rule.EventClass,
            Timestamp: day.UnixNano(),
        })
    }
    return events
}

// findMatchingEntry - Busca entrada correspondente a evento esperado
func (c *ComplianceChecker) findMatchingEntry(rule *chain.Rule, expected ExpectedEvent, window ComplianceWindow) bool {
    for _, block := range c.state.Blocks {
        if block.Index < window.StartCycle || block.Index > window.EndCycle {
            continue
        }
        for _, entry := range block.Anchored {
            if entry.Label != rule.EventClass {
                continue
            }
            entryTime := time.Unix(0, entry.Timestamp)
            expectedTime := time.Unix(0, expected.Timestamp)
            if entryTime.Sub(expectedTime).Abs() > time.Hour {
                continue
            }
            if len(rule.RequiredFields) > 0 {
                allPresent := true
                for _, field := range rule.RequiredFields {
                    if !entryHasField(&entry, field) {
                        allPresent = false
                        break
                    }
                }
                if !allPresent {
                    continue
                }
            }
            return true
        }
    }
    return false
}
```

---

### **2.1.4 Modificações em `pkg/consensus/engine.go`**

```go
// Adicionar ao Engine struct
type Engine struct {
    mandateResolver *validation.MandateResolver
    mandateValidator *validation.MandateValidator
    complianceChecker *validation.ComplianceChecker
}

// Modificar NewEngine
func newEngine(...) *Engine {
    eng := &Engine{
        mandateResolver: validation.NewMandateResolver(eng.st, &eng.state),
        mandateValidator: validation.NewMandateValidator(eng.mandateResolver, &eng.state),
        complianceChecker: validation.NewComplianceChecker(eng.mandateResolver, eng.st, &eng.state),
        // ...
    }
}

// Modificar Enqueue para validar mandatos
func (e *Engine) Enqueue(entry chain.ProvenanceEntry) error {
    // ... validações existentes ...
    
    // Validar contra mandatos (SPEC-3CP-V2.md §15)
    if err := e.mandateValidator.ValidateEntryAgainstMandates(
        &entry, e.state.Cycle, entry.Timestamp); err != nil {
        return WrapValidationError(ErrCodeMandateValidation, "mandate validation failed", err)
    }
    
    // ... resto do código ...
}
```

---

### **2.1.5 Endpoints gRPC em `pkg/server/api.proto`**

```protobuf
message ComplianceCheckRequest {
    bytes mandate_id = 1;
    int64 start_timestamp = 2;
    int64 end_timestamp = 3;
}

message ComplianceGap {
    int32 rule_index = 1;
    string rule_label = 2;
    string expected_event = 3;
    int64 expected_at = 4;
    string status = 5;
    repeated string missing_fields = 6;
}

message ComplianceReport {
    bytes mandate_id = 1;
    string mandate_label = 2;
    int64 start_timestamp = 3;
    int64 end_timestamp = 4;
    int32 total_expected = 5;
    int32 total_found = 6;
    double compliance_rate = 7;
    repeated ComplianceGap gaps = 8;
    int64 timestamp = 9;
}

message GetActiveMandatesRequest {
    int64 timestamp = 1;
}

message GetActiveMandatesResponse {
    repeated bytes mandates = 1;  // MandateEntry serializados
}

service Provenance {
    rpc CheckCompliance(ComplianceCheckRequest) returns (ComplianceReport);
    rpc GetActiveMandates(GetActiveMandatesRequest) returns (GetActiveMandatesResponse);
    rpc GetMandate(GetMandateRequest) returns (bytes); // MandateEntry serializado
}

message GetMandateRequest {
    bytes mandate_id = 1;
}
```

---

### **2.1.6 Implementação dos Endpoints em Go**

```go
func (s *Server) CheckCompliance(ctx context.Context, req *api.ComplianceCheckRequest) (*api.ComplianceReport, error) {
    var mandateID [32]byte
    copy(mandateID[:], req.MandateId)
    
    report, err := s.engine.complianceChecker.CheckCompliance(
        mandateID,
        validation.ComplianceWindow{
            StartTimestamp: req.StartTimestamp,
            EndTimestamp: req.EndTimestamp,
        },
    )
    if err != nil {
        return nil, status.Errorf(codes.Internal, "compliance check failed: %v", err)
    }
    
    // Converter para protobuf
    resp := convertComplianceReportToProto(report)
    return resp, nil
}

func (s *Server) GetActiveMandates(ctx context.Context, req *api.GetActiveMandatesRequest) (*api.GetActiveMandatesResponse, error) {
    mandates, err := s.engine.mandateResolver.GetActiveMandates(req.Timestamp)
    if err != nil {
        return nil, status.Errorf(codes.Internal, "failed to get active mandates: %v", err)
    }
    
    resp := &api.GetActiveMandatesResponse{}
    for _, mandate := range mandates {
        mandateBytes, _ := deterministicMode.Marshal(mandate)
        resp.Mandates = append(resp.Mandates, mandateBytes)
    }
    return resp, nil
}
```

---

### **2.1.7 Testes**

```go
func TestMandateValidation(t *testing.T) {
    validator := NewMandateValidator(getTestResolver(), getTestState())
    
    // Teste: Entrada com MandateRef válido e todos os campos - deve passar
    t.Run("ValidMandateRefWithAllFields", func(t *testing.T) {
        approver := [16]byte{0x03}
        entry := chain.ProvenanceEntry{
            Hash: [32]byte{0x01},
            Submitter: [16]byte{0x02},
            Timestamp: 1500,
            Label: "release_gate",
            MandateRef: &[32]byte{0x01},
            Approver: &approver,
            Signature: []byte{0x01, 0x02, 0x03},
        }
        err := validator.ValidateEntryAgainstMandates(&entry, 100, 1500)
        assert.NoError(t, err)
    })
    
    // Teste: Campo obrigatório faltando - deve falhar
    t.Run("MissingRequiredField", func(t *testing.T) {
        entry := chain.ProvenanceEntry{
            Hash: [32]byte{0x01},
            Submitter: [16]byte{0x02},
            Timestamp: 1500,
            Label: "release_gate",
            MandateRef: &[32]byte{0x01},
            // Approver está faltando!
            Signature: []byte{0x01, 0x02, 0x03},
        }
        err := validator.ValidateEntryAgainstMandates(&entry, 100, 1500)
        assert.Error(t, err)
        assert.Contains(t, err.Error(), "missing field")
    })
}

func TestComplianceCheck(t *testing.T) {
    checker := NewComplianceChecker(getTestResolver(), getTestSMT(), getTestState())
    mandateID := [32]byte{0x01}
    
    report, err := checker.CheckCompliance(
        mandateID,
        validation.ComplianceWindow{
            StartTimestamp: 1000,
            EndTimestamp: 1000 + 24*int64(time.Hour),
        },
    )
    
    assert.NoError(t, err)
    assert.NotNil(t, report)
    
    // Se não houver entradas, deve reportar gaps
    if len(report.Gaps) > 0 {
        assert.Equal(t, "missing", report.Gaps[0].Status)
    }
}
```

---

## GAP #3: LIGHT CLIENT SERVICE
**Prioridade: MÉDIA | Esforço: 2-3 dias | Impacto: THIRD-PARTY VERIFICATION**

## **3.1 Arquivos a Criar/Modificar**

### **3.1.1 `pkg/lightclient/service.go` (NOVO - ~300 linhas)**

```go
// LightClientService - SPEC-3CP-V2.md §12.2
type LightClientService struct {
    engine *consensus.Engine
    storage storage.EngineStorage
    maxBlocks int
}

// GetBlock - Obtém bloco pelo índice
func (s *LightClientService) GetBlock(ctx context.Context, index uint64) (*chain.Block, error) {
    if block := s.engine.GetBlock(index); block != nil {
        return block, nil
    }
    if s.storage != nil {
        return s.storage.LoadBlock(ctx, index)
    }
    return nil, fmt.Errorf("block %d not found", index)
}

// StreamBlocks - Stream de blocos a partir de índice
func (s *LightClientService) StreamBlocks(ctx context.Context, startIndex uint64) (<-chan *chain.Block, error) {
    ch := make(chan *chain.Block, 100)
    go func() {
        defer close(ch)
        for i := startIndex; i < s.engine.BlockCount() && i <= startIndex+uint64(s.maxBlocks); i++ {
            select {
            case <-ctx.Done():
                return
            default:
                block, _ := s.GetBlock(ctx, i)
                if block != nil {
                    ch <- block
                }
            }
        }
    }()
    return ch, nil
}

// GetValidatorSet - Obtém ValidatorSet para um ciclo
func (s *LightClientService) GetValidatorSet(ctx context.Context, cycle uint64) ([]chain.ValidatorInfo, error) {
    block, err := s.GetBlock(ctx, cycle)
    if err != nil {
        return nil, err
    }
    return block.Validators, nil
}

// GetMerkleProof - Obtém prova SMT
func (s *LightClientService) GetMerkleProof(ctx context.Context, key [32]byte, blockIndex uint64) ([][32]byte, error) {
    block, err := s.GetBlock(ctx, blockIndex)
    if err != nil {
        return nil, err
    }
    proof, err := s.engine.st.Prove(key[:])
    if err != nil {
        return nil, err
    }
    return proof, nil
}

// VerifyBlock - Verifica bloco (SPEC-3CP-V2.md §12.2)
// 1. Obtém ValidatorSet do ciclo
// 2. Verifica quorum de PREPARE
// 3. Verifica COMMIT signature
// 4. Verifica cadeia de PrevHash
func (s *LightClientService) VerifyBlock(ctx context.Context, block *chain.Block) error {
    // Passo 1: ValidatorSet
    validators, err := s.GetValidatorSet(ctx, block.Index)
    if err != nil {
        return fmt.Errorf("failed to get validator set: %w", err)
    }
    
    // Passo 2: Quorum PREPARE
    if err := s.verifyPrepareQuorum(block, validators); err != nil {
        return fmt.Errorf("PREPARE quorum verification failed: %w", err)
    }
    
    // Passo 3: COMMIT signature
    if err := s.verifyCommitSignature(block, validators); err != nil {
        return fmt.Errorf("COMMIT signature verification failed: %w", err)
    }
    
    // Passo 4: Cadeia de PrevHash
    if err := s.verifyBlockChain(block); err != nil {
        return fmt.Errorf("block chain verification failed: %w", err)
    }
    
    return nil
}

// verifyPrepareQuorum - Verifica quorum de PREPARE
func (s *LightClientService) verifyPrepareQuorum(block *chain.Block, validators []chain.ValidatorInfo) error {
    requiredQuorum := (2*len(validators) + 2) / 3
    
    // Verificar degraded mode
    if block.Metadata != nil {
        if val, ok := block.Metadata["3cp:degraded-block"]; ok && string(val) == "true" {
            requiredQuorum = 1
        }
    }
    
    validCount := 0
    for i, validator := range validators {
        if i >= len(block.PrepareSigsBitmap)*8 {
            continue
        }
        if block.PrepareSigsBitmap[i/8]&(1<<(i%8)) == 0 {
            continue
        }
        
        sigIndex := countBitsBefore(block.PrepareSigsBitmap, i)
        if sigIndex >= len(block.PrepareSigs) {
            return errors.New("PrepareSigs index out of bounds")
        }
        
        if !identity.VerifyDilithium(
            validator.Dilithium3PK[:], block.BlockHash, block.PrepareSigs[sigIndex]) {
            return errors.New("invalid PREPARE signature")
        }
        validCount++
    }
    
    if validCount < requiredQuorum {
        return fmt.Errorf("quorum not met: got %d, need %d", validCount, requiredQuorum)
    }
    return nil
}

// verifyCommitSignature - Verifica COMMIT signature
func (s *LightClientService) verifyCommitSignature(block *chain.Block, validators []chain.ValidatorInfo) error {
    var leader *chain.ValidatorInfo
    for _, v := range validators {
        if v.ValidatorID == block.Proposer {
            leader = &v
            break
        }
    }
    if leader == nil {
        return fmt.Errorf("leader %x not found", block.Proposer)
    }
    
    if !identity.VerifyDilithium(leader.Dilithium3PK[:], block.BlockHash, block.CommitSig) {
        return errors.New("invalid COMMIT signature")
    }
    return nil
}

// verifyBlockChain - Verifica cadeia de PrevHash
func (s *LightClientService) verifyBlockChain(block *chain.Block) error {
    if block.Index == 0 {
        for _, b := range block.PrevHash {
            if b != 0 {
                return errors.New("genesis block PrevHash must be zeros")
            }
        }
        return nil
    }
    
    prevBlock, err := s.GetBlock(context.Background(), block.Index-1)
    if err != nil {
        return fmt.Errorf("failed to get previous block: %w", err)
    }
    
    if !bytes.Equal(block.PrevHash, prevBlock.BlockHash) {
        return errors.New("PrevHash does not match")
    }
    return nil
}

// VerifyMerkleProof - Verifica prova SMT (SPEC-3CP-V2.md §9.3)
func (s *LightClientService) VerifyMerkleProof(
    key [32]byte, value []byte, root [32]byte, proof [][32]byte) bool {
    lh := smt.LeafHash(key[:], value)
    current := lh
    for i := 0; i < len(proof); i++ {
        depth := 255 - len(proof) + i + 1
        b := smt.Path(key[:], depth)
        if b == 0 {
            current = smt.ParentHash(current, proof[i])
        } else {
            current = smt.ParentHash(proof[i], current)
        }
    }
    return current == root
}

func countBitsBefore(bitmap []byte, pos int) int {
    count := 0
    for i := 0; i < pos; i++ {
        if bitmap[i/8]&(1<<(i%8)) != 0 {
            count++
        }
    }
    return count
}
```

# **IMPLEMENTATION-GUIDE.md**
# Guia de Implementação - Fechamento dos 3 Gaps do Gleipnir

**Objetivo:** Implementar os 3 gaps críticos para 100% compliance com 3CP v2.0
**Documentação:** SPEC-GLEIPNIR-GAPS-V2.1.md + SPEC-GLEIPNIR-GAPS-V2.1-PART2.md
**Ferramenta:** OpenCode (ou desenvolvimento manual)
**Tempo Estimado:** 5-10 dias

---

# SUMÁRIO EXECUTIVO

## **O que fazer?**
Implementar 3 features que faltam no Gleipnir para alcançar **100% compliance com 3CP v2.0**:

| # | Gap | Prioridade | Esforço | Impacto |
|---|-----|-----------|---------|---------|
| 1 | **Key Rotation** | CRÍTICA | 2-3 dias | Validadores podem rotacionar chaves |
| 2 | **Mandate Compliance** | ALTA | 3-5 dias | **INOVAÇÃO PRIMÁRIA** - Detecção de omissões |
| 3 | **Light Client Service** | MÉDIA | 2-3 dias | Terceiros verificam blocos |

**Total:** ~3,220 linhas de código | **5-10 dias**

---

# COMO USAR ESTE GUIA

## **Estrutura dos Documentos**

```
/workspace/
├── SPEC-GLEIPNIR-GAPS-V2.1.md          # Especificação técnica detalhada (Parte 1)
│   ├── Gap #1: Key Rotation Protocol   # ~970 linhas de código
│   ├── Gap #2: Mandate Compliance      # ~1,180 linhas de código
│   └── Gap #3: Light Client Service    # ~1,070 linhas de código (início)
│
├── SPEC-GLEIPNIR-GAPS-V2.1-PART2.md    # Continuação (Parte 2)
│   └── Gap #3: Light Client Service    # ~1,070 linhas de código (conclusão)
│
├── gleipnir_compliance_report.md       # Relatório de compliance detalhado
│
└── IMPLEMENTATION-GUIDE.md            # Este documento - guia prático
```

## **Como Navegar**

1. **Para entender O QUE fazer:** Leia este guia (IMPLEMENTATION-GUIDE.md)
2. **Para saber COMO fazer:** Leia SPEC-GLEIPNIR-GAPS-V2.1.md (especificação técnica)
3. **Para ver o status atual:** Leia gleipnir_compliance_report.md

---

# PLANO DE AÇÃO RECOMENDADO

## **Opção A: Implementação Sequencial (Recomendado)**

### **Fase 1: Key Rotation (2-3 dias)**
```
Dia 1:
├── Criar pkg/chain/key_rotation.go (200 linhas)
├── Criar pkg/validation/key_rotation.go (150 linhas)
├── Modificar pkg/consensus/engine.go (50 linhas)
└── Testes básicos

Dia 2:
├── Implementar Validate() com 5 regras
├── Implementar GetActivePublicKey() com overlap
├── Adicionar endpoint gRPC SubmitKeyRotation
└── Gerar código protobuf

Dia 3:
├── Testes completos (TC-ROT-01, TC-ROT-02)
├── Integração final
└── Documentação
```

### **Fase 2: Mandate Compliance (3-5 dias)**
```
Dia 1-2:
├── Criar pkg/validation/mandate_resolver.go (150 linhas)
├── Criar pkg/validation/mandate_validator.go (200 linhas)
└── Testes de validação

Dia 3-4:
├── Criar pkg/validation/compliance_checker.go (300 linhas)
├── Modificar pkg/consensus/engine.go (Enqueue)
└── Adicionar endpoints gRPC

Dia 5:
├── Implementar endpoints
├── Testes completos
└── Documentação
```

### **Fase 3: Light Client Service (2-3 dias)**
```
Dia 1:
├── Criar pkg/lightclient/service.go (300 linhas)
├── Criar pkg/lightclient/api.proto (150 linhas)
└── Gerar código protobuf

Dia 2:
├── Criar pkg/lightclient/server.go (200 linhas)
├── Modificar cmd/provenanced/main.go (20 linhas)
└── Testes básicos

Dia 3:
├── Criar pkg/lightclient/rest.go (150 linhas - opcional)
├── Testes completos (TC-ZK-01)
└── Documentação
```

---

## **Opção B: Implementação Paralela (Se tiver equipe)**

```
Equipe 1 (2-3 dias):
├── Key Rotation (Gap #1)
└── Light Client Service (Gap #3)

Equipe 2 (3-5 dias):
└── Mandate Compliance (Gap #2)

Vantagem: Entrega mais rápida (3-5 dias totais)
Desvantagem: Requer coordenação entre equipes
```

---

# ESTRUTURA DE ARQUIVOS E DIRETÓRIOS

## **Arquivos Novos a Criar**

```
pkg/
├── chain/
│   └── key_rotation.go              # Gap #1 - Tipo KeyRotationEntry
│
├── validation/
│   ├── key_rotation.go              # Gap #1 - Validador de key rotation
│   ├── key_rotation_test.go         # Gap #1 - Testes
│   ├── mandate_resolver.go          # Gap #2 - Resolver de mandatos
│   ├── mandate_validator.go          # Gap #2 - Validador de mandatos
│   ├── compliance_checker.go         # Gap #2 - Checker de conformidade
│   └── compliance_test.go            # Gap #2 - Testes
│
└── lightclient/
    ├── service.go                    # Gap #3 - Serviço principal
    ├── api.proto                     # Gap #3 - Definição protobuf
    ├── server.go                     # Gap #3 - Servidor gRPC
    ├── rest.go                       # Gap #3 - API REST (opcional)
    └── service_test.go               # Gap #3 - Testes
```

## **Arquivos Existentes a Modificar**

```
pkg/
├── consensus/
│   └── engine.go                    # Adicionar: keyRotationValidator, mandateValidator, complianceChecker
│                                       # Modificar: NewEngine, Enqueue, processKeyRotationEntries
│
├── server/
│   ├── api.proto                    # Adicionar: endpoints de key rotation e mandate compliance
│   └── api.pb.go                    # Implementar: SubmitKeyRotation, CheckCompliance, GetActiveMandates
│
cmd/
└── provenanced/
    └── main.go                       # Adicionar: flags para light client server
```

---

# COMANDOS ÚTEIS

## **Gerar Código Protobuf**

```bash
# Instalar ferramentas (se não estiverem instaladas)
go install google.golang.org/protobuf/cmd/protoc-gen-go@latest
go install google.golang.org/grpc/cmd/protoc-gen-go-grpc@latest

# Gerar código para lightclient
cd ~/gleipnir
protoc --go_out=. --go_opt=paths=source_relative \
    --go-grpc_out=. --go-grpc_opt=paths=source_relative \
    pkg/lightclient/api.proto

# Gerar código para server (se modificado)
protoc --go_out=. --go_opt=paths=source_relative \
    --go-grpc_out=. --go-grpc_opt=paths=source_relative \
    pkg/server/api.proto
```

## **Verificar Dependências**

```bash
# Listar todas as dependências
go list -m all

# Verificar dependências específicas
go list -m all | grep -E "cbor|blake3|circl|grpc|gorilla"

# Atualizar dependências (se necessário)
go get -u github.com/fxamacker/cbor/v2
```

## **Compilar e Testar**

```bash
# Compilar todo o projeto
cd ~/gleipnir
go build ./...

# Executar testes específicos
go test ./pkg/validation/... -v
go test ./pkg/lightclient/... -v
go test ./pkg/chain/... -v

# Executar todos os testes
go test ./... -v
```

---

# CHECKLIST DE IMPLEMENTAÇÃO

## GAP #1: KEY ROTATION

### **Arquivos a Criar**
- [ ] `pkg/chain/key_rotation.go` (200 linhas)
  - [ ] Tipo `KeyRotationEntry` com todos os campos (SPEC §8.1)
  - [ ] Função `NewKeyRotationEntry()`
  - [ ] Tipo `KeyRotationPayload`
  
- [ ] `pkg/validation/key_rotation.go` (150 linhas)
  - [ ] Tipo `KeyRotationValidator`
  - [ ] Função `Validate()` com 5 regras (SPEC §8.2)
  - [ ] Função `GetActivePublicKey()` com overlap handling
  - [ ] Função `findValidatorByID()`
  - [ ] Função `getLastRotationCycle()`

### **Arquivos a Modificar**
- [ ] `pkg/consensus/engine.go`
  - [ ] Adicionar `keyRotationValidator` ao struct `Engine`
  - [ ] Adicionar `activeKeyRotations` ao struct `Engine`
  - [ ] Modificar `NewEngine()` para inicializar validador
  - [ ] Adicionar função `processKeyRotationEntries()`
  - [ ] Adicionar função `verifySignatureWithOverlap()`
  - [ ] Chamar `processKeyRotationEntries()` em `RunCycle()`

- [ ] `pkg/server/api.proto`
  - [ ] Adicionar `KeyRotationRequest` message
  - [ ] Adicionar `KeyRotationResponse` message
  - [ ] Adicionar `SubmitKeyRotation` RPC

- [ ] `pkg/server/api.pb.go` (gerado automaticamente)
  - [ ] Implementar `SubmitKeyRotation()`

### **Testes**
- [ ] `pkg/validation/key_rotation_test.go` (250 linhas)
  - [ ] `TestKeyRotationValidation()`
  - [ ] `TestKeyRotationOverlapPeriod()` (TC-ROT-01)
  - [ ] `TestKeyRotationEarlyEffectiveCycle()` (TC-ROT-02)

### **Documentação**
- [ ] Atualizar README.md com exemplo de key rotation
- [ ] Adicionar comentários no código

---

## GAP #2: MANDATE COMPLIANCE

### **Arquivos a Criar**
- [ ] `pkg/validation/mandate_resolver.go` (150 linhas)
  - [ ] Tipo `MandateResolver`
  - [ ] Função `GetActiveMandates()`
  - [ ] Função `GetMandateByID()`
  - [ ] Função `GetMandateByReference()`

- [ ] `pkg/validation/mandate_validator.go` (200 linhas)
  - [ ] Tipo `MandateValidator`
  - [ ] Função `ValidateEntryAgainstMandates()`
  - [ ] Função `validateRule()`
  - [ ] Função `entryHasField()`

- [ ] `pkg/validation/compliance_checker.go` (300 linhas)
  - [ ] Tipo `ComplianceChecker`
  - [ ] Tipo `ComplianceReport`
  - [ ] Tipo `ComplianceWindow`
  - [ ] Tipo `ComplianceGap`
  - [ ] Função `CheckCompliance()`
  - [ ] Função `getExpectedEvents()`
  - [ ] Função `findMatchingEntry()`

### **Arquivos a Modificar**
- [ ] `pkg/consensus/engine.go`
  - [ ] Adicionar `mandateResolver` ao struct `Engine`
  - [ ] Adicionar `mandateValidator` ao struct `Engine`
  - [ ] Adicionar `complianceChecker` ao struct `Engine`
  - [ ] Modificar `NewEngine()` para inicializar componentes
  - [ ] Modificar `Enqueue()` para validar mandatos

- [ ] `pkg/server/api.proto`
  - [ ] Adicionar `ComplianceCheckRequest` message
  - [ ] Adicionar `ComplianceGap` message
  - [ ] Adicionar `ComplianceReport` message
  - [ ] Adicionar `GetActiveMandatesRequest` message
  - [ ] Adicionar `GetActiveMandatesResponse` message
  - [ ] Adicionar `GetMandateRequest` message
  - [ ] Adicionar `CheckCompliance` RPC
  - [ ] Adicionar `GetActiveMandates` RPC
  - [ ] Adicionar `GetMandate` RPC

- [ ] `pkg/server/api.pb.go` (gerado automaticamente)
  - [ ] Implementar `CheckCompliance()`
  - [ ] Implementar `GetActiveMandates()`
  - [ ] Implementar `GetMandate()`

### **Testes**
- [ ] `pkg/validation/compliance_test.go` (300 linhas)
  - [ ] `TestMandateValidation()`
  - [ ] `TestComplianceCheck()`

### **Documentação**
- [ ] Atualizar README.md com exemplo de mandate compliance
- [ ] Adicionar comentários no código

---

## GAP #3: LIGHT CLIENT SERVICE

### **Arquivos a Criar**
- [ ] `pkg/lightclient/service.go` (300 linhas)
  - [ ] Tipo `LightClientService`
  - [ ] Função `GetBlock()`
  - [ ] Função `StreamBlocks()`
  - [ ] Função `GetValidatorSet()`
  - [ ] Função `GetMerkleProof()`
  - [ ] Função `VerifyBlock()`
  - [ ] Função `verifyPrepareQuorum()`
  - [ ] Função `verifyCommitSignature()`
  - [ ] Função `verifyBlockChain()`
  - [ ] Função `VerifyMerkleProof()`
  - [ ] Função `countBitsBefore()`

- [ ] `pkg/lightclient/api.proto` (150 linhas)
  - [ ] Definir package e options
  - [ ] Definir service `LightClient`
  - [ ] Definir todas as messages (request/response)
  - [ ] Definir todos os RPCs

- [ ] `pkg/lightclient/server.go` (200 linhas)
  - [ ] Tipo `Server`
  - [ ] Função `NewServer()`
  - [ ] Função `Start()`
  - [ ] Implementar todos os métodos gRPC

- [ ] `pkg/lightclient/rest.go` (150 linhas - OPCIONAL)
  - [ ] Tipo `RESTServer`
  - [ ] Função `NewRESTServer()`
  - [ ] Função `RegisterRoutes()`
  - [ ] Implementar handlers HTTP

### **Arquivos a Modificar**
- [ ] `cmd/provenanced/main.go`
  - [ ] Adicionar flags `lightClientAddr` e `lightClientRESTAddr`
  - [ ] Adicionar inicialização do light client server
  - [ ] Adicionar inicialização do REST server (opcional)

### **Testes**
- [ ] `pkg/lightclient/service_test.go` (250 linhas)
  - [ ] `TestLightClientVerification()`
  - [ ] `TestSMTProofVerifiableByLightClient()` (TC-ZK-01)

### **Documentação**
- [ ] Atualizar README.md com exemplo de light client
- [ ] Adicionar comentários no código

---

# MÉTRICAS DE PROGRESSO

## **Checklist Diário**

### **Manhã (Standup)**
- [ ] Revisar o que foi feito ontem
- [ ] Planejar o que fazer hoje
- [ ] Identificar bloqueios

### **Noite (Wrap-up)**
- [ ] Compilar o código
- [ ] Executar testes
- [ ] Fazer commit das mudanças
- [ ] Atualizar status no checklist

---

## **Acompanhamento de Progresso**

| Dia | Gap | Tarefa | Status | Linhas | Testes |
|-----|-----|--------|--------|--------|--------|
| 1 | #1 | Infraestrutura Key Rotation | | 350 | |
| 1 | #1 | Integração no Engine | | 50 | |
| 2 | #1 | Validação das 5 regras | | 100 | |
| 2 | #1 | Endpoint gRPC | | 120 | |
| 3 | #1 | Testes | | 250 | |
| 1-2 | #2 | Mandate Resolver + Validator | | 350 | |
| 3-4 | #2 | Compliance Checker | | 300 | |
| 4 | #2 | Endpoints gRPC | | 100 | |
| 5 | #2 | Testes | | 300 | |
| 1 | #3 | Light Client Service | | 300 | |
| 2 | #3 | Protobuf + gRPC Server | | 350 | |
| 3 | #3 | Integração + Testes | | 400 | |

---

# DICAS E MELHORES PRÁTICAS

## **Dicas de Implementação**

### **1. Comece Pequeno**
- Implemente uma função de cada vez
- Teste cada função individualmente
- Integre apenas quando tudo estiver funcionando

### **2. Use o Código Existente**
O Gleipnir já tem **tudo o que você precisa**:
- `identity.VerifyDilithium()` - Verificação de assinaturas
- `smt.Prove()` e `smt.Verify()` - Provas SMT
- `chain.MarshalCBOR()` e `chain.UnmarshalCBOR()` - Serialização
- `engine.GetBlock()` - Acesso a blocos

### **3. Siga a Especificação**
- **SPEC-3CP-V2.md** é a fonte da verdade
- **SPEC-GLEIPNIR-GAPS-V2.1.md** tem o código exato a implementar
- Se tiver dúvida, pergunte: "O que o SPEC diz?"

### **4. Testes são Essenciais**
- Escreva testes **enquanto** implementa
- Use os testes de conformidade do SPEC (§16)
- TC-ROT-01, TC-ROT-02, TC-ZK-01 são **obrigatórios**

### **5. Documentação é Parte do Código**
- Adicione comentários explicando o **porquê**, não o **como**
- Atualize o README.md com exemplos de uso
- Documente as decisões de design

---

## **Boas Práticas de Código**

### **1. Nomenclatura**
- Use nomes **descritivos**: `ValidateKeyRotationEntry` em vez de `Validate`
- Use **camelCase** para funções e variáveis
- Use **PascalCase** para tipos

### **2. Tratamento de Erros**
- Retorne erros **específicos** (use os erros definidos em `pkg/validation/errors_v2.go`)
- Não ignore erros
- Use `fmt.Errorf("context: %w", err)` para wrap de erros

### **3. Concorrência**
- Use `sync.Mutex` para acesso concorrente
- Evite race conditions
- Use `context.Context` para cancelamento

### **4. Performance**
- Evite alocações desnecessárias
- Use slices pré-alocados quando possível
- Cache resultados quando apropriado

---

# SOLUÇÃO DE PROBLEMAS COMUNS

## **Problema: "Undefined: deterministicMode"**

**Solução:** Adicione ao `init()` do pacote:
```go
var deterministicMode cbor.EncMode

func init() {
    var err error
    deterministicMode, err = cbor.CanonicalEncOptions().EncMode()
    if err != nil {
        panic(fmt.Sprintf("failed to initialize CBOR: %v", err))
    }
}
```

## **Problema: "Cannot use ... as type"**

**Solução:** Verifique os tipos. Muitas vezes é um problema de conversão entre `[]byte` e `[N]byte`:
```go
// Errado
var pk []byte = validator.Dilithium3PK

// Certo
pk := validator.Dilithium3PK[:]
```

## **Problema: "Protobuf generation failed"**

**Solução:**
1. Verifique se o `protoc` está instalado
2. Verifique se os plugins Go estão instalados
3. Execute o comando de geração manualmente
4. Verifique se o arquivo `.proto` tem sintaxe correta

## **Problema: "Missing go.sum"**

**Solução:**
```bash
go mod tidy
go mod download
```

## **Problema: "Testes não passam"**

**Solução:**
1. Execute o teste com `-v` para ver detalhes
2. Verifique se as dependências estão corretas
3. Verifique se o código está seguindo a especificação
4. Debugue com `fmt.Println` ou `log.Printf`

---

# RECURSOS ADICIONAIS

## **Documentação de Referência**

1. **3CP v2.0 Specification:** https://github.com/had-nu/3CP (`spec/SPEC-3CP-V2.md`)
   - Todos os requisitos do protocolo
   - Seções relevantes: §4 (Criptografia), §5 (Blocos), §6 (Consenso), §8 (Key Rotation), §9 (SMT), §12 (Light Client), §15 (Mandates)

2. **Gleipnir Codebase:** https://github.com/had-nu/gleipnir
   - Código existente para referência
   - Arquivos importantes: `pkg/identity/`, `pkg/chain/`, `pkg/consensus/`, `pkg/smt/`

3. **Compliance Report:** `/workspace/gleipnir_compliance_report.md`
   - Análise detalhada do status atual
   - Identificação dos gaps

4. **Esta Spec:** `/workspace/SPEC-GLEIPNIR-GAPS-V2.1.md` + `PART2.md`
   - Especificação técnica para implementação
   - Código exemplo para cada gap

## **Links Úteis**

- **Go Documentation:** https://go.dev/doc/
- **gRPC Go:** https://grpc.io/docs/languages/go/
- **Protobuf:** https://developers.google.com/protocol-buffers
- **CBOR:** https://github.com/fxamacker/cbor
- **BLAKE3:** https://github.com/lucasjones/blake3

---

# CONCLUSÃO

**Você está a apenas 5-10 dias de 100% compliance com 3CP v2.0!**

### **O que você tem hoje:**
- Um dos **melhores protocolos de criptografia aplicada** do mundo
- **92% de compliance** com a especificação
- **Todas as partes difíceis** já implementadas (criptografia, consenso, SMT)

### **O que falta:**
- **3 features simples** que foram deixadas de lado
- **~3,220 linhas de código** (menos do que um único arquivo de spec!)
- **5-10 dias de desenvolvimento**

### **Como prosseguir:**
1. **Escolha um gap** (recomendação: Key Rotation)
2. **Abra a spec** (SPEC-GLEIPNIR-GAPS-V2.1.md)
3. **Implemente o código** (copie/cole/adapte os exemplos)
4. **Teste** (use os testes de conformidade)
5. **Repita** para os próximos gaps

**Com esta documentação, você tem TUDO o que precisa para fechar os 3 gaps com sucesso.**

---

**Boa sorte!**

**Documento gerado:** 2026-08-25  
**Autor:** Vibe Code (Mistral AI)  
**Status:**  **Pronto para uso com OpenCode**

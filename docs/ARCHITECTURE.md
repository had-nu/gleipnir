# Gleipnir IPC — Arquitetura do Sistema

## Visão Geral

**Gleipnir** é a implementação de referência do **IPC (Immutable Provenance Chain)** — uma rede de consenso leve, pós-quântica e sem tokens para ancoragem criptograficamente auditável de hashes de proveniência.

A chain roda inteiramente na infraestrutura do cliente, sem dependências externas: não utiliza blockchain público, nem tokens, nem mineração, nem serviços de terceiros.

## Componentes

A imagem Docker produz três binários a partir de uma mesma build:

| Binário | Função |
|---------|--------|
| `provenanced` | **Validador** — daemon que participa do consenso, mantém o estado da Sparse Merkle Tree (SMT), persiste a chain em BoltDB e expõe a API gRPC |
| `provectl` | **CLI** — cliente para submeter hashes, verificar entries, inicializar nós e inspecionar a chain |
| `pipeline-sim` | **Simulador de carga** — usado apenas em ambientes de teste para gerar tráfego de submissão contra os validadores |

## Topologia de Rede

### Produção (docker-compose.yml)

```
┌─ bootstrap ──────────────────────────────────────┐
│  Gera UID0 keys (Dilithium3 + Ristretto255 VRF)  │
│  para N validadores e salva em volume compartilhado│
└──────────────────────┬───────────────────────────┘
                       ↓
┌──────────────────────────────────────────────────┐
│                  ipc-net (bridge)                 │
│                                                    │
│  ┌──────────┐  ┌──────────┐  ┌──────────┐       │
│  │ val-1    │  │ val-2    │  │ val-3    │       │
│  │ gRPC:50051│←│ gRPC:50052│←│ gRPC:50053│  ... │
│  │ Met:9090 │  │ Met:9090 │  │ Met:9090 │       │
│  └────┬─────┘  └────┬─────┘  └────┬─────┘       │
│       │             │             │              │
│  ┌────┴─────┐  ┌────┴─────┐  ┌────┴─────┐       │
│  │ val-4    │  │ val-5    │  │          │       │
│  │ gRPC:50054│  │ gRPC:50055│  │          │       │
│  └──────────┘  └──────────┘  └──────────┘       │
└──────────────────────────────────────────────────┘
                       ↓
         ┌─────────────────────┐
         │ Prometheus + Grafana │ (opcional — profile "monitor")
         └─────────────────────┘
```

Cada validador:
- Executa o binário `provenanced` como entrypoint
- Carrega sua identidade UID0 a partir de um arquivo CBOR (`/uids/uid-<N>.cbor`)
- Conecta-se aos pares via gRPC (configurado via `IPC_PEERS`)
- Expõe porta gRPC (50051) para submissão de hashes
- Expõe porta de métricas (9090) para Prometheus

### Simulação (docker-compose.sim.yml)

```
                ┌──────────────────────┐
                │   Validadores (3/5)  │
                │  val-1  val-2  val-3 │
                └──────┬──────┬───────┘
                       │      │
    ┌──────────────────┤      ├──────────────────┐
    │                  │      │                  │
 ┌──┴──┐  ┌──┴──┐  ┌──┴──┐  ┌──┴──┐  ┌──┴──┐
 │sim-1│  │sim-2│  │sim-3│  │...  │  │sim-10│
 └─────┘  └─────┘  └─────┘  └─────┘  └─────┘
   Cada pipeline-sim envia hashes a cada 2s
   simulando pipelines CI/CD reais
```

Os containers `pipeline-sim` são **apenas para carga de teste** — não fazem parte da chain de produção. Cada simulador representa um pipeline CI/CD submetendo hashes de artefatos para ancoragem.

## Mecanismo de Consenso

Gleipnir implementa um consenso **sem líder fixo, sem forks, sem mineração e sem tokens**. Cada ciclo produz exatamente um bloco final.

### Fluxo por Ciclo

```
┌──────────┐    ┌──────────┐    ┌──────────┐
│ Peer 1   │    │ Peer 2   │    │ Peer 3   │
│ (VRF sk) │    │ (VRF sk) │    │ (VRF sk) │
└────┬─────┘    └────┬─────┘    └────┬─────┘
     │               │               │
     │  ── VRF Proof ──────────────► │
     │ ◄── VRF Proof ──────────────  │
     │  ── VRF Proof ───────────────►│
     │               │               │
     ▼               ▼               ▼
  Cada peer computa Gamma = VRF.Prove(cycle || stateRoot)
  Peer com menor Gamma vira PROPOSER
     │               │               │
     │ ◄── PROPOSER ──────────────── │
     │ ◄── (γ mínimo) ─────────────  │
     │               │               │
     ▼               ▼               ▼
  PROPOSER coleta hashes pendentes, monta o bloco,
  insere na SMT e transmite a proposta
     │               │               │
     │ ── PROPOSTA ────────────────► │
     │ ── (bloco + SMT root) ───────►│
     │               │               │
     ▼               ▼               ▼
  Cada peer insere as mesmas entries na SMT local,
  verifica se a raiz (stateRoot) é idêntica
     │               │               │
     │ ◄── CO-SIGN ───────────────── │
     │ ◄── Dilithium3 ─────────────  │
     │               │               │
     ▼               ▼               ▼
  Com M assinaturas (threshold configurável),
  o bloco é finalizado e persistido
```

### Detalhamento Técnico

1. **ECVRF Leader Election (RFC 9381)**
   - Cada peer computa `VRF.Prove(sk, cycle || stateRoot)` usando Ristretto255
   - O proof é gossipado e verificado contra a chave pública VRF de cada peer
   - O peer com o menor valor de Gamma (hash VRF) vence a rodada
   - Resiste a grinding: o resultado é imprevisível e verificável

2. **M-of-N Dilithium3 Quorum**
   - Configurável: `threshold ≤ N` (ex.: 3/3, 4/5)
   - O propositor coleta assinaturas Dilithium3 dos pares validadores
   - Cada par conta uma única vez (rejeita duplicate-signature attack)
   - Atingido o threshold, o bloco é finalizado

3. **Sparse Merkle Tree (Blake3)**
   - Profundidade configurável (default: 256)
   - O stateRoot é a raiz da SMT contendo todas as entries ancoradas
   - Cada peer replica localmente e verifica a raiz antes de co-assinar

4. **Instant Finality**
   - Um ciclo = um bloco = final
   - Sem forks, sem rollbacks, sem reorganização de chain

## Criptografia

| Componente | Algoritmo | Finalidade |
|------------|-----------|------------|
| Assinaturas | **Dilithium3** (ML-DSA-65) | M-of-N quorum, pós-quântico |
| KEM | **Kyber1024** (ML-KEM-1024) | Key encapsulation para canais cifrados entre pares |
| VRF | **Ristretto255** (RFC 9381) | Eleição de líder justa e verificável |
| Hash | **Blake3** | SMT, proofs, identificadores |
| AEAD | **ChaCha20-Poly1305** | Cifração dos canais de transporte |

## Sub-Chains

Cada serviço que deseja usar a IPC ganha sua própria sub-chain:

```
┌────────────────────────────────────────────┐
│              Parent Chain                   │
│  ┌─────┐ ┌─────┐ ┌─────┐ ┌─────┐ ┌─────┐ │
│  │ B#1 │ │ B#2 │ │ B#3 │ │ B#4 │ │ B#5 │ │
│  └──┬──┘ └──┬──┘ └──┬──┘ └──┬──┘ └──┬──┘ │
│     │       │       │       │       │     │
│     └───────┼───────┼───────┼───────┘     │
│             │       │       │              │
│  ┌──────────┴───────┴───────┴──────────┐  │
│  │   Cross-chain proofs (dual-Merkle)   │  │
│  └──────────────────────────────────────┘  │
└────────────────────────────────────────────┘
         ▲                    ▲
         │                    │
┌────────┴────────┐  ┌────────┴────────┐
│  Sub-chain      │  │  Sub-chain      │
│  (Service A)    │  │  (Service B)    │
│  ┌───┐ ┌───┐    │  │  ┌───┐ ┌───┐   │
│  │B#1│ │B#2│... │  │  │B#1│ │B#2│...│
│  └───┘ └───┘    │  │  └───┘ └───┘   │
└─────────────────┘  └─────────────────┘
```

- Cada sub-chain tem sua própria SMT isolada
- Periodicamente, a raiz da sub-chain é ancorada na parent chain
- As provas de âncora usam dual-Merkle proofs (uma prova na sub-chain + uma na parent chain)

## Persistência

- **BoltDB** (embedded key-value store)
- Estado persistido automaticamente em `Stop()` e `RunCycle()`
- Cada validador mantém seu próprio banco local (`/data/` no container)
- Sem dependência de banco externo

## API gRPC

| Método | Descrição |
|--------|-----------|
| `SubmitHash` | Submete um hash para ancoragem |
| `WaitForAnchor` | Bloqueia até o hash ser ancorado |
| `VerifyHash` | Verifica se um hash consta na chain |
| `GetCurrentStateRoot` | Retorna a raiz atual da SMT |
| `GetHealth` | Métricas de saúde do nó |
| `GetBlock` | Recupera um bloco pelo índice |
| `StreamBlocks` | Stream de blocos a partir de um intervalo |

## Monitoramento

- Cada validador expõe métricas Prometheus em `:9090/metrics`
- Laplacian λ₁ diffusion supervisiona a saúde da topologia via heartbeat latencies
- Opcional: Prometheus + Grafana para dashboards

## Identidade (UID0)

- Identidade determinística derivada do hash do contrato da empresa
- Vincula "este nó fala pelo contrato X" de forma verificável
- Chaves Dilithium3 + Ristretto255 VRF geradas no bootstrap e distribuídas via volume compartilhado (`/uids/`)

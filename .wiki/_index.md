---
title: gleipnir-ipc
summary: IPC (Immutable Provenance Chain) — Gleipnir reference implementation. Full protocol conformance testing with real-project pipeline scenarios.
tags: [ipc, provenance, blockchain, conformance, testing, integration]
updated: 2026-07-14
articles: 2
raw: 0
---

## Wiki

| Article | Summary |
|---------|---------|
| [[conformance-v1\|IPC Protocol Conformance — v1]] ([references/conformance-v1.md](wiki/references/conformance-v1.md)) | Original 12-test gap coverage (G1–G6) — deprecated by v2 |
| [[conformance-v2\|IPC Protocol Conformance — v2]] ([references/conformance-v2.md](wiki/references/conformance-v2.md)) | **Current.** 33-test full coverage including non-repudiation, chain integrity, and real-project pipeline scenarios (Masthead, Hashchain, Vigil, Compliance) |

## Integrations

| Project | Adapter | Status |
|---------|---------|--------|
| Masthead (HTTP scanner) | `integration.go` MastheadFinding | Tested via fixture (P1) |
| Hashchain (backup integrity) | `integration.go` HashchainRecord | Tested via fixture (P2) |
| Vigil (security event ledger) | `integration.go` SecurityEvent | Tested via fixture (P3) |
| Compliance-mappings | `integration.go` ComplianceMapping | Tested via fixture (P4) |

## Raw Sources

> No raw sources ingested yet.

## Inventory

> No inventory records.

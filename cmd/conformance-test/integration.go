// Integration adapters: types and fixtures mirroring real homelab projects.
// Each adapter shows the <50 lines of code needed to integrate any Go service with IPC.
package main

import (
	"crypto/sha256"
	"encoding/hex"
	"time"
)

// ── Masthead Adapter ──────────────────────────────────────────────────────
// Real project: /home/hadnu/workspace/homelab/masthead
// Output: JSON scan report with per-endpoint header findings.

type MastheadFinding struct {
	Path       string `json:"path"`
	Method     string `json:"method"`
	StatusCode int    `json:"status_code"`
	HeaderName string `json:"header_name"`
	Present    bool   `json:"present"`
	Severity   string `json:"severity"`
}

type MastheadScan struct {
	Target      string            `json:"target"`
	GeneratedAt string            `json:"generated_at"`
	Findings    []MastheadFinding `json:"findings"`
}

func mastheadFixture() MastheadScan {
	return MastheadScan{
		Target:      "https://app.example.com",
		GeneratedAt: time.Now().UTC().Format(time.RFC3339),
		Findings: []MastheadFinding{
			{Path: "/login", Method: "GET", StatusCode: 200, HeaderName: "Strict-Transport-Security", Present: false, Severity: "Critical"},
			{Path: "/login", Method: "GET", StatusCode: 200, HeaderName: "Content-Security-Policy", Present: false, Severity: "Critical"},
			{Path: "/login", Method: "GET", StatusCode: 200, HeaderName: "X-Frame-Options", Present: true, Severity: "High"},
			{Path: "/api/v1/health", Method: "GET", StatusCode: 200, HeaderName: "Strict-Transport-Security", Present: true, Severity: "Critical"},
			{Path: "/api/v1/health", Method: "GET", StatusCode: 200, HeaderName: "X-Content-Type-Options", Present: true, Severity: "High"},
		},
	}
}

// MastheadHash computes a deterministic hash for a finding (e.g., for IPC submission).
func (f MastheadFinding) Hash() []byte {
	h := sha256.New()
	h.Write([]byte(f.Path))
	h.Write([]byte(f.Method))
	h.Write([]byte(f.HeaderName))
	if f.Present {
		h.Write([]byte("present"))
	} else {
		h.Write([]byte("missing"))
	}
	return h.Sum(nil)
}

// ── Vigil Adapter ─────────────────────────────────────────────────────────
// Real project: /home/hadnu/workspace/homelab/vigil
// Types mirror internal/ledger/types.go

type SecurityEvent struct {
	ID        string `json:"id"`
	Timestamp string `json:"timestamp"`
	Source    string `json:"source"`
	EventType string `json:"event_type"`
	FindingID string `json:"finding_id"`
	Reason    string `json:"reason,omitempty"`
	Actor     string `json:"actor,omitempty"`
	PrevHash  string `json:"prev_hash"`
	Hash      string `json:"hash"`
}

func ComputeVigilHash(e SecurityEvent) string {
	h := sha256.New()
	h.Write([]byte(e.ID))
	h.Write([]byte(e.Timestamp))
	h.Write([]byte(e.Source))
	h.Write([]byte(e.EventType))
	h.Write([]byte(e.FindingID))
	h.Write([]byte(e.Reason))
	h.Write([]byte(e.Actor))
	h.Write([]byte(e.PrevHash))
	return hex.EncodeToString(h.Sum(nil))
}

func vigilEventFixture(prevHash string) SecurityEvent {
	e := SecurityEvent{
		ID:        "evt-001",
		Timestamp: time.Now().UTC().Format(time.RFC3339),
		Source:    "masthead",
		EventType: "finding",
		FindingID: "f-001",
		Reason:    "HSTS missing on /login — critical severity",
		Actor:     "security-bot",
		PrevHash:  prevHash,
	}
	e.Hash = ComputeVigilHash(e)
	return e
}

// ── Hashchain Adapter ────────────────────────────────────────────────────
// Real project: /home/hadnu/workspace/homelab/hashchain
// Types mirror internal/storage Record.

type HashchainRecord struct {
	ID        int    `json:"id"`
	Filepath  string `json:"filepath"`
	DataHash  string `json:"data_hash"`
	ChainHash string `json:"chain_hash"`
	Timestamp string `json:"timestamp"`
}

func hashchainFixture() []HashchainRecord {
	return []HashchainRecord{
		{ID: 1, Filepath: "/data/postgres/db_dump.sql", DataHash: "a1b2c3d4e5f6...", ChainHash: "abc123...", Timestamp: time.Now().UTC().Format(time.RFC3339)},
		{ID: 2, Filepath: "/data/config/app.yaml", DataHash: "f6e5d4c3b2a1...", ChainHash: "def456...", Timestamp: time.Now().UTC().Format(time.RFC3339)},
	}
}

// ── Compliance-Mappings Adapter ──────────────────────────────────────────
// Real project: /home/hadnu/workspace/homelab/compliance-mappings
// Schema: schemas/mapping-v1.0.0.json

type ComplianceMapping struct {
	Framework         string            `json:"framework"`
	FrameworkRevision string            `json:"framework_revision"`
	ControlID         string            `json:"control_id"`
	ControlName       string            `json:"control_name"`
	Rationale         string            `json:"rationale"`
	SeverityModifier  map[string]int    `json:"severity_modifier"`
}

var complianceFixtures = []ComplianceMapping{
	{
		Framework: "ISO27001", FrameworkRevision: "2022",
		ControlID: "A.8.24", ControlName: "Use of cryptography",
		Rationale:        "HSTS enforces TLS, required by cryptographic controls",
		SeverityModifier: map[string]int{"authentication": 1, "payment": 1},
	},
	{
		Framework: "NIS2", FrameworkRevision: "directive_2022_2555",
		ControlID: "ART.21.2.h", ControlName: "Cryptography and encryption",
		Rationale:        "Missing HSTS undermines encryption in transit",
		SeverityModifier: map[string]int{"authentication": 1},
	},
	{
		Framework: "DORA", FrameworkRevision: "regulation_2022_2554",
		ControlID: "ART.9", ControlName: "Protection and prevention",
		Rationale:        "Security header gaps reduce ICT protection posture",
		SeverityModifier: map[string]int{"api": 1},
	},
}

// ── Sub-chain Adapter ─────────────────────────────────────────────────────
// Demonstrates the sub-chain concept: a local SMT + periodic anchoring.
// Uses the real smt package for the local SMT.

type SubChainEntry struct {
	ID        string `json:"id"`
	Payload   []byte `json:"payload"`
	StateRoot []byte `json:"state_root"`
}

func subChainFixture() []SubChainEntry {
	return []SubChainEntry{
		{ID: "svc-deploy-001", Payload: []byte("deploy: app v2.3.1 to staging")},
		{ID: "svc-deploy-002", Payload: []byte("deploy: app v2.3.1 to production")},
	}
}



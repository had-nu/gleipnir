package state

import (
	"bytes"
	"math/rand"
	"testing"

	"github.com/fxamacker/cbor/v2"
)

func TestStateSerialization(t *testing.T) {
	s := NetworkState{
		Cycle: 1,
		Nodes: map[string]NodeState{
			"010203": {
				UID:    []byte{1, 2, 3},
				Status: 1.0,
			},
		},
		Graph: ReputationGraph{
			Edges: []Edge{
				{From: "010203", To: "010203", Weight: 1.0},
			},
		},
	}

	root1 := ComputeSupervisionRoot(s)
	s.SupervisionRoot = root1

	root2 := ComputeSupervisionRoot(s)
	if !bytes.Equal(root1, root2) {
		t.Errorf("StateRoot calculation is not deterministic")
	}
}

func TestApplyWithHeartbeat(t *testing.T) {
	s0 := NetworkState{
		Cycle: 0,
		Nodes: map[string]NodeState{
			"aa": {UID: []byte{0xaa}, Status: 1.0, JoinCycle: 0},
			"bb": {UID: []byte{0xbb}, Status: 1.0, JoinCycle: 0},
			"cc": {UID: []byte{0xcc}, Status: 1.0, JoinCycle: 0},
		},
		Graph: ReputationGraph{
			Edges: []Edge{
				{From: "aa", To: "bb", Weight: 0.5},
				{From: "bb", To: "cc", Weight: 0.5},
				{From: "cc", To: "aa", Weight: 0.5},
			},
		},
	}
	s0.SupervisionRoot = ComputeSupervisionRoot(s0)

	heartbeats := []string{"aa", "bb"}
	s1, err := Apply(s0, s0.SupervisionRoot, heartbeats, DefaultConfig)
	if err != nil {
		t.Fatalf("Apply failed: %v", err)
	}

	if s1.Cycle != 1 {
		t.Errorf("Expected cycle 1, got %d", s1.Cycle)
	}

	if s1.Nodes["aa"].Consecutive != 1 {
		t.Errorf("Expected consecutive 1 for aa, got %d", s1.Nodes["aa"].Consecutive)
	}

	if s1.Nodes["cc"].Consecutive != 0 {
		t.Errorf("Expected consecutive 0 for cc (no heartbeat), got %d", s1.Nodes["cc"].Consecutive)
	}

	if s1.Nodes["cc"].Status >= 1.0 {
		t.Errorf("Expected cc status to decay, got %f", s1.Nodes["cc"].Status)
	}

	if s1.Lambda1 <= 0 {
		t.Errorf("Expected positive Lambda1 for connected graph, got %f", s1.Lambda1)
	}
}

func TestApplyChainBroken(t *testing.T) {
	s0 := NetworkState{
		Cycle: 1,
		Nodes: map[string]NodeState{
			"aa": {UID: []byte{0xaa}, Status: 1.0, JoinCycle: 0},
		},
		Graph: ReputationGraph{
			Edges: []Edge{{From: "aa", To: "aa", Weight: 1.0}},
		},
	}
	s0.SupervisionRoot = ComputeSupervisionRoot(s0)

	_, err := Apply(s0, []byte("wrong-prev-root"), nil, DefaultConfig)
	if err != ErrChainBroken {
		t.Fatalf("expected ErrChainBroken for mismatched prevRoot, got %v", err)
	}
}

func TestApplyChainBrokenNilPrevRoot(t *testing.T) {
	s0 := NetworkState{
		Cycle: 0,
		Nodes: map[string]NodeState{
			"aa": {UID: []byte{0xaa}, Status: 1.0, JoinCycle: 0},
			"bb": {UID: []byte{0xbb}, Status: 1.0, JoinCycle: 0},
			"cc": {UID: []byte{0xcc}, Status: 1.0, JoinCycle: 0},
		},
		Graph: ReputationGraph{
			Edges: []Edge{
				{From: "aa", To: "bb", Weight: 0.5},
				{From: "bb", To: "cc", Weight: 0.5},
				{From: "cc", To: "aa", Weight: 0.5},
			},
		},
	}
	s0.SupervisionRoot = ComputeSupervisionRoot(s0)

	s1, err := Apply(s0, nil, []string{"aa"}, DefaultConfig)
	if err != nil {
		t.Fatalf("Apply with nil prevRoot on cycle 0 should pass: %v", err)
	}
	if s1.Cycle != 1 {
		t.Fatalf("expected cycle 1, got %d", s1.Cycle)
	}
}

func TestApplyNetworkFragmented(t *testing.T) {
	s0 := NetworkState{
		Cycle: 0,
		Nodes: map[string]NodeState{
			"a1": {UID: []byte{0xa1}, Status: 1.0, JoinCycle: 0},
			"b1": {UID: []byte{0xb1}, Status: 1.0, JoinCycle: 0},
			"x1": {UID: []byte{0xc1}, Status: 1.0, JoinCycle: 0},
		},
		Graph: ReputationGraph{
			Edges: []Edge{
				{From: "a1", To: "b1", Weight: 1.0},
			},
		},
	}
	s0.SupervisionRoot = ComputeSupervisionRoot(s0) // disconnected: a1-b1, x1 isolated → λ₁ = 0

	_, err := Apply(s0, s0.SupervisionRoot, []string{"a1", "b1", "x1"}, DefaultConfig)
	if err != ErrNetworkFragmented {
		t.Fatalf("expected ErrNetworkFragmented for disconnected graph, got %v", err)
	}
}

// GLP-T-A04 — CBOR canonical encoding stability.
// Confirm that NetworkState CBOR-encodes identically regardless of
// map insertion order.
func TestCBORCanonicalEncoding(t *testing.T) {
	em, _ := cbor.CanonicalEncOptions().EncMode()

	// Build two states with same data but different insertion order
	s1 := NetworkState{
		Cycle: 10,
		Nodes: map[string]NodeState{
			"zulu": {UID: []byte{0x99}, Status: 0.5},
			"alfa": {UID: []byte{0x01}, Status: 1.0},
		},
		Graph: ReputationGraph{
			Edges: []Edge{
				{From: "alfa", To: "zulu", Weight: 0.8},
			},
		},
	}

	s2 := NetworkState{
		Cycle: 10,
		Nodes: map[string]NodeState{
			"alfa": {UID: []byte{0x01}, Status: 1.0},
			"zulu": {UID: []byte{0x99}, Status: 0.5},
		},
		Graph: ReputationGraph{
			Edges: []Edge{
				{From: "alfa", To: "zulu", Weight: 0.8},
			},
		},
	}

	d1, err := em.Marshal(s1)
	if err != nil {
		t.Fatal(err)
	}
	d2, err := em.Marshal(s2)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(d1, d2) {
		t.Fatal("CBOR encoding differs despite identical data (map insertion order leak)")
	}

	// Round-trip: unmarshal and re-marshal
	var s3 NetworkState
	if err := cbor.Unmarshal(d1, &s3); err != nil {
		t.Fatal(err)
	}
	d3, _ := em.Marshal(s3)
	if !bytes.Equal(d1, d3) {
		t.Fatal("CBOR round-trip produced different encoding")
	}

	// Shuffle nodes map keys and verify stability
	keys := make([]string, 0, len(s1.Nodes))
	for k := range s1.Nodes {
		keys = append(keys, k)
	}
	for i := 0; i < 10; i++ {
		// Reorder
		for j := range keys {
			k2 := rand.Intn(len(keys))
			keys[j], keys[k2] = keys[k2], keys[j]
		}
		shuffled := NetworkState{
			Cycle: s1.Cycle,
			Nodes: make(map[string]NodeState),
			Graph: s1.Graph,
		}
		for _, k := range keys {
			shuffled.Nodes[k] = s1.Nodes[k]
		}
		d, _ := em.Marshal(shuffled)
		if !bytes.Equal(d1, d) {
			t.Fatal("CBOR encoding changed after reordering map keys")
		}
	}
}

package state

import (
	"bytes"
	"testing"
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

	root1 := ComputeStateRoot(s)
	s.StateRoot = root1

	root2 := ComputeStateRoot(s)
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
	s0.StateRoot = ComputeStateRoot(s0)

	heartbeats := []string{"aa", "bb"}
	s1, err := Apply(s0, s0.StateRoot, heartbeats, DefaultConfig)
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

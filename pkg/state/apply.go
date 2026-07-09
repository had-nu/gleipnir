package state

import (
	"bytes"
	"errors"
)

var (
	ErrChainBroken       = errors.New("chain broken: previous hash does not match state root")
	ErrNetworkFragmented = errors.New("network fragmented: lambda1 below threshold")
)

func Apply(s NetworkState, prevRoot []byte, heartbeats []string, cfg Config) (NetworkState, error) {
	if s.Cycle > 0 && !bytes.Equal(prevRoot, s.StateRoot) {
		return NetworkState{}, ErrChainBroken
	}

	newNodes := make(map[string]NodeState)
	for uid, node := range s.Nodes {
		hb := false
		for _, h := range heartbeats {
			if uid == h {
				hb = true
				break
			}
		}
		if hb {
			node.Consecutive++
			node.Status = 1.0
		} else {
			node.Consecutive = 0
			node.Status -= cfg.DecayRate
			if node.Status < 0 {
				node.Status = 0
			}
		}
		newNodes[uid] = node
	}

	newGraph := s.Graph

	l := BuildLaplacian(newGraph, newNodes)
	lambda1 := ComputeLambda1(l)

	next := NetworkState{
		Cycle:   s.Cycle + 1,
		Nodes:   newNodes,
		Graph:   newGraph,
		Lambda1: lambda1,
	}
	next.StateRoot = ComputeStateRoot(next)

	return next, nil
}

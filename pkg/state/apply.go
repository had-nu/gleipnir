// IPC state transition (heartbeat diffusion).
package state

import (
	"bytes"
	"errors"
)

var (
	ErrChainBroken       = errors.New("IPC chain broken: previous hash does not match state root")
	ErrNetworkFragmented = errors.New("IPC network fragmented: lambda1 below threshold")
)

func Apply(s NetworkState, prevRoot []byte, heartbeats []string, cfg Config) (NetworkState, error) {
	if s.Cycle > 0 && !bytes.Equal(prevRoot, s.SupervisionRoot) {
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
	nextCycle := s.Cycle + 1

	lambda1 := s.Lambda1
	recompute := cfg.LambdaInterval == 0 || s.Lambda1 == 0 || nextCycle%cfg.LambdaInterval == 0
	if recompute {
		l := BuildLaplacian(newGraph, newNodes)
		lambda1 = ComputeLambda1(l)
	}

	if lambda1 < cfg.MinLambda1 {
		return NetworkState{}, ErrNetworkFragmented
	}

	next := NetworkState{
		Cycle:   nextCycle,
		Nodes:   newNodes,
		Graph:   newGraph,
		Lambda1: lambda1,
	}
	next.SupervisionRoot = ComputeSupervisionRoot(next)

	return next, nil
}

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

// Apply applies the state transition for a new cycle.
// It uses the provided IncrementalLaplacian for efficient λ₁ computation.
func Apply(s NetworkState, prevRoot [32]byte, heartbeats []string, cfg Config, laplacian *IncrementalLaplacian) (NetworkState, error) {
	if s.Cycle > 0 && !bytes.Equal(prevRoot[:], s.SupervisionRoot[:]) {
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

	// Check if graph structure changed (nodes or edges added/removed)
	graphChanged := len(newNodes) != len(s.Nodes) || len(newGraph.Edges) != len(s.Graph.Edges)
	if !graphChanged {
		// Check for edge weight changes
		for i := range newGraph.Edges {
			if newGraph.Edges[i].Weight != s.Graph.Edges[i].Weight {
				graphChanged = true
				break
			}
		}
	}

	lambda1 := s.Lambda1
	recompute := cfg.LambdaInterval == 0 || s.Lambda1 == 0 || nextCycle%cfg.LambdaInterval == 0

	if graphChanged {
		laplacian.MarkDirty()
		recompute = true
	}

	if recompute {
		lambda1, _ = laplacian.Compute(NetworkState{
			Nodes: newNodes,
			Graph: newGraph,
		})
	}

	if len(newNodes) >= 2 && lambda1 < cfg.MinLambda1 {
		return NetworkState{}, ErrNetworkFragmented
	}

	next := NetworkState{
		Cycle:           nextCycle,
		Nodes:           newNodes,
		Graph:           newGraph,
		Lambda1:         lambda1,
		ActiveMandates:  s.ActiveMandates,
		ValidatorSet:    s.ValidatorSet,
	}
	next.SupervisionRoot = ComputeSupervisionRoot(next)

	return next, nil
}

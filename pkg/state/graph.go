// IPC Laplacian graph — eigenvalue supervision.
package state

import (
	"gonum.org/v1/gonum/mat"
)

func BuildLaplacian(graph ReputationGraph, nodes map[string]NodeState) *mat.SymDense {
	n := len(nodes)
	if n < 2 {
		return nil
	}

	uids := make([]string, 0, n)
	indexMap := make(map[string]int)
	for uid := range nodes {
		indexMap[uid] = len(uids)
		uids = append(uids, uid)
	}

	w := mat.NewDense(n, n, nil)
	for _, edge := range graph.Edges {
		i, ok1 := indexMap[edge.From]
		j, ok2 := indexMap[edge.To]
		if ok1 && ok2 {
			w.Set(i, j, edge.Weight)
			w.Set(j, i, edge.Weight)
		}
	}

	l := mat.NewSymDense(n, nil)
	for i := 0; i < n; i++ {
		degree := 0.0
		for j := 0; j < n; j++ {
			if i != j {
				weight := w.At(i, j)
				degree += weight
				l.SetSym(i, j, -weight)
			}
		}
		l.SetSym(i, i, degree)
	}

	return l
}

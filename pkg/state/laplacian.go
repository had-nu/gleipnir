// Incremental Laplacian for λ₁ computation with caching.
// Only recomputes Cholesky factorization when graph topology changes.
package state

import (
	"fmt"
	"math"

	"gonum.org/v1/gonum/mat"
)

// IncrementalLaplacian computes λ₁ (Fiedler eigenvalue) efficiently
// by caching Cholesky factorization of (L + μI) and only recomputing
// when the graph topology changes.
type IncrementalLaplacian struct {
	// Cached state
	laplacian     *mat.SymDense    // Current Laplacian matrix
	cholFact      *mat.Cholesky    // Cached Cholesky of (L + μI)
	shift         float64          // Shift parameter μ
	nodeOrder     []string         // Current node ordering
	nodeIndices   map[string]int   // UID -> index map
	isDirty       bool             // Whether graph changed since last compute
	opts          Lambda1Options   // Power iteration options
	lastLambda1   float64          // Cached λ₁ value
	lastGraphHash string           // Hash of graph structure for change detection
}

// NewIncrementalLaplacian creates a new IncrementalLaplacian with given options.
func NewIncrementalLaplacian(opts Lambda1Options) *IncrementalLaplacian {
	if opts.MaxIter <= 0 {
		opts.MaxIter = 300
	}
	if opts.Tolerance <= 0 {
		opts.Tolerance = 1e-8
	}
	if opts.Shift <= 0 {
		opts.Shift = 1e-2
	}
	return &IncrementalLaplacian{
		opts: opts,
	}
}

// DefaultIncrementalLaplacian returns a new IncrementalLaplacian with default options.
func DefaultIncrementalLaplacian() *IncrementalLaplacian {
	return NewIncrementalLaplacian(DefaultLambda1Options())
}

// MarkDirty marks the Laplacian as needing recomputation.
func (il *IncrementalLaplacian) MarkDirty() {
	il.isDirty = true
	il.cholFact = nil
}

// Compute computes λ₁ for the given network state.
// Uses cached factorization if graph hasn't changed.
func (il *IncrementalLaplacian) Compute(state NetworkState) (float64, error) {
	if len(state.Nodes) < 2 {
		il.lastLambda1 = 0
		return 0, nil
	}

	// Check if graph structure changed
	graphHash := hashGraphStructure(state.Graph.Edges, state.Nodes)
	if graphHash == il.lastGraphHash && !il.isDirty && il.cholFact != nil {
		// Graph unchanged, but we still need to check if nodes changed
		// For now, we recompute if dirty or first time
		il.lastLambda1 = il.computeLambda1FromCache(state)
		return il.lastLambda1, nil
	}

	// Build Laplacian with consistent node ordering
	l, order := BuildLaplacianWithOrder(state.Graph, state.Nodes)

	// Update cache
	il.laplacian = l
	il.nodeOrder = order
	il.nodeIndices = make(map[string]int, len(order))
	for i, uid := range order {
		il.nodeIndices[uid] = i
	}
	il.shift = il.opts.Shift
	il.isDirty = false
	il.lastGraphHash = graphHash

	// Factorize (L + μI)
	shifted := mat.NewSymDense(l.SymmetricDim(), nil)
	for i := 0; i < l.SymmetricDim(); i++ {
		for j := i; j < l.SymmetricDim(); j++ {
			v := l.At(i, j)
			if i == j {
				v += il.shift
			}
			shifted.SetSym(i, j, v)
		}
	}

	var cholFact mat.Cholesky
	if ok := cholFact.Factorize(shifted); !ok {
		return 0, fmt.Errorf("Cholesky factorization failed: matrix not positive definite")
	}
	il.cholFact = &cholFact

	// Compute λ₁ using power iteration with cached factorization
	il.lastLambda1 = il.computeLambda1FromCache(state)
	return il.lastLambda1, nil
}

// computeLambda1FromCache computes λ₁ using the cached Cholesky factorization.
func (il *IncrementalLaplacian) computeLambda1FromCache(state NetworkState) float64 {
	n := il.laplacian.SymmetricDim()
	if n < 2 {
		return 0
	}

	// Small matrices: use EigenSym directly
	if n < 20 {
		return computeLambda1EigenSym(il.laplacian)
	}

	// Use shift-invert power iteration with cached factorization
	return computeLambda1PowerIterWithFact(il.laplacian, il.cholFact, il.opts)
}

// computeLambda1PowerIterWithFact computes λ₁ using cached Cholesky factorization.
func computeLambda1PowerIterWithFact(l *mat.SymDense, cholFact *mat.Cholesky, opts Lambda1Options) float64 {
	n := l.SymmetricDim()

	// Initial vector (orthogonal to all-ones)
	b := mat.NewVecDense(n, nil)
	for i := 0; i < n; i++ {
		b.SetVec(i, 1.0)
	}
	mean := mat.Sum(b) / float64(n)
	for i := 0; i < n; i++ {
		b.SetVec(i, b.AtVec(i)-mean)
	}
	b.ScaleVec(1.0/mat.Norm(b, 2), b)

	var lambda float64
	for iter := 0; iter < opts.MaxIter; iter++ {
		x := mat.NewVecDense(n, nil)
		if err := cholFact.SolveVecTo(x, b); err != nil {
			return 0
		}

		// Rayleigh quotient
		Lx := mat.NewVecDense(n, nil)
		Lx.MulVec(l, x)

		xTLx := mat.Dot(x, Lx)
		xTx := mat.Dot(x, b)

		if xTx == 0 {
			return 0
		}

		lambdaNew := xTLx / xTx

		if lambda > 0 {
			relDiff := math.Abs(lambdaNew-lambda) / math.Max(math.Abs(lambdaNew), 1.0)
			if relDiff < opts.Tolerance {
				return lambdaNew
			}
		}

		lambda = lambdaNew

		// Next iteration
		b.CopyVec(x)
		mean := mat.Sum(b) / float64(n)
		for i := 0; i < n; i++ {
			b.SetVec(i, b.AtVec(i)-mean)
		}
		b.ScaleVec(1.0/mat.Norm(b, 2), b)

		if opts.Verbose {
			fmt.Printf("Iter %d: λ=%.10f\n", iter, lambda)
		}
	}

	return 0
}

// hashGraphStructure creates a simple hash of graph structure for change detection.
func hashGraphStructure(edges []Edge, nodes map[string]NodeState) string {
	h := fmt.Sprintf("%d", len(nodes))
	for _, e := range edges {
		h += fmt.Sprintf("|%s->%s:%.6f", e.From, e.To, e.Weight)
	}
	return h
}

// BuildLaplacianWithOrder builds Laplacian and returns node order for consistent indexing.
func BuildLaplacianWithOrder(graph ReputationGraph, nodes map[string]NodeState) (*mat.SymDense, []string) {
	n := len(nodes)
	if n < 2 {
		return nil, nil
	}

	// Canonical ordering: sort UIDs for deterministic results
	uids := make([]string, 0, n)
	for uid := range nodes {
		uids = append(uids, uid)
	}
	// Simple sort for determinism
	for i := 0; i < len(uids)-1; i++ {
		for j := i + 1; j < len(uids); j++ {
			if uids[i] > uids[j] {
				uids[i], uids[j] = uids[j], uids[i]
			}
		}
	}

	indexMap := make(map[string]int, n)
	for i, uid := range uids {
		indexMap[uid] = i
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

	return l, uids
}

// GetLastLambda1 returns the last computed λ₁ value.
func (il *IncrementalLaplacian) GetLastLambda1() float64 {
	return il.lastLambda1
}

// GetNodeOrder returns the canonical node ordering.
func (il *IncrementalLaplacian) GetNodeOrder() []string {
	return il.nodeOrder
}
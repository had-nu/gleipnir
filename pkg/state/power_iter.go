// Power iteration for λ₁ (Fiedler eigenvalue) computation.
package state

import (
	"fmt"
	"math"

	"gonum.org/v1/gonum/mat"
)

// Lambda1Options configures power iteration.
type Lambda1Options struct {
	MaxIter    int     // Maximum iterations (default 300)
	Tolerance  float64 // Relative convergence tolerance (default 1e-8)
	Shift      float64 // Shift parameter μ (default 1e-2)
	Verbose    bool    // Print iteration progress
}

// DefaultLambda1Options returns default options.
func DefaultLambda1Options() Lambda1Options {
	return Lambda1Options{
		MaxIter:   300,
		Tolerance: 1e-8,
		Shift:     1e-2,
		Verbose:   false,
	}
}

// ComputeLambda1 computes λ₁ (Fiedler eigenvalue) using shift-invert power iteration.
// Falls back to EigenSym for small matrices (n < 20) or on convergence failure.
// Uses shift-invert power iteration on (L + μI)⁻¹ with Cholesky factorization.
// The smallest eigenvalue of (L + μI)⁻¹ is 1/(λ₁ + μ), so λ₁ = 1/λ_inv - μ.
func ComputeLambda1(l *mat.SymDense) float64 {
	return ComputeLambda1WithOptions(l, DefaultLambda1Options())
}

// ComputeLambda1WithOptions computes λ₁ with custom options.
func ComputeLambda1WithOptions(l *mat.SymDense, opts Lambda1Options) float64 {
	if l == nil {
		return 0
	}
	n, _ := l.Dims()
	if n < 2 {
		return 0
	}

	// Small matrices: use EigenSym directly (fast and accurate)
	if n < 20 {
		return computeLambda1EigenSym(l)
	}

	// Use shift-invert power iteration
	lambda1, converged := computeLambda1PowerIter(l, opts)
	if !converged {
		// Fallback to EigenSym
		if opts.Verbose {
			fmt.Printf("Power iteration did not converge, falling back to EigenSym\n")
		}
		return computeLambda1EigenSym(l)
	}
	return lambda1
}

func computeLambda1PowerIter(l *mat.SymDense, opts Lambda1Options) (float64, bool) {
	n, _ := l.Dims()

	mu := opts.Shift
	if mu <= 0 {
		mu = 1e-2
	}
	if opts.MaxIter <= 0 {
		opts.MaxIter = 300
	}
	if opts.Tolerance <= 0 {
		opts.Tolerance = 1e-8
	}

	// Factorize (L + μI) once using Cholesky
	shifted := mat.NewSymDense(n, nil)
	for i := 0; i < n; i++ {
		for j := i; j < n; j++ {
			v := l.At(i, j)
			if i == j {
				v += mu
			}
			shifted.SetSym(i, j, v)
		}
	}

	var cholFact mat.Cholesky
	if ok := cholFact.Factorize(shifted); !ok {
		return 0, false
	}

	// Initial vector (random, orthogonalized to all-ones vector)
	b := mat.NewVecDense(n, nil)
	for i := 0; i < n; i++ {
		b.SetVec(i, 1.0)
	}
	// Project onto orthogonal complement of all-ones vector
	mean := mat.Sum(b) / float64(n)
	for i := 0; i < n; i++ {
		b.SetVec(i, b.AtVec(i)-mean)
	}
	b.ScaleVec(1.0/mat.Norm(b, 2), b)

	var lambda float64
	for iter := 0; iter < opts.MaxIter; iter++ {
		x := mat.NewVecDense(n, nil)
		if err := cholFact.SolveVecTo(x, b); err != nil {
			return 0, false
		}

		// Rayleigh quotient for L: λ = xᵀ L x / xᵀ x
		Lx := mat.NewVecDense(n, nil)
		Lx.MulVec(l, x)

		xTLx := mat.Dot(x, Lx)
		xTx := mat.Dot(x, x)

		if xTx == 0 {
			return 0, false
		}

		lambdaNew := xTLx / xTx

		if lambda > 0 {
			relDiff := math.Abs(lambdaNew-lambda) / math.Max(math.Abs(lambdaNew), 1.0)
			if relDiff < opts.Tolerance {
				return lambdaNew, true
			}
		}

		lambda = lambdaNew

		// Next iteration: b = (L + μI)⁻¹ x
		b.CopyVec(x)

		// Re-orthogonalize to all-ones vector
		mean := mat.Sum(b) / float64(n)
		for i := 0; i < n; i++ {
			b.SetVec(i, b.AtVec(i)-mean)
		}
		b.ScaleVec(1.0/mat.Norm(b, 2), b)

		if opts.Verbose {
			fmt.Printf("Iter %d: λ=%.10f\n", iter, lambda)
		}
	}

	return 0, false
}

func computeLambda1EigenSym(l *mat.SymDense) float64 {
	var eig mat.EigenSym
	if ok := eig.Factorize(l, true); !ok {
		return 0
	}
	values := eig.Values(nil)
	if len(values) < 2 {
		return 0
	}
	lambda1 := values[1]
	if lambda1 < 0 {
		return 0
	}
	return lambda1
}
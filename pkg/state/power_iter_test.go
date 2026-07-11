package state

import (
	"math"
	"math/rand"
	"testing"

	"gonum.org/v1/gonum/mat"
)

// TestLambda1PowerIterAccuracy validates power iteration against EigenSym.
func TestLambda1PowerIterAccuracy(t *testing.T) {
	testCases := []struct {
		name         string
		n            int
		density      float64
		maxRelError  float64
	}{
		{"small_dense_5", 5, 1.0, 1e-8},
		{"small_dense_10", 10, 1.0, 1e-8},
		{"medium_dense_20", 20, 1.0, 1e-7},
		{"medium_dense_50", 50, 1.0, 1e-6},
		{"sparse_20", 20, 0.2, 1e-6},
		{"sparse_50", 50, 0.1, 1e-5},
		{"medium_sparse_100", 100, 0.05, 1e-4},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			l := randomLaplacian(tc.n, tc.density)

			groundTruth := computeLambda1EigenSym(l)

			opts := Lambda1Options{
				MaxIter:   200,
				Tolerance: 1e-10,
				Shift:     1e-6,
				Verbose:   false,
			}
			power := ComputeLambda1WithOptions(l, opts)

			relError := math.Abs(power - groundTruth) / math.Max(groundTruth, 1e-12)
			if relError > tc.maxRelError {
				t.Errorf("relError=%.2e > %v (power=%.6f, eigen=%.6f)", relError, tc.maxRelError, power, groundTruth)
			}

			if opts.Verbose {
				t.Logf("power=%.8f eigen=%.8f relErr=%.2e", power, groundTruth, relError)
			}
		})
	}
}

// TestLambda1Convergence tests convergence properties.
func TestLambda1Convergence(t *testing.T) {
	l := randomLaplacian(100, 0.3)
	opts := Lambda1Options{
		MaxIter:   500,
		Tolerance: 1e-12,
		Shift:     1e-2,
		Verbose:   false,
	}

	lambda := ComputeLambda1WithOptions(l, opts)
	t.Logf("Lambda1(100, dense=0.3) = %.8f", lambda)
}

// BenchmarkLambda1PowerIter vs EigenSym.
func BenchmarkLambda1PowerIter(b *testing.B) {
	sizes := []int{10, 20, 50, 100, 200, 500}
	for _, n := range sizes {
		b.Run("n="+string(rune(n)), func(b *testing.B) {
			l := randomLaplacian(n, 0.3)
			opts := Lambda1Options{
				MaxIter:   200,
				Tolerance: 1e-10,
			}
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				_ = ComputeLambda1WithOptions(l, opts)
			}
		})
	}
}

func BenchmarkLambda1EigenSym(b *testing.B) {
	sizes := []int{10, 20, 50, 100, 200}
	for _, n := range sizes {
		b.Run("n="+string(rune(n)), func(b *testing.B) {
			l := randomLaplacian(n, 0.3)
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				_ = computeLambda1EigenSym(l)
			}
		})
	}
}

// Helper to generate random connected Laplacian.
func randomLaplacian(n int, density float64) *mat.SymDense {
	// Ensure connectivity: start with a cycle
	l := mat.NewSymDense(n, nil)
	for i := 0; i < n; i++ {
		l.SetSym(i, i, 2) // degree 2 from cycle
		l.SetSym(i, (i+1)%n, -1)
		l.SetSym((i+1)%n, i, -1)
	}

	// Add random edges
	edges := int(float64(n*n) * density / 2)
	for e := 0; e < edges; e++ {
		i := rand.Intn(n)
		j := rand.Intn(n)
		if i == j {
			continue
		}
		if l.At(i, j) == 0 {
			l.SetSym(i, j, -1)
			l.SetSym(j, i, -1)
			l.SetSym(i, i, l.At(i, i)+1)
			l.SetSym(j, j, l.At(j, j)+1)
		}
	}
	return l
}
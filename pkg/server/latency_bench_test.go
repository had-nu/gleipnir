// Submit-to-anchor latency measurement — issue #5.
//
// The benchmarks in bench/report.json covered SMT operations, crypto primitives and
// consensus internals. None of them measured the number a pipeline actually waits for: how
// long a submission takes to become anchored. SMT being fast says nothing about that,
// because the dominant term is the consensus cycle interval, not the tree operation.
//
// A Go benchmark cannot answer the question either. `go test -bench` reports a mean with
// its standard error, and the mean of a distribution that is dominated by a fixed periodic
// wait is not the number anybody needs. So the percentiles are collected here, over
// repeated round trips, and reported directly.
//
//nolint:errcheck // test assertions
package server

import (
	"context"
	"crypto/sha256"
	"fmt"
	"sort"
	"testing"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/test/bufconn"

	"github.com/had-nu/gleipnir/pkg/identity"

	pb "github.com/had-nu/gleipnir/pkg/server/pb"
)

// percentile returns the p-th percentile of a sorted-in-place copy of samples.
//
// Nearest-rank rather than interpolated: for a distribution of this shape an interpolated
// p99 invents a value no measurement produced. Nearest-rank always returns a real sample.
func percentile(samples []time.Duration, p float64) time.Duration {
	if len(samples) == 0 {
		return 0
	}
	sorted := append([]time.Duration(nil), samples...)
	sort.Slice(sorted, func(i, j int) bool { return sorted[i] < sorted[j] })

	rank := int(float64(len(sorted))*p+0.9999999) - 1
	if rank < 0 {
		rank = 0
	}
	if rank >= len(sorted) {
		rank = len(sorted) - 1
	}
	return sorted[rank]
}

func summarise(samples []time.Duration) (p50, p95, p99 time.Duration) {
	return percentile(samples, 0.50), percentile(samples, 0.95), percentile(samples, 0.99)
}

// measureSubmitToAnchor runs n round trips at the given cycle interval and returns the
// samples.
//
// Submissions are staggered across the cycle rather than issued back to back. Issued
// together they would all land in the same cycle and share one wait, which would report
// the cycle period and nothing about the distribution.
func measureSubmitToAnchor(
	t *testing.T,
	nodeID string,
	cycleInterval time.Duration,
	n int,
) []time.Duration {
	t.Helper()

	uid := newLatencyUID(t, nodeID)
	srv := NewServer(nodeID, uid, WithCycleInterval(cycleInterval))

	lis := newBufListener()
	cleanup := serveForTest(srv, lis)
	defer cleanup()

	conn := dialForTest(t, lis)
	defer func() { _ = conn.Close() }()
	client := pb.NewProvenanceAnchorClient(conn)

	ctx := context.Background()
	samples := make([]time.Duration, 0, n)

	// Stagger by a fraction of the cycle so successive submissions land in successive
	// cycles rather than all queueing behind the same one.
	stagger := cycleInterval / 4

	for i := 0; i < n; i++ {
		if i > 0 {
			time.Sleep(stagger)
		}

		label := fmt.Sprintf("latency-%s-%d", nodeID, i)
		hash := sha256.Sum256([]byte(label))
		var submitter [16]byte
		copy(submitter[:], uid.RootID[:])
		ts := time.Now().UnixNano()
		sig := identity.SignDilithium3(uid.SecretKey,
			identity.CanonicalPayload(hash[:], submitter[:], ts, label))

		start := time.Now()
		if _, err := client.SubmitHash(ctx, &pb.SubmitRequest{
			Hash: hash[:], Submitter: submitter[:],
			Timestamp: ts, Label: label, Signature: sig,
		}); err != nil {
			t.Fatalf("sample %d: SubmitHash: %v", i, err)
		}

		waitCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
		proof, err := client.WaitForAnchor(waitCtx, &pb.WaitRequest{Hash: hash[:]})
		cancel()
		if err != nil {
			t.Fatalf("sample %d: WaitForAnchor: %v", i, err)
		}
		if !proof.Found {
			t.Fatalf("sample %d: not anchored", i)
		}
		samples = append(samples, time.Since(start))
	}
	return samples
}

// TestSubmitAnchorLatencyPercentiles is the measurement issue #5 asks for.
//
// It runs at the default 3s interval, which is what a node uses unless told otherwise, and
// reports p50, p95 and p99 of the full SubmitHash to anchored path. The expectation is
// that the distribution sits just above one cycle interval, because a submission waits for
// the next cycle: the p50 near the period and the tail showing how much slip accumulates.
func TestSubmitAnchorLatencyPercentiles(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping latency measurement in -short mode; it waits on real cycle intervals")
	}

	const samples = 12

	for _, interval := range []time.Duration{time.Second, 3 * time.Second} {
		interval := interval
		t.Run(fmt.Sprintf("interval=%s", interval), func(t *testing.T) {
			t.Parallel()

			got := measureSubmitToAnchor(t, fmt.Sprintf("latency-%gs", interval.Seconds()), interval, samples)
			p50, p95, p99 := summarise(got)

			t.Logf("submit->anchor over %d samples at cycleInterval=%s: p50=%s p95=%s p99=%s",
				len(got), interval, p50.Round(time.Millisecond), p95.Round(time.Millisecond), p99.Round(time.Millisecond))
			for i, d := range got {
				t.Logf("  sample %2d: %s", i, d.Round(time.Millisecond))
			}

			// Submissions are staggered across the cycle, so the median lands near half a
			// period. Below that would mean the wait is not being measured at all -- the
			// engine ticking faster than configured, or the wait excluded from the timing.
			if p50 < interval/2 {
				t.Errorf("p50 %s is below half the cycle interval %s; the measurement is "+
					"not covering the wait for a cycle", p50, interval)
			}
			// Above a few periods would mean submissions are queueing rather than being
			// picked up by the next cycle.
			if p99 > 5*interval {
				t.Errorf("p99 %s is more than five cycles (%s); submissions are queueing",
					p99, 5*interval)
			}
		})
	}
}

// TestSubmitAnchorLatencyScalesWithCycleInterval records the relationship the numbers
// above imply, so a future change to the cycle loop cannot quietly break it.
//
// If anchoring stopped waiting for the cycle, all three intervals would produce the same
// figures and the interval would stop being the dominant term.
func TestSubmitAnchorLatencyScalesWithCycleInterval(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping latency measurement in -short mode; it waits on real cycle intervals")
	}

	const samples = 6

	short := measureSubmitToAnchor(t, "latency-scale-short", time.Second, samples)
	long := measureSubmitToAnchor(t, "latency-scale-long", 4*time.Second, samples)

	shortP50, _, _ := summarise(short)
	longP50, _, _ := summarise(long)

	t.Logf("p50 at 1s=%s, p50 at 4s=%s", shortP50.Round(time.Millisecond), longP50.Round(time.Millisecond))

	// Four times the interval must cost more than two times the interval. The margin is
	// loose because these are single-node measurements on shared infrastructure.
	if longP50 < 2*shortP50 {
		t.Errorf("p50 at 4s (%s) is not meaningfully above p50 at 1s (%s); the cycle "+
			"interval is no longer the dominant term", longP50, shortP50)
	}
}

// BenchmarkSubmitToAnchor measures the mean round trip, so the figure lands in
// bench/report.json alongside the SMT numbers for anyone comparing them.
//
// The percentiles above are the answer to the question; this is for continuity with the
// existing report.
func BenchmarkSubmitToAnchor(b *testing.B) {
	uid := newLatencyUIDB(b, "bench-submit-anchor")

	srv := NewServer("bench-submit-anchor", uid, WithCycleInterval(100*time.Millisecond))
	lis := newBufListener()
	cleanup := serveForTest(srv, lis)
	defer cleanup()

	conn := dialForTestB(b, lis)
	defer func() { _ = conn.Close() }()
	client := pb.NewProvenanceAnchorClient(conn)
	ctx := context.Background()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		label := fmt.Sprintf("bench-anchor-%d", i)
		hash := sha256.Sum256([]byte(label))
		var submitter [16]byte
		copy(submitter[:], uid.RootID[:])
		ts := time.Now().UnixNano()
		sig := identity.SignDilithium3(uid.SecretKey,
			identity.CanonicalPayload(hash[:], submitter[:], ts, label))

		if _, err := client.SubmitHash(ctx, &pb.SubmitRequest{
			Hash: hash[:], Submitter: submitter[:],
			Timestamp: ts, Label: label, Signature: sig,
		}); err != nil {
			b.Fatalf("SubmitHash: %v", err)
		}
		waitCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
		_, err := client.WaitForAnchor(waitCtx, &pb.WaitRequest{Hash: hash[:]})
		cancel()
		if err != nil {
			b.Fatalf("WaitForAnchor: %v", err)
		}
	}
}

// latencyUID builds a deterministic identity for a latency run, so repeated runs are
// comparable rather than differing by key generation.
func latencyUID(name string) (*identity.UIDZeroSoulbound, error) {
	var networkID [32]byte
	copy(networkID[:], []byte("submit-anchor-latency-bench"))
	return identity.NewUIDZero(name, networkID, true)
}

func newLatencyUID(t *testing.T, name string) *identity.UIDZeroSoulbound {
	t.Helper()
	uid, err := latencyUID(name)
	if err != nil {
		t.Fatalf("NewUIDZero: %v", err)
	}
	return uid
}

func newLatencyUIDB(b *testing.B, name string) *identity.UIDZeroSoulbound {
	b.Helper()
	uid, err := latencyUID(name)
	if err != nil {
		b.Fatalf("NewUIDZero: %v", err)
	}
	return uid
}

// newBufListener and serveForTest stand up the server on an in-process listener, so the
// measurement covers the real gRPC path rather than an in-process shortcut.
func newBufListener() *bufconn.Listener {
	return bufconn.Listen(4 * 1024 * 1024)
}

func serveForTest(srv *Server, lis *bufconn.Listener) func() {
	gs := grpc.NewServer()
	pb.RegisterProvenanceAnchorServer(gs, srv)
	go func() { _ = gs.Serve(lis) }()
	return func() {
		gs.Stop()
		_ = lis.Close()
		srv.Stop()
	}
}

func dialForTest(t *testing.T, lis *bufconn.Listener) *grpc.ClientConn {
	t.Helper()
	conn, err := grpc.NewClient("passthrough:///bufconn",
		grpc.WithTransportCredentials(insecure.NewCredentials()),
		grpc.WithContextDialer(bufDialer(lis)))
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	return conn
}

func dialForTestB(b *testing.B, lis *bufconn.Listener) *grpc.ClientConn {
	b.Helper()
	conn, err := grpc.NewClient("passthrough:///bufconn",
		grpc.WithTransportCredentials(insecure.NewCredentials()),
		grpc.WithContextDialer(bufDialer(lis)))
	if err != nil {
		b.Fatalf("dial: %v", err)
	}
	return conn
}

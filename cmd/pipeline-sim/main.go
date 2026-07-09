package main

import (
	"context"
	"crypto/sha256"
	"flag"
	"fmt"
	"log"
	"math"
	"os"
	"strings"
	"sync/atomic"
	"time"

	pb "github.com/had-nu/prana-provenance-chain/pkg/server/pb"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
)

var (
	totalSubmits atomic.Uint64
	totalErrors  atomic.Uint64
	totalLatency atomic.Int64
	minLatency   atomic.Int64
	maxLatency   atomic.Int64
)

func envFlag(name, env, def string) string {
	if v := os.Getenv(env); v != "" {
		return v
	}
	if def != "" {
		return def
	}
	return ""
}

func main() {
	targets := flag.String("targets", envFlag("", "IPC_TARGETS", "localhost:50051"), "Comma-separated validator addresses")
	interval := flag.Duration("interval", envFlagDuration("IPC_INTERVAL", 2*time.Second), "Interval between submissions")
	pipelineID := flag.String("pipeline-id", envFlag("", "IPC_PIPELINE_ID", "ci-pipeline-0"), "Pipeline identifier")
	duration := flag.Duration("duration", envFlagDuration("IPC_DURATION", 0), "Run duration (0 = infinite)")
	flag.Parse()

	addrs := strings.Split(*targets, ",")
	log.Printf("Pipeline %s starting, targets=%v interval=%v", *pipelineID, addrs, *interval)

	minLatency.Store(math.MaxInt64)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	var ops uint64
	start := time.Now()

	for {
		select {
		case <-ctx.Done():
			return
		default:
		}

		if *duration > 0 && time.Since(start) > *duration {
			break
		}

		target := addrs[ops%uint64(len(addrs))]
		simulateOne(ctx, target, *pipelineID, ops)

		ops++
		if ops%100 == 0 {
			printStats(*pipelineID, ops, time.Since(start))
		}

		time.Sleep(*interval)
	}

	printStats(*pipelineID, ops, time.Since(start))
}

func envFlagDuration(env string, def time.Duration) time.Duration {
	if v := os.Getenv(env); v != "" {
		d, err := time.ParseDuration(v)
		if err == nil {
			return d
		}
	}
	return def
}

func simulateOne(ctx context.Context, target, pipelineID string, seq uint64) {
	hash := sha256.Sum256([]byte(fmt.Sprintf("%s-%d-%d", pipelineID, seq, time.Now().UnixNano())))

	conn, err := grpc.Dial(target,
		grpc.WithTransportCredentials(insecure.NewCredentials()),
		grpc.WithBlock(),
	)
	if err != nil {
		totalErrors.Add(1)
		return
	}
	defer conn.Close()

	client := pb.NewProvenanceAnchorClient(conn)
	start := time.Now()

	resp, err := client.SubmitHash(ctx, &pb.SubmitRequest{
		Hash:      hash[:],
		Label:     fmt.Sprintf("%s-seq-%d", pipelineID, seq),
		Timestamp: time.Now().UnixNano(),
	})
	if err != nil {
		totalErrors.Add(1)
		return
	}

	latency := time.Since(start).Microseconds()
	totalSubmits.Add(1)
	totalLatency.Add(latency)
	updateMinMax(latency)

	if !resp.Accepted {
		totalErrors.Add(1)
	}
}

func updateMinMax(lat int64) {
	for {
		cur := minLatency.Load()
		if lat >= cur {
			break
		}
		if minLatency.CompareAndSwap(cur, lat) {
			break
		}
	}
	for {
		cur := maxLatency.Load()
		if lat <= cur {
			break
		}
		if maxLatency.CompareAndSwap(cur, lat) {
			break
		}
	}
}

func printStats(id string, ops uint64, elapsed time.Duration) {
	submits := totalSubmits.Load()
	errs := totalErrors.Load()
	avg := time.Duration(0)
	if submits > 0 {
		avg = time.Duration(totalLatency.Load()/int64(submits)) * time.Microsecond
	}
	mn := time.Duration(minLatency.Load()) * time.Microsecond
	mx := time.Duration(maxLatency.Load()) * time.Microsecond

	fmt.Printf("[%s] %d ops | %.1f/s | OK=%d ERR=%d | lat avg=%v min=%v max=%v\n",
		id, ops, float64(ops)/elapsed.Seconds(), submits, errs, avg, mn, mx)
}

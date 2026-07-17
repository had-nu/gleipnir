// bench/report.go — runs all Gleipnir benchmarks and generates a JSON + text report.
// Usage: go run bench/report.go
package main

import (
	"encoding/json"
	"fmt"
	"log"
	"os"
	"os/exec"
	"regexp"
	"strconv"
	"strings"
	"time"
)

type BenchResult struct {
	Name   string  `json:"name"`
	N      int     `json:"n"`
	NsOp   float64 `json:"ns_per_op"`
	BOp    int64   `json:"bytes_per_op"`
	Allocs int64   `json:"allocs_per_op"`
}

type Report struct {
	Generated time.Time    `json:"generated"`
	System    string       `json:"system"`
	Results   []BenchResult `json:"results"`
}

func main() {
	report := Report{
		Generated: time.Now(),
		System:    "Gleipnir Provenance Chain",
	}

	packages := []string{
		"./pkg/smt/...",
		"./pkg/identity/...",
		"./pkg/consensus/...",
	}

	lineRe := regexp.MustCompile(`^(Benchmark\S+)\s+(\d+)\s+(\d+)\s+ns/op\s+(\d+)\s+B/op\s+(\d+)\s+allocs/op`)

	for _, pkg := range packages {
		fmt.Fprintf(os.Stderr, "Benchmarking %s ...\n", pkg)
		cmd := exec.Command("go", "test", pkg, "-bench=.", "-benchmem", "-count=1", "-timeout=180s")
		cmd.Dir = findModRoot()
		out, err := cmd.Output()
		if err != nil {
			fmt.Fprintf(os.Stderr, "error running benchmarks for %s: %v\n", pkg, err)
			continue
		}
		for _, line := range strings.Split(string(out), "\n") {
			m := lineRe.FindStringSubmatch(line)
			if m == nil {
				continue
			}
			n, _ := strconv.Atoi(m[2])
			ns, _ := strconv.ParseFloat(m[3], 64)
			b, _ := strconv.ParseInt(m[4], 10, 64)
			a, _ := strconv.ParseInt(m[5], 10, 64)
			report.Results = append(report.Results, BenchResult{
				Name:   m[1],
				N:      n,
				NsOp:   ns,
				BOp:    b,
				Allocs: a,
			})
		}
	}

	jsonBytes, _ := json.MarshalIndent(report, "", "  ")
	if err := os.WriteFile("bench/report.json", jsonBytes, 0644); err != nil {
		log.Printf("bench: write report: %v", err)
	}

	fmt.Println("\n=== Gleipnir Performance Report ===")
	fmt.Printf("Generated: %s\n", report.Generated.Format(time.RFC3339))
	fmt.Println()
	for _, r := range report.Results {
		tps := 0.0
		if r.NsOp > 0 {
			tps = 1e9 / r.NsOp
		}
		fmt.Printf("%-45s %8d ops  %10.2f ns/op  %8d B/op  %5d allocs/op  %8.0f ops/s\n",
			r.Name, r.N, r.NsOp, r.BOp, r.Allocs, tps)
	}
	fmt.Println("\nReport saved to bench/report.json")
}

func findModRoot() string {
	wd, _ := os.Getwd()
	if strings.HasSuffix(wd, "/bench") {
		return wd[:len(wd)-6]
	}
	return wd
}

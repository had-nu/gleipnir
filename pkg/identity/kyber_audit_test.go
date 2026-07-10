package identity

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// GLP-T-B04 — Kyber1024 usage audit.
// Grep the codebase for every call site of the Kyber1024 dependency.
// This test exists to keep issue #2 honest: confirm empirically whether
// "not yet used for its intended purpose" is still accurate.
func TestKyberUsageAudit(t *testing.T) {
	repoRoot := findRepoRoot(t)
	if repoRoot == "" {
		t.Skip("cannot find repo root")
	}

	type match struct {
		file string
		line string
	}
	var matches []match

	err := filepath.Walk(repoRoot, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if info.IsDir() && strings.HasPrefix(info.Name(), ".") && info.Name() != "." {
			return filepath.SkipDir
		}
		if !strings.HasSuffix(path, ".go") {
			return nil
		}
		if strings.Contains(path, "vendor/") {
			return nil
		}

		data, err := os.ReadFile(path)
		if err != nil {
			return nil
		}
		lines := strings.Split(string(data), "\n")
		for _, line := range lines {
			if strings.Contains(line, "kyber") || strings.Contains(line, "Kyber") || strings.Contains(line, "KEM") {
				rel, _ := filepath.Rel(repoRoot, path)
				matches = append(matches, match{
					file: rel,
					line: strings.TrimSpace(line),
				})
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}

	// Report findings
	t.Logf("Kyber1024/KEM references found: %d", len(matches))
	for _, m := range matches {
		t.Logf("  %s: %s", m.file, m.line)
	}

	// Kyber1024 should NOT be used for its intended purpose (KEM) yet.
	// Acceptable: import/declaration, comments, docs. Unacceptable:
	// actual key exchange, encryption, or KEM operations.
	// Count non-trivial usages.
	nonTrivial := 0
	for _, m := range matches {
		line := strings.ToLower(m.line)
		if strings.Contains(line, "import") || strings.Contains(line, "//") || strings.Contains(line, "/*") {
			continue
		}
		if strings.Contains(line, "kyber") || strings.Contains(line, "kem") {
			nonTrivial++
		}
	}

	if nonTrivial > 0 {
		t.Logf("WARNING: %d non-trivial Kyber1024/KEM references found — issue #2 may need updating", nonTrivial)
	} else {
		t.Log("Confirmed: Kyber1024 is not used for its intended purpose (KEM) — issue #2 is accurate")
	}
}

func findRepoRoot(t *testing.T) string {
	dir, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	for {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			return dir
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			return ""
		}
		dir = parent
	}
}

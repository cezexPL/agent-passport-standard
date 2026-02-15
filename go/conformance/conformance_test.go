package conformance

import (
	"os"
	"path/filepath"
	"testing"
)

func findVectorsPath() string {
	// Try relative paths from the test location
	candidates := []string{
		"../../spec/test-vectors.json",
		"../../../standard/spec/test-vectors.json",
	}
	for _, c := range candidates {
		abs, _ := filepath.Abs(c)
		if _, err := os.Stat(abs); err == nil {
			return abs
		}
	}
	return ""
}

func TestConformance_RunAll(t *testing.T) {
	path := findVectorsPath()
	if path == "" {
		t.Fatal("test-vectors.json not found")
	}

	report := RunAll(path)
	t.Logf("Conformance: %d total, %d passed, %d failed, %d skipped",
		report.Total, report.Passed, report.Failed, report.Skipped)

	for _, r := range report.Results {
		if r.Skipped {
			t.Logf("  SKIP: %s - %s", r.Name, r.Message)
		} else if r.Passed {
			t.Logf("  PASS: %s %s", r.Name, r.Message)
		} else {
			t.Errorf("  FAIL: %s - %s", r.Name, r.Message)
		}
	}

	if report.Passed == 0 {
		t.Error("no vectors passed")
	}

	if report.Failed != 0 {
		t.Errorf("conformance failed vectors: %d", report.Failed)
	}

	if report.Skipped != 0 {
		t.Errorf("expected 0 skipped vectors, got %d", report.Skipped)
	}
}

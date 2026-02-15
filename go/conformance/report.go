package conformance

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
)

// GenerateReport runs conformance vectors and returns a JSON report.
func GenerateReport() ([]byte, error) {
	vectorsPath := findVectorsPath()
	if vectorsPath == "" {
		return nil, fmt.Errorf("cannot locate test-vectors.json")
	}

	return GenerateReportFromPath(vectorsPath)
}

// GenerateReportFromPath runs conformance vectors from a specific path.
func GenerateReportFromPath(vectorsPath string) ([]byte, error) {
	report := RunAll(vectorsPath)
	data, err := json.MarshalIndent(report, "", "  ")
	if err != nil {
		return nil, fmt.Errorf("marshal conformance report: %w", err)
	}
	return data, nil
}

func findVectorsPath() string {
	candidates := []string{
		"../../spec/test-vectors.json",
		"../../../standard/spec/test-vectors.json",
		"standard/spec/test-vectors.json",
		"spec/test-vectors.json",
	}

	for _, candidate := range candidates {
		abs, err := filepath.Abs(candidate)
		if err != nil {
			continue
		}
		if _, err := os.Stat(abs); err == nil {
			return abs
		}
	}
	return ""
}

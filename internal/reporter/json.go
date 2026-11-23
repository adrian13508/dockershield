package reporter

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/adrian13508/skobel/pkg/models"
)

// JSONReporter handles JSON output formatting
type JSONReporter struct{}

// NewJSONReporter creates a new JSON reporter
func NewJSONReporter() *JSONReporter {
	return &JSONReporter{}
}

// Generate creates a JSON report from scan results
func (r *JSONReporter) Generate(
	containers []models.Container,
	networks []models.NetworkInfo,
	firewall *models.FirewallInfo,
	findings []models.Finding,
	securityChecks *models.SecurityChecks,
	riskSummary models.RiskSummary,
	score int,
) ([]byte, error) {
	// Get hostname for the report
	hostname, err := os.Hostname()
	if err != nil {
		hostname = "unknown"
	}

	// Build the scan result
	result := models.ScanResult{
		Timestamp:      time.Now(),
		Hostname:       hostname,
		Containers:     containers,
		Networks:       networks,
		Firewall:       firewall,
		Findings:       findings,
		SecurityChecks: securityChecks,
		RiskSummary:    riskSummary,
		OverallScore:   score,
	}

	// Marshal to JSON with indentation for readability
	jsonBytes, err := json.MarshalIndent(result, "", "  ")
	if err != nil {
		return nil, fmt.Errorf("failed to marshal JSON: %w", err)
	}

	return jsonBytes, nil
}

// WriteToFile writes JSON output to a file
func (r *JSONReporter) WriteToFile(data []byte, path string) error {
	return writeReportFile(data, path)
}

// writeReportFile writes report data with owner-only permissions. It writes
// a temporary file in the same directory and renames it, so that a reader
// such as the node_exporter textfile collector never sees half a file.
func writeReportFile(data []byte, path string) error {
	tmp, err := os.CreateTemp(filepath.Dir(path), ".skobel-*")
	if err != nil {
		return fmt.Errorf("failed to write file %s: %w", path, err)
	}
	defer func() { _ = os.Remove(tmp.Name()) }() // no-op after a successful rename
	if _, err := tmp.Write(data); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("failed to write file %s: %w", path, err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("failed to write file %s: %w", path, err)
	}
	if err := os.Rename(tmp.Name(), path); err != nil {
		return fmt.Errorf("failed to write file %s: %w", path, err)
	}
	return nil
}

// Print outputs JSON to stdout
func (r *JSONReporter) Print(data []byte) {
	fmt.Println(string(data))
}

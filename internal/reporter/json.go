package reporter

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/adrian13508/dockershield/pkg/models"
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
	// Validate path to prevent directory traversal
	cleanPath := filepath.Clean(path)

	// Check if path is absolute - reject absolute paths outside current directory
	if filepath.IsAbs(cleanPath) {
		return fmt.Errorf("absolute paths are not allowed for security reasons")
	}

	// Check for directory traversal attempts
	if strings.Contains(cleanPath, "..") {
		return fmt.Errorf("path traversal is not allowed for security reasons")
	}

	// Write to file with restrictive permissions (owner read/write only)
	err := os.WriteFile(cleanPath, data, 0600)
	if err != nil {
		return fmt.Errorf("failed to write file %s: %w", cleanPath, err)
	}
	return nil
}

// Print outputs JSON to stdout
func (r *JSONReporter) Print(data []byte) {
	fmt.Println(string(data))
}

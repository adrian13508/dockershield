package reporter

import (
	"encoding/json"
	"os"
	"testing"
	"time"

	"github.com/adrian13508/dockershield/pkg/models"
)

// TestJSONGeneration tests that JSON is properly generated
func TestJSONGeneration(t *testing.T) {
	reporter := NewJSONReporter()

	// Create test data
	containers := []models.Container{
		{
			ID:          "abc123456789",
			Name:        "test_postgres",
			Image:       "postgres:15",
			State:       "running",
			NetworkMode: "bridge",
			Ports: []models.PortBinding{
				{
					HostIP:        "0.0.0.0",
					HostPort:      "5432",
					ContainerPort: "5432",
					Protocol:      "tcp",
					ExposureType:  models.ExposurePublic,
					RiskLevel:     models.RiskCritical,
					RiskReason:    "PostgreSQL exposed to public internet",
				},
			},
			Networks:    []string{"bridge"},
			HighestRisk: models.RiskCritical,
			RiskCount: models.RiskSummary{
				Critical: 1,
				High:     0,
				Medium:   0,
				Low:      0,
				Info:     0,
			},
			CreatedAt: time.Now(),
		},
	}

	networks := []models.NetworkInfo{
		{
			ID:         "net123456789",
			Name:       "bridge",
			Driver:     "bridge",
			Subnet:     "172.17.0.0/16",
			Gateway:    "172.17.0.1",
			Containers: []string{"abc123456789"},
		},
	}

	riskSummary := models.RiskSummary{
		Critical: 1,
		High:     0,
		Medium:   0,
		Low:      0,
		Info:     0,
	}

	score := 75

	firewallInfo := &models.FirewallInfo{
		UFWActive:          true,
		DockerDetected:     true,
		DockerBypassingUFW: true,
		DockerChains:       []string{"DOCKER", "DOCKER-USER"},
		Warning:            "Docker is bypassing UFW",
	}

	// Generate JSON (with empty security checks for this test)
	jsonData, err := reporter.Generate(containers, networks, firewallInfo, nil, riskSummary, score)
	if err != nil {
		t.Fatalf("Failed to generate JSON: %v", err)
	}

	// Verify it's valid JSON by unmarshaling
	var result models.ScanResult
	err = json.Unmarshal(jsonData, &result)
	if err != nil {
		t.Fatalf("Generated invalid JSON: %v", err)
	}

	// Verify key fields
	if result.OverallScore != score {
		t.Errorf("Expected score %d, got %d", score, result.OverallScore)
	}

	if len(result.Containers) != 1 {
		t.Errorf("Expected 1 container, got %d", len(result.Containers))
	}

	if result.Containers[0].Name != "test_postgres" {
		t.Errorf("Expected container name 'test_postgres', got '%s'", result.Containers[0].Name)
	}

	if result.RiskSummary.Critical != 1 {
		t.Errorf("Expected 1 critical issue, got %d", result.RiskSummary.Critical)
	}
}

// TestJSONWriteToFile tests writing JSON to a file
func TestJSONWriteToFile(t *testing.T) {
	reporter := NewJSONReporter()

	// Create temporary file
	tmpFile := "/tmp/dockershield_test_output.json"
	defer os.Remove(tmpFile) // Clean up after test

	jsonData := []byte(`{"test": "data"}`)

	// Write to file
	err := reporter.WriteToFile(jsonData, tmpFile)
	if err != nil {
		t.Fatalf("Failed to write JSON to file: %v", err)
	}

	// Verify file exists and has correct content
	content, err := os.ReadFile(tmpFile)
	if err != nil {
		t.Fatalf("Failed to read back JSON file: %v", err)
	}

	if string(content) != string(jsonData) {
		t.Errorf("File content doesn't match. Expected %s, got %s", jsonData, content)
	}
}

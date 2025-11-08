package analyzer

import (
	"testing"

	"github.com/adrian13508/dockershield/pkg/models"
)

// TestPortRiskAnalysis tests the risk analysis for various port configurations
func TestPortRiskAnalysis(t *testing.T) {
	tests := []struct {
		name           string
		binding        models.PortBinding
		expectedRisk   models.RiskLevel
		expectedReason string
	}{
		{
			name: "PostgreSQL on public internet - CRITICAL",
			binding: models.PortBinding{
				HostIP:        "0.0.0.0",
				HostPort:      "5432",
				ContainerPort: "5432",
				Protocol:      "tcp",
				ExposureType:  models.ExposurePublic,
			},
			expectedRisk:   models.RiskCritical,
			expectedReason: "PostgreSQL exposed to public internet",
		},
		{
			name: "MySQL on localhost - LOW",
			binding: models.PortBinding{
				HostIP:        "127.0.0.1",
				HostPort:      "3306",
				ContainerPort: "3306",
				Protocol:      "tcp",
				ExposureType:  models.ExposureLocalhost,
			},
			expectedRisk:   models.RiskLow,
			expectedReason: "MySQL (localhost only - OK)",
		},
		{
			name: "HTTP on public internet - MEDIUM",
			binding: models.PortBinding{
				HostIP:        "0.0.0.0",
				HostPort:      "80",
				ContainerPort: "80",
				Protocol:      "tcp",
				ExposureType:  models.ExposurePublic,
			},
			expectedRisk:   models.RiskMedium,
			expectedReason: "HTTP exposed to public internet",
		},
		{
			name: "Redis on public internet - CRITICAL",
			binding: models.PortBinding{
				HostIP:        "0.0.0.0",
				HostPort:      "6379",
				ContainerPort: "6379",
				Protocol:      "tcp",
				ExposureType:  models.ExposurePublic,
			},
			expectedRisk:   models.RiskCritical,
			expectedReason: "Redis exposed to public internet",
		},
		{
			name: "Unknown port on public internet - MEDIUM",
			binding: models.PortBinding{
				HostIP:        "0.0.0.0",
				HostPort:      "9999",
				ContainerPort: "9999",
				Protocol:      "tcp",
				ExposureType:  models.ExposurePublic,
			},
			expectedRisk:   models.RiskMedium,
			expectedReason: "Port exposed to public internet",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Analyze the port
			AnalyzePortRisk(&tt.binding)

			// Check risk level
			if tt.binding.RiskLevel != tt.expectedRisk {
				t.Errorf("Expected risk %s, got %s",
					tt.expectedRisk, tt.binding.RiskLevel)
			}

			// Check risk reason
			if tt.binding.RiskReason != tt.expectedReason {
				t.Errorf("Expected reason '%s', got '%s'",
					tt.expectedReason, tt.binding.RiskReason)
			}
		})
	}
}

// TestSecurityScore tests the overall security scoring
func TestSecurityScore(t *testing.T) {
	tests := []struct {
		name           string
		summary        models.RiskSummary
		expectedScore  int
		expectedRating string
	}{
		{
			name: "Perfect security",
			summary: models.RiskSummary{
				Critical: 0,
				High:     0,
				Medium:   0,
				Low:      0,
			},
			expectedScore:  100,
			expectedRating: "EXCELLENT",
		},
		{
			name: "One critical issue",
			summary: models.RiskSummary{
				Critical: 1,
				High:     0,
				Medium:   0,
				Low:      0,
			},
			expectedScore:  75,
			expectedRating: "GOOD",
		},
		{
			name: "Multiple issues",
			summary: models.RiskSummary{
				Critical: 2,
				High:     3,
				Medium:   5,
				Low:      10,
			},
			expectedScore:  0, // 100 - 50 - 30 - 25 - 20 = -25, clamped to 0
			expectedRating: "CRITICAL",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			score := CalculateSecurityScore(tt.summary)
			rating := GetScoreRating(score)

			if score != tt.expectedScore {
				t.Errorf("Expected score %d, got %d", tt.expectedScore, score)
			}

			if rating != tt.expectedRating {
				t.Errorf("Expected rating %s, got %s", tt.expectedRating, rating)
			}
		})
	}
}

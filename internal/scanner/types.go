package scanner

import (
	"time"

	"github.com/adrian13508/dockershield/pkg/models"
)

// CategoryResult represents the result of a category-specific scan
type CategoryResult struct {
	Category      string                `json:"category"`
	Timestamp     time.Time             `json:"timestamp"`
	ScanTimeMs    int64                 `json:"scan_time_ms"`
	Results       CategoryResultSummary `json:"results"`
	Findings      []Finding             `json:"findings"`
	ContainerName string                `json:"container_name,omitempty"` // If filtered by container
}

// CategoryResultSummary counts issues by severity
type CategoryResultSummary struct {
	Critical int `json:"critical"`
	High     int `json:"high"`
	Medium   int `json:"medium"`
	Low      int `json:"low"`
	Info     int `json:"info"`
	OK       int `json:"ok"`
}

// Finding represents a single security finding
type Finding struct {
	Severity    string `json:"severity"`              // critical, high, medium, low, info, ok
	Container   string `json:"container"`             // Container name
	Port        string `json:"port,omitempty"`        // Port if applicable
	Binding     string `json:"binding,omitempty"`     // Port binding if applicable
	Network     string `json:"network,omitempty"`     // Network if applicable
	Message     string `json:"message"`               // Description
	Remediation string `json:"remediation,omitempty"` // Fix suggestion
}

// CheckOptions contains options for category checks
type CheckOptions struct {
	JSON      bool
	Container string // Filter by container name
	Severity  string // Filter by severity (critical, high, medium, low, all)
	NoCache   bool   // Skip cache
	Quiet     bool   // Suppress output
}

// riskLevelToSeverity converts models.RiskLevel to severity string
func riskLevelToSeverity(risk models.RiskLevel) string {
	switch risk {
	case models.RiskCritical:
		return "critical"
	case models.RiskHigh:
		return "high"
	case models.RiskMedium:
		return "medium"
	case models.RiskLow:
		return "low"
	case models.RiskInfo:
		return "info"
	default:
		return "ok"
	}
}

// shouldIncludeSeverity checks if a severity should be included based on filter
func shouldIncludeSeverity(severity string, filter string) bool {
	if filter == "all" || filter == "" {
		return true
	}

	// Map severity levels for filtering
	severityLevels := map[string]int{
		"critical": 4,
		"high":     3,
		"medium":   2,
		"low":      1,
		"info":     0,
		"ok":       0,
	}

	severityLevel := severityLevels[severity]
	filterLevel := severityLevels[filter]

	return severityLevel >= filterLevel
}

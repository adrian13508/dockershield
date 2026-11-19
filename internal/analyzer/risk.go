package analyzer

import (
	"github.com/adrian13508/dockershield/pkg/models"
)

// AnalyzeContainers performs risk analysis on all containers
// It modifies containers in-place to add risk information
func AnalyzeContainers(containers []models.Container) models.RiskSummary {
	totalRisks := models.RiskSummary{}

	for i := range containers {
		container := &containers[i]

		for j := range container.Ports {
			AnalyzePortRisk(&container.Ports[j])
		}

		container.RiskCount = calculateContainerRisks(container.Ports)
		container.HighestRisk = getHighestRisk(container.Ports)

		totalRisks.Critical += container.RiskCount.Critical
		totalRisks.High += container.RiskCount.High
		totalRisks.Medium += container.RiskCount.Medium
		totalRisks.Low += container.RiskCount.Low
		totalRisks.Info += container.RiskCount.Info
	}

	return totalRisks
}

// calculateContainerRisks counts risks for a single container.
// A port published on all interfaces shows up twice on a dual-stack host
// (0.0.0.0 and ::); that is one mistake, so it is counted once.
func calculateContainerRisks(ports []models.PortBinding) models.RiskSummary {
	summary := models.RiskSummary{}
	seen := map[string]bool{}
	for _, port := range ports {
		if port.AddressScope == models.ScopeAllInterfaces {
			key := port.HostPort + "/" + port.ContainerPort + "/" + port.Protocol
			if seen[key] {
				continue
			}
			seen[key] = true
		}
		countRisk(&summary, port.RiskLevel)
	}
	return summary
}

// getHighestRisk returns the highest risk level from a list of ports
func getHighestRisk(ports []models.PortBinding) models.RiskLevel {
	if len(ports) == 0 {
		return models.RiskInfo
	}

	highest := models.RiskInfo

	for _, port := range ports {
		if isHigherRisk(port.RiskLevel, highest) {
			highest = port.RiskLevel
		}
	}

	return highest
}

// isHigherRisk compares two risk levels
func isHigherRisk(a, b models.RiskLevel) bool {
	riskOrder := map[models.RiskLevel]int{
		models.RiskInfo:     0,
		models.RiskLow:      1,
		models.RiskMedium:   2,
		models.RiskHigh:     3,
		models.RiskCritical: 4,
	}
	return riskOrder[a] > riskOrder[b]
}

// countRisk increments the appropriate counter in the summary
func countRisk(summary *models.RiskSummary, level models.RiskLevel) {
	switch level {
	case models.RiskCritical:
		summary.Critical++
	case models.RiskHigh:
		summary.High++
	case models.RiskMedium:
		summary.Medium++
	case models.RiskLow:
		summary.Low++
	case models.RiskInfo:
		summary.Info++
	}
}

// CalculateSecurityScore returns a score from 0-100
// 100 = perfect security, 0 = critical issues
func CalculateSecurityScore(summary models.RiskSummary) int {
	// Start at 100 (perfect score)
	score := 100

	// Deduct points for each risk level
	score -= summary.Critical * 25 // Critical issues: -25 points each
	score -= summary.High * 10     // High issues: -10 points each
	score -= summary.Medium * 5    // Medium issues: -5 points each
	// Low and info do not affect the score: a port bound to localhost is the
	// recommended setup and must not cost points.

	// Ensure score doesn't go negative
	if score < 0 {
		score = 0
	}

	return score
}

// GetScoreRating converts a numeric score to a text rating
func GetScoreRating(score int) string {
	switch {
	case score >= 90:
		return "EXCELLENT"
	case score >= 70:
		return "GOOD"
	case score >= 50:
		return "FAIR"
	case score >= 30:
		return "POOR"
	default:
		return "CRITICAL"
	}
}

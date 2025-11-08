package scanner

import (
	"fmt"
	"time"

	"github.com/adrian13508/dockershield/internal/docker"
	"github.com/adrian13508/dockershield/pkg/models"
)

// CheckPorts performs a focused scan on port exposures
func CheckPorts(opts CheckOptions) (*CategoryResult, error) {
	startTime := time.Now()

	// Connect to Docker
	client, err := docker.NewClient()
	if err != nil {
		return nil, fmt.Errorf("failed to connect to Docker: %w", err)
	}
	defer client.Close()

	// List containers
	containers, err := client.ListContainers()
	if err != nil {
		return nil, fmt.Errorf("failed to list containers: %w", err)
	}

	// Filter by container if specified
	if opts.Container != "" {
		containers = filterContainersByName(containers, opts.Container)
		if len(containers) == 0 {
			return nil, fmt.Errorf("container not found: %s", opts.Container)
		}
	}

	// Analyze ports
	var findings []Finding
	summary := CategoryResultSummary{}

	for _, container := range containers {
		// Only look at ports
		if len(container.Ports) == 0 {
			summary.OK++
			if shouldIncludeSeverity("ok", opts.Severity) {
				findings = append(findings, Finding{
					Severity:  "ok",
					Container: container.Name,
					Message:   "No exposed ports",
				})
			}
			continue
		}

		// Check each port
		hasIssue := false
		for _, port := range container.Ports {
			severity := riskLevelToSeverity(port.RiskLevel)

			if !shouldIncludeSeverity(severity, opts.Severity) {
				continue
			}

			// Count by severity
			switch severity {
			case "critical":
				summary.Critical++
				hasIssue = true
			case "high":
				summary.High++
				hasIssue = true
			case "medium":
				summary.Medium++
				hasIssue = true
			case "low":
				summary.Low++
			case "info":
				summary.Info++
			}

			// Get remediation
			remediation := ""
			if port.RiskLevel == models.RiskCritical || port.RiskLevel == models.RiskHigh {
				// Generate remediation for high-risk ports
				remediation = fmt.Sprintf("Bind to localhost: docker run -p 127.0.0.1:%s:%s/tcp ...",
					port.HostPort, port.ContainerPort)
			}

			findings = append(findings, Finding{
				Severity:    severity,
				Container:   container.Name,
				Port:        fmt.Sprintf("%s/%s", port.ContainerPort, port.Protocol),
				Binding:     fmt.Sprintf("%s:%s", port.HostIP, port.HostPort),
				Message:     port.RiskReason,
				Remediation: remediation,
			})
		}

		if !hasIssue {
			summary.OK++
		}
	}

	// Calculate scan time
	scanTime := time.Since(startTime).Milliseconds()

	result := &CategoryResult{
		Category:      "ports",
		Timestamp:     time.Now(),
		ScanTimeMs:    scanTime,
		Results:       summary,
		Findings:      findings,
		ContainerName: opts.Container,
	}

	return result, nil
}

// filterContainersByName filters containers by name
func filterContainersByName(containers []models.Container, name string) []models.Container {
	var filtered []models.Container
	for _, c := range containers {
		if c.Name == name {
			filtered = append(filtered, c)
		}
	}
	return filtered
}

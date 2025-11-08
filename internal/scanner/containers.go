package scanner

import (
	"fmt"
	"time"

	"github.com/adrian13508/dockershield/internal/docker"
)

// CheckContainers performs a focused scan on container security settings
func CheckContainers(opts CheckOptions) (*CategoryResult, error) {
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

	// Analyze container security
	var findings []Finding
	summary := CategoryResultSummary{}

	for _, container := range containers {
		// Check running status
		if container.State != "running" {
			summary.Info++
			if shouldIncludeSeverity("info", opts.Severity) {
				findings = append(findings, Finding{
					Severity:  "info",
					Container: container.Name,
					Message:   fmt.Sprintf("Container is %s (not running)", container.State),
				})
			}
			continue
		}

		// Basic container info
		hasIssues := false

		// Check for host network mode (covered in networks, but important)
		if container.NetworkMode == "host" {
			summary.High++
			hasIssues = true
			if shouldIncludeSeverity("high", opts.Severity) {
				findings = append(findings, Finding{
					Severity:    "high",
					Container:   container.Name,
					Message:     "Using host network mode (no network isolation)",
					Remediation: "Use bridge or custom network",
				})
			}
		}

		// Check highest risk level from ports
		if container.HighestRisk != "" {
			severity := riskLevelToSeverity(container.HighestRisk)

			if severity == "critical" || severity == "high" {
				hasIssues = true
				switch severity {
				case "critical":
					summary.Critical++
				case "high":
					summary.High++
				}

				if shouldIncludeSeverity(severity, opts.Severity) {
					portCount := len(container.Ports)
					findings = append(findings, Finding{
						Severity:  severity,
						Container: container.Name,
						Message:   fmt.Sprintf("Container has %s risk exposure (%d port(s))", severity, portCount),
					})
				}
			}
		}

		// If no issues, mark as OK
		if !hasIssues {
			summary.OK++
			if shouldIncludeSeverity("ok", opts.Severity) {
				findings = append(findings, Finding{
					Severity:  "ok",
					Container: container.Name,
					Message:   fmt.Sprintf("Container is running with %s networking", container.NetworkMode),
				})
			}
		}

		// Add info about the container
		if shouldIncludeSeverity("info", opts.Severity) {
			findings = append(findings, Finding{
				Severity:  "info",
				Container: container.Name,
				Message:   fmt.Sprintf("Image: %s, Network: %s, Ports: %d", container.Image, container.NetworkMode, len(container.Ports)),
			})
		}
	}

	// Calculate scan time
	scanTime := time.Since(startTime).Milliseconds()

	result := &CategoryResult{
		Category:      "containers",
		Timestamp:     time.Now(),
		ScanTimeMs:    scanTime,
		Results:       summary,
		Findings:      findings,
		ContainerName: opts.Container,
	}

	return result, nil
}

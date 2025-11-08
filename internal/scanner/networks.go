package scanner

import (
	"fmt"
	"strings"
	"time"

	"github.com/adrian13508/dockershield/internal/docker"
)

// CheckNetworks performs a focused scan on Docker networks
func CheckNetworks(opts CheckOptions) (*CategoryResult, error) {
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

	// List networks
	networks, err := client.ListNetworks()
	if err != nil {
		return nil, fmt.Errorf("failed to list networks: %w", err)
	}

	// Analyze network configuration
	var findings []Finding
	summary := CategoryResultSummary{}

	// Check each container's network mode
	for _, container := range containers {
		networkMode := container.NetworkMode

		// Check for host networking (high risk)
		if networkMode == "host" {
			summary.High++
			if shouldIncludeSeverity("high", opts.Severity) {
				findings = append(findings, Finding{
					Severity:    "high",
					Container:   container.Name,
					Network:     "host",
					Message:     "Container uses host networking (bypasses network isolation)",
					Remediation: "Use bridge networking instead: docker run --network bridge ...",
				})
			}
		} else if networkMode == "none" {
			summary.Info++
			if shouldIncludeSeverity("info", opts.Severity) {
				findings = append(findings, Finding{
					Severity:  "info",
					Container: container.Name,
					Network:   "none",
					Message:   "Container has no network access",
				})
			}
		} else {
			// Bridge or custom network - generally OK
			summary.OK++
			if shouldIncludeSeverity("ok", opts.Severity) {
				networksStr := strings.Join(container.Networks, ", ")
				if networksStr == "" {
					networksStr = networkMode
				}
				findings = append(findings, Finding{
					Severity:  "ok",
					Container: container.Name,
					Network:   networksStr,
					Message:   fmt.Sprintf("Using %s networking", networkMode),
				})
			}
		}
	}

	// Report on networks
	for _, network := range networks {
		if shouldIncludeSeverity("info", opts.Severity) {
			containerCount := len(network.Containers)
			message := fmt.Sprintf("Network '%s' (%s driver) - %d container(s)",
				network.Name, network.Driver, containerCount)

			findings = append(findings, Finding{
				Severity: "info",
				Network:  network.Name,
				Message:  message,
			})
		}
	}

	// Calculate scan time
	scanTime := time.Since(startTime).Milliseconds()

	result := &CategoryResult{
		Category:      "networks",
		Timestamp:     time.Now(),
		ScanTimeMs:    scanTime,
		Results:       summary,
		Findings:      findings,
		ContainerName: opts.Container,
	}

	return result, nil
}

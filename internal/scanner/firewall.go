package scanner

import (
	"fmt"
	"time"

	"github.com/adrian13508/dockershield/internal/system"
)

// CheckFirewall performs a focused scan on firewall configuration
func CheckFirewall(opts CheckOptions) (*CategoryResult, error) {
	startTime := time.Now()

	// Analyze iptables/firewall
	firewallAnalysis := system.AnalyzeIptables()

	var findings []Finding
	summary := CategoryResultSummary{}

	// Check if we could read iptables
	if firewallAnalysis.ErrorMessage != "" {
		if firewallAnalysis.RequiresSudo {
			summary.Info++
			if shouldIncludeSeverity("info", opts.Severity) {
				findings = append(findings, Finding{
					Severity:    "info",
					Message:     "Firewall analysis requires sudo privileges",
					Remediation: "Run with sudo: sudo dockershield check firewall",
				})
			}
		} else {
			return nil, fmt.Errorf("failed to analyze firewall: %s", firewallAnalysis.ErrorMessage)
		}
	} else {
		// Successfully analyzed firewall

		// Check UFW status
		if firewallAnalysis.UFWActive {
			summary.OK++
			if shouldIncludeSeverity("ok", opts.Severity) {
				findings = append(findings, Finding{
					Severity: "ok",
					Message:  "UFW firewall is active",
				})
			}
		} else {
			summary.Medium++
			if shouldIncludeSeverity("medium", opts.Severity) {
				findings = append(findings, Finding{
					Severity:    "medium",
					Message:     "UFW firewall is not active",
					Remediation: "Enable UFW: sudo ufw enable",
				})
			}
		}

		// Check if Docker is detected
		if firewallAnalysis.HasDocker {
			summary.Info++
			if shouldIncludeSeverity("info", opts.Severity) {
				chainCount := len(firewallAnalysis.DockerChains)
				findings = append(findings, Finding{
					Severity: "info",
					Message:  fmt.Sprintf("Docker iptables chains detected (%d chains)", chainCount),
				})
			}
		}

		// Check if Docker is bypassing UFW
		if firewallAnalysis.DockerBypassingUFW {
			summary.High++
			if shouldIncludeSeverity("high", opts.Severity) {
				findings = append(findings, Finding{
					Severity:    "high",
					Message:     "Docker is bypassing UFW firewall",
					Remediation: firewallAnalysis.GetRecommendation(),
				})
			}
		}

		// Add warning if available
		warning := firewallAnalysis.GetFirewallWarning()
		if warning != "" {
			// Warning is already a high-severity issue
			if !firewallAnalysis.DockerBypassingUFW {
				summary.High++
				if shouldIncludeSeverity("high", opts.Severity) {
					findings = append(findings, Finding{
						Severity:    "high",
						Message:     warning,
						Remediation: firewallAnalysis.GetRecommendation(),
					})
				}
			}
		} else {
			// No warnings - firewall looks good
			if !firewallAnalysis.UFWActive && !firewallAnalysis.HasDocker {
				summary.OK++
			}
		}
	}

	// Calculate scan time
	scanTime := time.Since(startTime).Milliseconds()

	result := &CategoryResult{
		Category:   "firewall",
		Timestamp:  time.Now(),
		ScanTimeMs: scanTime,
		Results:    summary,
		Findings:   findings,
	}

	return result, nil
}

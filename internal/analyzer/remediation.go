package analyzer

import (
	"fmt"
	"strings"

	"github.com/adrian13508/dockershield/pkg/models"
)

// Remediation represents a fix for a security issue
type Remediation struct {
	Issue       string
	Severity    models.RiskLevel
	Fix         string
	Command     string // Executable command to fix the issue
	Explanation string
}

// GenerateRemediation creates remediation steps for a port binding
func GenerateRemediation(containerName string, port models.PortBinding) *Remediation {
	// Only generate remediation for actual problems
	if port.RiskLevel == models.RiskLow || port.RiskLevel == models.RiskInfo {
		return nil
	}

	r := &Remediation{
		Severity: port.RiskLevel,
	}

	// Build issue description
	r.Issue = fmt.Sprintf("Container '%s': %s", containerName, port.RiskReason)

	// Generate fix based on exposure type
	switch port.ExposureType {
	case models.ExposurePublic:
		r.Fix = "Bind port to localhost (127.0.0.1) or specific private IP"
		r.Explanation = "Public exposure (0.0.0.0) makes this service accessible from the internet. " +
			"Unless you need external access, bind to 127.0.0.1 for local-only access."

		// Generate docker run command example
		r.Command = fmt.Sprintf("# Instead of: -p %s:%s\n"+
			"# Use: -p 127.0.0.1:%s:%s\n"+
			"# Or use docker-compose with:\n"+
			"#   ports:\n"+
			"#     - \"127.0.0.1:%s:%s\"",
			port.HostPort, port.ContainerPort,
			port.HostPort, port.ContainerPort,
			port.HostPort, port.ContainerPort)

	case models.ExposureSpecificIP:
		r.Fix = "Review firewall rules to ensure this IP is protected"
		r.Explanation = "Port is bound to a specific IP. Ensure your firewall (iptables/UFW) " +
			"properly restricts access to this IP address."
		r.Command = fmt.Sprintf("# Check firewall status:\n"+
			"sudo ufw status\n"+
			"# Or check iptables:\n"+
			"sudo iptables -L -n | grep %s", port.HostPort)
	}

	return r
}

// GenerateContainerRemediations returns all remediations for a container
func GenerateContainerRemediations(container models.Container) []Remediation {
	var remediations []Remediation

	for _, port := range container.Ports {
		if r := GenerateRemediation(container.Name, port); r != nil {
			remediations = append(remediations, *r)
		}
	}

	// Add network-specific recommendations
	if container.NetworkMode == "host" {
		remediations = append(remediations, Remediation{
			Issue:    fmt.Sprintf("Container '%s': Using host networking mode", container.Name),
			Severity: models.RiskHigh,
			Fix:      "Use bridge networking instead of host mode",
			Explanation: "Host networking mode gives the container full access to the host's network stack, " +
				"which can be a security risk. Use bridge mode unless you have a specific need for host networking.",
			Command: "# Remove --network host from docker run command\n# Or in docker-compose.yml, remove 'network_mode: host'",
		})
	}

	return remediations
}

// FormatRemediation returns a human-readable string for a remediation
func FormatRemediation(r Remediation) string {
	var sb strings.Builder

	// Severity indicator
	severityIcon := "⚠️"
	if r.Severity == models.RiskCritical {
		severityIcon = "🔴"
	}

	sb.WriteString(fmt.Sprintf("%s %s [%s]\n", severityIcon, r.Issue, strings.ToUpper(string(r.Severity))))
	sb.WriteString(fmt.Sprintf("   Fix: %s\n", r.Fix))

	if r.Explanation != "" {
		sb.WriteString(fmt.Sprintf("   Why: %s\n", r.Explanation))
	}

	if r.Command != "" {
		sb.WriteString(fmt.Sprintf("\n   Example:\n"))
		for _, line := range strings.Split(r.Command, "\n") {
			sb.WriteString(fmt.Sprintf("   %s\n", line))
		}
	}

	return sb.String()
}

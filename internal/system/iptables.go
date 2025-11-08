package system

import (
	"fmt"
	"os/exec"
	"strings"
)

// IptablesRule represents a parsed iptables rule
type IptablesRule struct {
	Chain  string // e.g., "DOCKER", "DOCKER-USER", "INPUT"
	Rule   string // The full rule text
	Action string // e.g., "ACCEPT", "DROP", "REJECT"
}

// IptablesAnalysis contains the results of iptables analysis
type IptablesAnalysis struct {
	HasDocker          bool     // Docker chains detected
	DockerChains       []string // List of Docker chains found
	DockerUserRules    []string // Rules in DOCKER-USER chain
	UFWActive          bool     // Is UFW running
	DockerBypassingUFW bool     // Is Docker bypassing UFW
	RequiresSudo       bool     // Did we need sudo to read iptables
	ErrorMessage       string   // Error if analysis failed
}

// AnalyzeIptables reads and analyzes iptables rules
func AnalyzeIptables() *IptablesAnalysis {
	analysis := &IptablesAnalysis{}

	// Try to read iptables rules
	rules, requiresSudo, err := readIptablesRules()
	if err != nil {
		analysis.ErrorMessage = err.Error()
		return analysis
	}

	analysis.RequiresSudo = requiresSudo

	// Parse rules
	analysis.parseRules(rules)

	// Check UFW status
	analysis.checkUFW()

	// Determine if Docker is bypassing UFW
	if analysis.UFWActive && analysis.HasDocker {
		analysis.DockerBypassingUFW = true
	}

	return analysis
}

// readIptablesRules attempts to read iptables rules
func readIptablesRules() (string, bool, error) {
	// Try without sudo first
	cmd := exec.Command("iptables-save")
	output, err := cmd.CombinedOutput()

	if err == nil && len(output) > 0 {
		// Success without sudo
		return string(output), false, nil
	}

	// Try with sudo
	cmd = exec.Command("sudo", "-n", "iptables-save")
	output, err = cmd.CombinedOutput()

	if err != nil {
		// Check if iptables-save exists
		if strings.Contains(err.Error(), "not found") || strings.Contains(string(output), "not found") {
			return "", false, fmt.Errorf("iptables-save not found (iptables not installed?)")
		}
		// Permission denied or sudo not available
		return "", true, fmt.Errorf("insufficient permissions (run with sudo or configure passwordless sudo)")
	}

	return string(output), true, nil
}

// parseRules extracts Docker-related information from iptables rules
func (a *IptablesAnalysis) parseRules(rules string) {
	lines := strings.Split(rules, "\n")
	dockerChainsSeen := make(map[string]bool)

	for _, line := range lines {
		line = strings.TrimSpace(line)

		// Skip empty lines and comments
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		// Check for chain definitions
		if strings.HasPrefix(line, ":DOCKER") {
			chainName := extractChainName(line)
			dockerChainsSeen[chainName] = true
		}

		// Check for DOCKER-USER rules
		if strings.HasPrefix(line, "-A DOCKER-USER") {
			a.DockerUserRules = append(a.DockerUserRules, line)
		}
	}

	// Set Docker chains
	for chain := range dockerChainsSeen {
		a.DockerChains = append(a.DockerChains, chain)
	}

	a.HasDocker = len(a.DockerChains) > 0
}

// extractChainName gets the chain name from a chain definition line
func extractChainName(line string) string {
	// Format: ":DOCKER-USER ACCEPT [0:0]"
	parts := strings.Fields(line)
	if len(parts) > 0 {
		return strings.TrimPrefix(parts[0], ":")
	}
	return ""
}

// checkUFW determines if UFW is active
func (a *IptablesAnalysis) checkUFW() {
	// Try to check UFW status
	cmd := exec.Command("ufw", "status")
	output, err := cmd.CombinedOutput()

	if err != nil {
		// UFW might not be installed
		a.UFWActive = false
		return
	}

	// Check if output contains "Status: active"
	outputStr := string(output)
	a.UFWActive = strings.Contains(outputStr, "Status: active")
}

// GetFirewallWarning returns a warning message if there are firewall issues
func (a *IptablesAnalysis) GetFirewallWarning() string {
	if a.ErrorMessage != "" {
		return fmt.Sprintf("Could not analyze firewall: %s", a.ErrorMessage)
	}

	if !a.HasDocker {
		return ""
	}

	if a.DockerBypassingUFW {
		return "⚠️  Docker is bypassing UFW! Port bindings (0.0.0.0) are exposed despite UFW rules."
	}

	return ""
}

// GetRecommendation provides advice based on firewall analysis
func (a *IptablesAnalysis) GetRecommendation() string {
	if !a.DockerBypassingUFW {
		return ""
	}

	return `Docker bypasses UFW by default. To fix this:

1. Use DOCKER-USER chain for firewall rules:
   sudo iptables -I DOCKER-USER -j DROP
   sudo iptables -I DOCKER-USER -s 10.0.0.0/8 -j ACCEPT
   sudo iptables -I DOCKER-USER -s 172.16.0.0/12 -j ACCEPT
   sudo iptables -I DOCKER-USER -s 192.168.0.0/16 -j ACCEPT

2. OR bind ports to localhost and use reverse proxy:
   docker run -p 127.0.0.1:8080:8080 myapp

3. OR configure Docker to respect UFW:
   https://github.com/chaifeng/ufw-docker`
}

package system

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"sort"
	"strings"
)

// IptablesAnalysis contains the results of iptables analysis
type IptablesAnalysis struct {
	HasDocker          bool     // Docker chains detected (IPv4)
	DockerChains       []string // List of Docker chains found (IPv4)
	DockerUserRules    []string // Rules in the IPv4 DOCKER-USER chain
	DockerUserFiltered bool     // IPv4 DOCKER-USER has DROP/REJECT/ufw rules
	UFWActive          bool     // Is UFW running
	DockerBypassingUFW bool     // UFW active, Docker chains present, DOCKER-USER not filtering
	RequiresSudo       bool     // Did we need sudo to read iptables
	ErrorMessage       string   // Error if analysis failed

	IPv6Checked            bool // ip6tables-save could be read
	IPv6DockerUserFiltered bool // IPv6 DOCKER-USER has DROP/REJECT/ufw rules
}

// AnalyzeIptables reads and analyzes iptables rules
func AnalyzeIptables() *IptablesAnalysis {
	v4, requiresSudo, err := readRules("iptables-save")
	if err != nil {
		return &IptablesAnalysis{ErrorMessage: err.Error(), RequiresSudo: requiresSudo}
	}
	v6, _, err6 := readRules("ip6tables-save")

	analysis := analyze(v4, v6, err6 == nil, ufwActive())
	analysis.RequiresSudo = requiresSudo
	return analysis
}

// analyze derives the firewall state from saved rule sets. Pure function.
func analyze(v4, v6 string, v6ok, ufw bool) *IptablesAnalysis {
	a := &IptablesAnalysis{UFWActive: ufw, IPv6Checked: v6ok}

	chains, rules := parseRules(v4)
	a.DockerChains, a.DockerUserRules = chains, rules[dockerUserChain]
	a.HasDocker = len(a.DockerChains) > 0
	a.DockerUserFiltered = filters(rules, dockerUserChain, map[string]bool{})

	if v6ok {
		_, v6Rules := parseRules(v6)
		a.IPv6DockerUserFiltered = filters(v6Rules, dockerUserChain, map[string]bool{})
	}

	// Docker's rules are evaluated before UFW's. Unless the user has put
	// filtering rules into DOCKER-USER (which is what ufw-docker does),
	// UFW does not see traffic to published ports.
	a.DockerBypassingUFW = a.UFWActive && a.HasDocker && !a.DockerUserFiltered
	return a
}

// readRules runs iptables-save or ip6tables-save, falling back to sudo -n.
// The fallback also covers systems where /usr/sbin is only in root's PATH.
func readRules(command string) (string, bool, error) {
	output, direct := exec.Command(command).CombinedOutput()
	if direct == nil && len(output) > 0 {
		return string(output), false, nil
	}

	output, err := exec.Command("sudo", "-n", command).CombinedOutput()
	switch {
	case err == nil:
		return string(output), true, nil
	case errors.Is(err, exec.ErrNotFound) && errors.Is(direct, exec.ErrNotFound),
		strings.Contains(string(output), "command not found"):
		return "", false, fmt.Errorf("%s not found (iptables not installed?)", command)
	}
	return "", true, fmt.Errorf("insufficient permissions (run with sudo or configure passwordless sudo)")
}

const dockerUserChain = "DOCKER-USER"

// parseRules extracts Docker chain names and the rules of every chain from
// iptables-save output
func parseRules(rules string) (chains []string, byChain map[string][]string) {
	byChain = map[string][]string{}
	seen := map[string]bool{}
	for _, line := range strings.Split(rules, "\n") {
		line = strings.TrimSpace(line)
		fields := strings.Fields(line)
		switch {
		case strings.HasPrefix(line, ":DOCKER"):
			// Format: ":DOCKER-USER - [0:0]"
			if name := strings.TrimPrefix(fields[0], ":"); !seen[name] {
				seen[name] = true
				chains = append(chains, name)
			}
		case len(fields) >= 2 && fields[0] == "-A":
			byChain[fields[1]] = append(byChain[fields[1]], line)
		}
	}
	sort.Strings(chains)
	return chains, byChain
}

// filters reports whether a chain drops, rejects or hands traffic to a ufw
// chain, directly or in a chain it jumps to. It does not evaluate what the
// rules match.
func filters(byChain map[string][]string, chain string, visited map[string]bool) bool {
	if visited[chain] {
		return false
	}
	visited[chain] = true
	for _, rule := range byChain[chain] {
		fields := strings.Fields(rule)
		for i, f := range fields[:len(fields)-1] {
			if f != "-j" && f != "-g" {
				continue
			}
			target := fields[i+1]
			if target == "DROP" || target == "REJECT" || strings.HasPrefix(target, "ufw-") {
				return true
			}
			if filters(byChain, target, visited) {
				return true
			}
		}
	}
	return false
}

// ufwActive determines if UFW is enabled. `ufw status` needs root, so the
// config file is used as a fallback.
func ufwActive() bool {
	output, err := exec.Command("ufw", "status").CombinedOutput()
	if err == nil {
		return strings.Contains(string(output), "Status: active")
	}
	conf, err := os.ReadFile("/etc/ufw/ufw.conf")
	return err == nil && ufwEnabledInConf(string(conf))
}

// ufwEnabledInConf parses /etc/ufw/ufw.conf
func ufwEnabledInConf(conf string) bool {
	for _, line := range strings.Split(conf, "\n") {
		line = strings.ToLower(strings.TrimSpace(line))
		if strings.HasPrefix(line, "enabled=") {
			return strings.Trim(strings.TrimPrefix(line, "enabled="), `"'`) == "yes"
		}
	}
	return false
}

// GetFirewallWarning returns a warning message if there are firewall issues
func (a *IptablesAnalysis) GetFirewallWarning() string {
	if a.ErrorMessage != "" {
		return fmt.Sprintf("Could not analyze firewall: %s", a.ErrorMessage)
	}
	if a.DockerBypassingUFW {
		return "UFW is active, but Docker's iptables rules are evaluated first and the DOCKER-USER chain has no filtering rules. UFW rules do not apply to published container ports."
	}
	return ""
}

// GetRecommendation provides advice based on firewall analysis
func (a *IptablesAnalysis) GetRecommendation() string {
	if !a.DockerBypassingUFW {
		return ""
	}

	return `Docker bypasses UFW by default. To fix this:

1. Bind ports to localhost and use a reverse proxy:
   docker run -p 127.0.0.1:8080:8080 myapp

2. OR filter in the DOCKER-USER chain:
   https://docs.docker.com/engine/network/packet-filtering-firewalls/#docker-and-ufw

3. OR let a tool manage those rules:
   https://github.com/chaifeng/ufw-docker`
}

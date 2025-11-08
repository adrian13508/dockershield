package security

import (
	"fmt"
	"os/exec"
	"regexp"
	"strconv"
	"strings"
)

// Fail2banStatus represents the status of fail2ban installation and configuration
type Fail2banStatus struct {
	Installed       bool           `json:"installed"`
	Running         bool           `json:"running"`
	Jails           []Fail2banJail `json:"jails,omitempty"`
	TotalBanned     int            `json:"total_banned"`
	ErrorMessage    string         `json:"error_message,omitempty"`
	Recommendations []string       `json:"recommendations,omitempty"`
	RiskLevel       string         `json:"risk_level"` // LOW, MEDIUM, HIGH, CRITICAL
}

// Fail2banJail represents a single fail2ban jail
type Fail2banJail struct {
	Name        string `json:"name"`
	Enabled     bool   `json:"enabled"`
	BannedIPs   int    `json:"banned_ips"`
	TotalBanned int    `json:"total_banned"`
	TotalFailed int    `json:"total_failed"`
}

// AnalyzeFail2ban checks fail2ban installation, status, and configuration
func AnalyzeFail2ban() *Fail2banStatus {
	status := &Fail2banStatus{
		Installed:       false,
		Running:         false,
		Jails:           []Fail2banJail{},
		TotalBanned:     0,
		Recommendations: []string{},
	}

	// Check if fail2ban is installed
	if !isFail2banInstalled() {
		status.Installed = false
		status.RiskLevel = "HIGH"
		status.Recommendations = append(status.Recommendations,
			"Install fail2ban: sudo apt install fail2ban",
			"Enable fail2ban: sudo systemctl enable fail2ban",
			"Start fail2ban: sudo systemctl start fail2ban",
		)
		return status
	}

	status.Installed = true

	// Check if fail2ban is running
	if !isFail2banRunning() {
		status.Running = false
		status.RiskLevel = "HIGH"
		status.Recommendations = append(status.Recommendations,
			"Start fail2ban: sudo systemctl start fail2ban",
			"Enable fail2ban on boot: sudo systemctl enable fail2ban",
		)
		return status
	}

	status.Running = true

	// Get jail status (requires root/sudo)
	jails, err := getFail2banJails()
	if err != nil {
		status.ErrorMessage = fmt.Sprintf("Cannot read jail status (requires sudo): %v", err)
		status.RiskLevel = "MEDIUM"
		return status
	}

	status.Jails = jails

	// Calculate total banned IPs
	for _, jail := range jails {
		status.TotalBanned += jail.BannedIPs
	}

	// Analyze configuration and provide recommendations
	status.analyzeConfiguration()

	return status
}

// isFail2banInstalled checks if fail2ban is installed
func isFail2banInstalled() bool {
	cmd := exec.Command("which", "fail2ban-client")
	err := cmd.Run()
	return err == nil
}

// isFail2banRunning checks if fail2ban service is running
func isFail2banRunning() bool {
	cmd := exec.Command("systemctl", "is-active", "fail2ban")
	output, _ := cmd.Output()
	return strings.TrimSpace(string(output)) == "active"
}

// getFail2banJails retrieves the list of jails and their status
func getFail2banJails() ([]Fail2banJail, error) {
	// Get list of active jails
	cmd := exec.Command("sudo", "fail2ban-client", "status")
	output, err := cmd.Output()
	if err != nil {
		// Try without sudo
		cmd = exec.Command("fail2ban-client", "status")
		output, err = cmd.Output()
		if err != nil {
			return nil, fmt.Errorf("cannot execute fail2ban-client: %w", err)
		}
	}

	// Parse jail list from output
	// Format: "Jail list:	sshd, nginx-limit-req"
	jailListRegex := regexp.MustCompile(`Jail list:\s+(.+)`)
	matches := jailListRegex.FindStringSubmatch(string(output))
	if len(matches) < 2 {
		return []Fail2banJail{}, nil
	}

	jailNames := strings.Split(matches[1], ",")
	jails := []Fail2banJail{}

	// Get details for each jail
	for _, jailName := range jailNames {
		jailName = strings.TrimSpace(jailName)
		if jailName == "" {
			continue
		}

		// Validate jail name to prevent command injection
		// Only allow alphanumeric, dash, and underscore characters
		validJailName := regexp.MustCompile(`^[a-zA-Z0-9_-]+$`)
		if !validJailName.MatchString(jailName) {
			// Skip invalid jail names
			continue
		}

		jail := Fail2banJail{
			Name:    jailName,
			Enabled: true,
		}

		// Get jail statistics
		cmd := exec.Command("sudo", "fail2ban-client", "status", jailName)
		jailOutput, err := cmd.Output()
		if err != nil {
			// Try without sudo
			cmd = exec.Command("fail2ban-client", "status", jailName)
			jailOutput, err = cmd.Output()
			if err != nil {
				continue
			}
		}

		// Parse jail output
		// Format:
		// Currently banned: 3
		// Total banned: 127
		// Total failed: 1523
		bannedRegex := regexp.MustCompile(`Currently banned:\s+(\d+)`)
		totalBannedRegex := regexp.MustCompile(`Total banned:\s+(\d+)`)
		totalFailedRegex := regexp.MustCompile(`(?:Banned IP list|Total failed):\s+(\d+)`)

		jailOutputStr := string(jailOutput)

		if matches := bannedRegex.FindStringSubmatch(jailOutputStr); len(matches) > 1 {
			jail.BannedIPs, _ = strconv.Atoi(matches[1])
		}

		if matches := totalBannedRegex.FindStringSubmatch(jailOutputStr); len(matches) > 1 {
			jail.TotalBanned, _ = strconv.Atoi(matches[1])
		}

		if matches := totalFailedRegex.FindStringSubmatch(jailOutputStr); len(matches) > 1 {
			jail.TotalFailed, _ = strconv.Atoi(matches[1])
		}

		jails = append(jails, jail)
	}

	return jails, nil
}

// analyzeConfiguration analyzes fail2ban setup and provides recommendations
func (f *Fail2banStatus) analyzeConfiguration() {
	// Check for critical services
	hasSSH := false
	hasNginx := false
	hasDocker := false

	for _, jail := range f.Jails {
		if strings.Contains(strings.ToLower(jail.Name), "ssh") || jail.Name == "sshd" {
			hasSSH = true
		}
		if strings.Contains(strings.ToLower(jail.Name), "nginx") || strings.Contains(strings.ToLower(jail.Name), "apache") {
			hasNginx = true
		}
		if strings.Contains(strings.ToLower(jail.Name), "docker") {
			hasDocker = true
		}
	}

	// Assess risk level
	if !hasSSH {
		f.RiskLevel = "MEDIUM"
		f.Recommendations = append(f.Recommendations,
			"Enable SSH protection: Add [sshd] jail to /etc/fail2ban/jail.local",
		)
	} else if !hasNginx && !hasDocker {
		f.RiskLevel = "LOW"
		f.Recommendations = append(f.Recommendations,
			"Consider adding nginx/apache protection if you're running a web server",
		)
	} else {
		f.RiskLevel = "LOW"
	}

	// Check if any bans have occurred
	if f.TotalBanned > 0 {
		f.Recommendations = append(f.Recommendations,
			fmt.Sprintf("✓ Fail2ban is working: %d total IPs have been banned", f.TotalBanned),
		)
	}

	if len(f.Jails) == 0 {
		f.RiskLevel = "MEDIUM"
		f.Recommendations = append(f.Recommendations,
			"No jails are currently active",
			"Configure jails in /etc/fail2ban/jail.local",
		)
	}
}

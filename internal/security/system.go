package security

import (
	"bufio"
	"fmt"
	"os"
	"os/exec"
	"regexp"
	"strings"
	"time"
)

// SystemSecurityStatus represents the overall system security status
type SystemSecurityStatus struct {
	LastUpdate         time.Time     `json:"last_update,omitempty"`
	DaysSinceUpdate    int           `json:"days_since_update"`
	UpdatesAvailable   int           `json:"updates_available"`
	SecurityUpdates    int           `json:"security_updates"`
	KernelVersion      string        `json:"kernel_version"`
	OSVersion          string        `json:"os_version"`
	AutoUpdatesEnabled bool          `json:"auto_updates_enabled"`
	RebootRequired     bool          `json:"reboot_required"`
	Issues             []SystemIssue `json:"issues"`
	RiskLevel          string        `json:"risk_level"` // LOW, MEDIUM, HIGH, CRITICAL
}

// SystemIssue represents a system security issue
type SystemIssue struct {
	Severity       string `json:"severity"` // CRITICAL, HIGH, MEDIUM, LOW, INFO
	Issue          string `json:"issue"`
	Recommendation string `json:"recommendation"`
}

// AnalyzeSystemSecurity checks system update status and security posture
func AnalyzeSystemSecurity() *SystemSecurityStatus {
	status := &SystemSecurityStatus{
		Issues: []SystemIssue{},
	}

	// Get OS version
	status.OSVersion = getOSVersion()

	// Get kernel version
	status.KernelVersion = getKernelVersion()

	// Check last update time
	status.LastUpdate, _ = getLastUpdateTime()
	if !status.LastUpdate.IsZero() {
		status.DaysSinceUpdate = int(time.Since(status.LastUpdate).Hours() / 24)
	}

	// Check for available updates (requires apt update to be recent)
	status.UpdatesAvailable, status.SecurityUpdates = checkAvailableUpdates()

	// Check if reboot is required
	status.RebootRequired = checkRebootRequired()

	// Check if automatic updates are enabled
	status.AutoUpdatesEnabled = checkAutoUpdates()

	// Analyze and generate recommendations
	status.analyzeSystemStatus()

	return status
}

// getOSVersion retrieves the operating system version
func getOSVersion() string {
	// Try /etc/os-release first
	file, err := os.Open("/etc/os-release")
	if err != nil {
		return "Unknown"
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	prettyName := ""
	for scanner.Scan() {
		line := scanner.Text()
		if strings.HasPrefix(line, "PRETTY_NAME=") {
			prettyName = strings.TrimPrefix(line, "PRETTY_NAME=")
			prettyName = strings.Trim(prettyName, "\"")
			break
		}
	}

	if prettyName != "" {
		return prettyName
	}

	return "Unknown"
}

// getKernelVersion retrieves the kernel version
func getKernelVersion() string {
	cmd := exec.Command("uname", "-r")
	output, err := cmd.Output()
	if err != nil {
		return "Unknown"
	}
	return strings.TrimSpace(string(output))
}

// getLastUpdateTime gets the last apt update/upgrade time
func getLastUpdateTime() (time.Time, error) {
	// Check /var/log/apt/history.log for last upgrade
	file, err := os.Open("/var/log/apt/history.log")
	if err != nil {
		return time.Time{}, err
	}
	defer file.Close()

	var lastUpdate time.Time
	scanner := bufio.NewScanner(file)
	dateRegex := regexp.MustCompile(`^Start-Date:\s+(.+)$`)

	for scanner.Scan() {
		line := scanner.Text()
		if matches := dateRegex.FindStringSubmatch(line); len(matches) > 1 {
			// Parse date format: "2025-11-06  14:30:45"
			t, err := time.Parse("2006-01-02  15:04:05", matches[1])
			if err == nil && t.After(lastUpdate) {
				lastUpdate = t
			}
		}
	}

	if !lastUpdate.IsZero() {
		return lastUpdate, nil
	}

	// Fallback: check apt cache directory modification time
	info, err := os.Stat("/var/cache/apt")
	if err == nil {
		return info.ModTime(), nil
	}

	return time.Time{}, fmt.Errorf("could not determine last update time")
}

// checkAvailableUpdates checks how many updates are available
func checkAvailableUpdates() (total int, security int) {
	// Run apt list --upgradable to see available updates
	cmd := exec.Command("apt", "list", "--upgradable")
	output, err := cmd.Output()
	if err != nil {
		return 0, 0
	}

	lines := strings.Split(string(output), "\n")
	total = 0
	security = 0

	for _, line := range lines {
		if strings.Contains(line, "/") && !strings.HasPrefix(line, "Listing") {
			total++
			// Check if it's a security update
			if strings.Contains(strings.ToLower(line), "security") ||
				strings.Contains(strings.ToLower(line), "-security") {
				security++
			}
		}
	}

	return total, security
}

// checkRebootRequired checks if system reboot is required
func checkRebootRequired() bool {
	_, err := os.Stat("/var/run/reboot-required")
	return err == nil
}

// checkAutoUpdates checks if unattended-upgrades is enabled
func checkAutoUpdates() bool {
	// Check if unattended-upgrades is installed
	cmd := exec.Command("dpkg", "-l", "unattended-upgrades")
	if err := cmd.Run(); err != nil {
		return false
	}

	// Check if it's enabled
	configFile := "/etc/apt/apt.conf.d/20auto-upgrades"
	file, err := os.Open(configFile)
	if err != nil {
		// Try alternative location
		configFile = "/etc/apt/apt.conf.d/50unattended-upgrades"
		file, err = os.Open(configFile)
		if err != nil {
			return false
		}
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := scanner.Text()
		// Look for APT::Periodic::Unattended-Upgrade "1";
		if strings.Contains(line, "Unattended-Upgrade") && strings.Contains(line, "\"1\"") {
			return true
		}
	}

	return false
}

// analyzeSystemStatus analyzes system security and generates recommendations
func (s *SystemSecurityStatus) analyzeSystemStatus() {
	score := 100

	// Check days since last update
	if s.DaysSinceUpdate > 90 {
		s.Issues = append(s.Issues, SystemIssue{
			Severity:       "CRITICAL",
			Issue:          fmt.Sprintf("System not updated in %d days", s.DaysSinceUpdate),
			Recommendation: "Run 'sudo apt update && sudo apt upgrade' immediately",
		})
		score -= 30
	} else if s.DaysSinceUpdate > 30 {
		s.Issues = append(s.Issues, SystemIssue{
			Severity:       "HIGH",
			Issue:          fmt.Sprintf("System not updated in %d days", s.DaysSinceUpdate),
			Recommendation: "Update system: 'sudo apt update && sudo apt upgrade'",
		})
		score -= 20
	} else if s.DaysSinceUpdate > 14 {
		s.Issues = append(s.Issues, SystemIssue{
			Severity:       "MEDIUM",
			Issue:          fmt.Sprintf("System not updated in %d days", s.DaysSinceUpdate),
			Recommendation: "Consider updating system regularly",
		})
		score -= 10
	}

	// Check security updates
	if s.SecurityUpdates > 0 {
		s.Issues = append(s.Issues, SystemIssue{
			Severity:       "HIGH",
			Issue:          fmt.Sprintf("%d security update(s) available", s.SecurityUpdates),
			Recommendation: "Install security updates: 'sudo apt update && sudo apt upgrade'",
		})
		score -= 20
	}

	// Check total updates
	if s.UpdatesAvailable > 50 {
		s.Issues = append(s.Issues, SystemIssue{
			Severity:       "MEDIUM",
			Issue:          fmt.Sprintf("%d package updates available", s.UpdatesAvailable),
			Recommendation: "Update packages to latest versions",
		})
		score -= 10
	} else if s.UpdatesAvailable > 0 {
		s.Issues = append(s.Issues, SystemIssue{
			Severity:       "LOW",
			Issue:          fmt.Sprintf("%d package update(s) available", s.UpdatesAvailable),
			Recommendation: "Keep system up to date: 'sudo apt upgrade'",
		})
		score -= 5
	}

	// Check reboot required
	if s.RebootRequired {
		s.Issues = append(s.Issues, SystemIssue{
			Severity:       "MEDIUM",
			Issue:          "System reboot required (kernel or critical updates)",
			Recommendation: "Reboot system to apply updates: 'sudo reboot'",
		})
		score -= 10
	}

	// Check automatic updates
	if !s.AutoUpdatesEnabled {
		s.Issues = append(s.Issues, SystemIssue{
			Severity:       "MEDIUM",
			Issue:          "Automatic security updates not enabled",
			Recommendation: "Enable unattended-upgrades: 'sudo apt install unattended-upgrades && sudo dpkg-reconfigure -plow unattended-upgrades'",
		})
		score -= 15
	}

	// Determine risk level
	if score >= 85 {
		s.RiskLevel = "LOW"
	} else if score >= 70 {
		s.RiskLevel = "MEDIUM"
	} else if score >= 50 {
		s.RiskLevel = "HIGH"
	} else {
		s.RiskLevel = "CRITICAL"
	}

	// Add positive note if system is well maintained
	if len(s.Issues) == 0 {
		s.Issues = append(s.Issues, SystemIssue{
			Severity:       "INFO",
			Issue:          "System is up to date and well maintained",
			Recommendation: "Continue regular updates and monitoring",
		})
	}
}

// GetSystemSecurityScore calculates a 0-100 security score
func (s *SystemSecurityStatus) GetSystemSecurityScore() int {
	score := 100

	if s.DaysSinceUpdate > 90 {
		score -= 30
	} else if s.DaysSinceUpdate > 30 {
		score -= 20
	} else if s.DaysSinceUpdate > 14 {
		score -= 10
	}

	if s.SecurityUpdates > 0 {
		score -= 20
	}

	if s.UpdatesAvailable > 50 {
		score -= 10
	} else if s.UpdatesAvailable > 0 {
		score -= 5
	}

	if s.RebootRequired {
		score -= 10
	}

	if !s.AutoUpdatesEnabled {
		score -= 15
	}

	if score < 0 {
		score = 0
	}

	return score
}

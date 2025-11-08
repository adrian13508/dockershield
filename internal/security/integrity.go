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

// IntegrityStatus represents file integrity monitoring status
type IntegrityStatus struct {
	AIDEStatus      AIDEInfo         `json:"aide"`
	Tripwire        TripwireInfo     `json:"tripwire,omitempty"`
	LastScanTime    time.Time        `json:"last_scan_time,omitempty"`
	ChangesDetected int              `json:"changes_detected"`
	ModifiedFiles   []FileChange     `json:"modified_files,omitempty"`
	Issues          []IntegrityIssue `json:"issues"`
	RiskLevel       string           `json:"risk_level"`     // LOW, MEDIUM, HIGH, CRITICAL
	SecurityScore   int              `json:"security_score"` // 0-100
}

// AIDEInfo represents AIDE (Advanced Intrusion Detection Environment) status
type AIDEInfo struct {
	Installed      bool      `json:"installed"`
	Initialized    bool      `json:"initialized"`
	Version        string    `json:"version,omitempty"`
	DatabasePath   string    `json:"database_path,omitempty"`
	DatabaseExists bool      `json:"database_exists"`
	DatabaseAge    int       `json:"database_age_days"`
	LastCheck      time.Time `json:"last_check,omitempty"`
	ChangesFound   int       `json:"changes_found"`
	Status         string    `json:"status"`
}

// TripwireInfo represents Tripwire status
type TripwireInfo struct {
	Installed bool   `json:"installed"`
	Version   string `json:"version,omitempty"`
	Status    string `json:"status"`
}

// FileChange represents a detected file modification
type FileChange struct {
	FilePath    string `json:"file_path"`
	ChangeType  string `json:"change_type"` // added, removed, modified, attributes
	Description string `json:"description"`
	Severity    string `json:"severity"` // CRITICAL, HIGH, MEDIUM, LOW
}

// IntegrityIssue represents a file integrity security concern
type IntegrityIssue struct {
	Severity       string `json:"severity"` // CRITICAL, HIGH, MEDIUM, LOW
	Issue          string `json:"issue"`
	Recommendation string `json:"recommendation"`
}

// AnalyzeFileIntegrity performs file integrity monitoring checks
func AnalyzeFileIntegrity() *IntegrityStatus {
	status := &IntegrityStatus{
		ModifiedFiles: []FileChange{},
		Issues:        []IntegrityIssue{},
		SecurityScore: 100,
	}

	// Check AIDE
	status.AIDEStatus = checkAIDE()

	// Check Tripwire
	status.Tripwire = checkTripwire()

	// Evaluate integrity monitoring status
	status.evaluateIntegrityStatus()

	// Calculate risk level
	status.calculateIntegrityRisk()

	return status
}

// checkAIDE checks AIDE installation and status
func checkAIDE() AIDEInfo {
	info := AIDEInfo{
		Installed:      false,
		Initialized:    false,
		DatabaseExists: false,
		Status:         "Not installed",
	}

	// Check if AIDE is installed
	path, err := exec.LookPath("aide")
	if err != nil {
		return info
	}

	info.Installed = true

	// Get version
	cmd := exec.Command(path, "--version")
	output, err := cmd.Output()
	if err == nil {
		lines := strings.Split(string(output), "\n")
		for _, line := range lines {
			if strings.Contains(line, "AIDE") && strings.Contains(line, "version") {
				// Extract version
				re := regexp.MustCompile(`(\d+\.\d+[\.\d+]*)`)
				if matches := re.FindStringSubmatch(line); len(matches) > 0 {
					info.Version = matches[0]
				}
				break
			}
		}
	}

	// Check for AIDE database
	databasePaths := []string{
		"/var/lib/aide/aide.db",
		"/var/lib/aide/aide.db.gz",
		"/var/lib/aide.db",
		"/var/lib/aide.db.gz",
	}

	for _, dbPath := range databasePaths {
		if stat, err := os.Stat(dbPath); err == nil {
			info.DatabasePath = dbPath
			info.DatabaseExists = true
			info.Initialized = true

			// Calculate database age
			age := time.Since(stat.ModTime())
			info.DatabaseAge = int(age.Hours() / 24)

			break
		}
	}

	// Check for AIDE check results
	info.LastCheck, info.ChangesFound = parseAIDELog()

	// Determine status
	if !info.Initialized {
		info.Status = "Installed but not initialized"
	} else if info.ChangesFound > 0 {
		info.Status = fmt.Sprintf("%d file change(s) detected - Review required", info.ChangesFound)
	} else if info.DatabaseAge > 30 {
		info.Status = fmt.Sprintf("Database is %d days old - Update recommended", info.DatabaseAge)
	} else if !info.LastCheck.IsZero() {
		daysSince := int(time.Since(info.LastCheck).Hours() / 24)
		info.Status = fmt.Sprintf("Last check: %d days ago - No changes detected", daysSince)
	} else {
		info.Status = "Initialized - No checks performed yet"
	}

	return info
}

// parseAIDELog parses AIDE log file for recent check results
func parseAIDELog() (time.Time, int) {
	var lastCheck time.Time
	changes := 0

	logPaths := []string{
		"/var/log/aide/aide.log",
		"/var/log/aide.log",
	}

	var logFile string
	for _, path := range logPaths {
		if _, err := os.Stat(path); err == nil {
			logFile = path
			break
		}
	}

	if logFile == "" {
		return lastCheck, changes
	}

	file, err := os.Open(logFile)
	if err != nil {
		return lastCheck, changes
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	dateRegex := regexp.MustCompile(`(\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2})`)
	changesRegex := regexp.MustCompile(`(?i)(added|removed|changed).*files?`)

	for scanner.Scan() {
		line := scanner.Text()

		// Extract timestamp
		if matches := dateRegex.FindStringSubmatch(line); len(matches) > 1 {
			if t, err := time.Parse("2006-01-02 15:04:05", matches[1]); err == nil {
				if lastCheck.IsZero() || t.After(lastCheck) {
					lastCheck = t
				}
			}
		}

		// Count changes
		if changesRegex.MatchString(line) {
			// Try to extract number
			re := regexp.MustCompile(`(\d+)`)
			if matches := re.FindStringSubmatch(line); len(matches) > 0 {
				// This is a simplified count - real parsing would be more complex
				changes++
			}
		}

		// Look for specific change indicators
		if strings.Contains(line, "added:") || strings.Contains(line, "removed:") || strings.Contains(line, "changed:") {
			changes++
		}
	}

	return lastCheck, changes
}

// checkTripwire checks Tripwire installation and status
func checkTripwire() TripwireInfo {
	info := TripwireInfo{
		Installed: false,
		Status:    "Not installed",
	}

	// Check if Tripwire is installed
	path, err := exec.LookPath("tripwire")
	if err != nil {
		return info
	}

	info.Installed = true

	// Get version
	cmd := exec.Command(path, "--version")
	output, err := cmd.Output()
	if err == nil {
		lines := strings.Split(string(output), "\n")
		for _, line := range lines {
			if strings.Contains(line, "Tripwire") {
				re := regexp.MustCompile(`(\d+\.\d+[\.\d+]*)`)
				if matches := re.FindStringSubmatch(line); len(matches) > 0 {
					info.Version = matches[0]
				}
				break
			}
		}
	}

	info.Status = "Installed"

	return info
}

// evaluateIntegrityStatus evaluates file integrity monitoring status
func (i *IntegrityStatus) evaluateIntegrityStatus() {
	// Check if any FIM tool is installed
	if !i.AIDEStatus.Installed && !i.Tripwire.Installed {
		i.Issues = append(i.Issues, IntegrityIssue{
			Severity:       "HIGH",
			Issue:          "No File Integrity Monitoring (FIM) tool installed",
			Recommendation: "Install AIDE: sudo apt-get install aide && sudo aideinit",
		})
		i.SecurityScore -= 30
		return
	}

	// Evaluate AIDE
	if i.AIDEStatus.Installed {
		if !i.AIDEStatus.Initialized {
			i.Issues = append(i.Issues, IntegrityIssue{
				Severity:       "HIGH",
				Issue:          "AIDE is installed but database not initialized",
				Recommendation: "Initialize AIDE: sudo aideinit (this may take several minutes)",
			})
			i.SecurityScore -= 20
		} else {
			// Check if database is outdated
			if i.AIDEStatus.DatabaseAge > 90 {
				i.Issues = append(i.Issues, IntegrityIssue{
					Severity:       "MEDIUM",
					Issue:          fmt.Sprintf("AIDE database is %d days old (very outdated)", i.AIDEStatus.DatabaseAge),
					Recommendation: "Update AIDE database: sudo aide --update && sudo mv /var/lib/aide/aide.db.new /var/lib/aide/aide.db",
				})
				i.SecurityScore -= 15
			} else if i.AIDEStatus.DatabaseAge > 30 {
				i.Issues = append(i.Issues, IntegrityIssue{
					Severity:       "LOW",
					Issue:          fmt.Sprintf("AIDE database is %d days old", i.AIDEStatus.DatabaseAge),
					Recommendation: "Consider updating AIDE database: sudo aide --update",
				})
				i.SecurityScore -= 5
			}

			// Check if changes were detected
			if i.AIDEStatus.ChangesFound > 0 {
				severity := "MEDIUM"
				if i.AIDEStatus.ChangesFound > 10 {
					severity = "HIGH"
				}
				if i.AIDEStatus.ChangesFound > 50 {
					severity = "CRITICAL"
				}

				i.Issues = append(i.Issues, IntegrityIssue{
					Severity:       severity,
					Issue:          fmt.Sprintf("AIDE detected %d file change(s)", i.AIDEStatus.ChangesFound),
					Recommendation: "Review changes: sudo aide --check | less",
				})

				i.ChangesDetected = i.AIDEStatus.ChangesFound
				i.SecurityScore -= (i.AIDEStatus.ChangesFound * 2)
			}

			// Check if scans are being performed
			if i.AIDEStatus.LastCheck.IsZero() {
				i.Issues = append(i.Issues, IntegrityIssue{
					Severity:       "MEDIUM",
					Issue:          "No AIDE check results found",
					Recommendation: "Run AIDE check: sudo aide --check",
				})
				i.SecurityScore -= 10
			} else {
				daysSince := int(time.Since(i.AIDEStatus.LastCheck).Hours() / 24)
				if daysSince > 30 {
					i.Issues = append(i.Issues, IntegrityIssue{
						Severity:       "MEDIUM",
						Issue:          fmt.Sprintf("Last AIDE check was %d days ago", daysSince),
						Recommendation: "Run regular checks: sudo aide --check (consider adding to cron)",
					})
					i.SecurityScore -= 10
				}

				i.LastScanTime = i.AIDEStatus.LastCheck
			}

			// Suggest automation
			if !i.AIDEStatus.LastCheck.IsZero() {
				cronExists := checkAIDECron()
				if !cronExists {
					i.Issues = append(i.Issues, IntegrityIssue{
						Severity:       "LOW",
						Issue:          "AIDE is not scheduled to run automatically",
						Recommendation: "Schedule daily AIDE checks in cron: echo '0 3 * * * root /usr/bin/aide --check' | sudo tee -a /etc/cron.d/aide",
					})
					i.SecurityScore -= 5
				}
			}
		}
	}

	// Evaluate Tripwire
	if i.Tripwire.Installed {
		i.Issues = append(i.Issues, IntegrityIssue{
			Severity:       "INFO",
			Issue:          "Tripwire is installed",
			Recommendation: "Tripwire detected - ensure it's properly configured and running",
		})
	}
}

// checkAIDECron checks if AIDE is scheduled in cron
func checkAIDECron() bool {
	// Check common cron locations
	cronPaths := []string{
		"/etc/cron.d/aide",
		"/etc/cron.daily/aide",
		"/etc/crontab",
	}

	for _, cronPath := range cronPaths {
		file, err := os.Open(cronPath)
		if err != nil {
			continue
		}
		defer file.Close()

		scanner := bufio.NewScanner(file)
		for scanner.Scan() {
			line := scanner.Text()
			if strings.Contains(line, "aide") && !strings.HasPrefix(strings.TrimSpace(line), "#") {
				return true
			}
		}
	}

	return false
}

// calculateIntegrityRisk determines the overall integrity monitoring risk level
func (i *IntegrityStatus) calculateIntegrityRisk() {
	// Ensure score doesn't go negative
	if i.SecurityScore < 0 {
		i.SecurityScore = 0
	}

	// Determine risk level based on score
	if i.SecurityScore >= 80 {
		i.RiskLevel = "LOW"
	} else if i.SecurityScore >= 60 {
		i.RiskLevel = "MEDIUM"
	} else if i.SecurityScore >= 40 {
		i.RiskLevel = "HIGH"
	} else {
		i.RiskLevel = "CRITICAL"
	}
}

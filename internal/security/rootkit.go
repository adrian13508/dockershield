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

// RootkitStatus represents rootkit detection status
type RootkitStatus struct {
	RkhunterStatus   RkhunterInfo     `json:"rkhunter"`
	ChkrootkitStatus ChkrootkitInfo   `json:"chkrootkit"`
	LastScanTime     time.Time        `json:"last_scan_time,omitempty"`
	Warnings         []RootkitWarning `json:"warnings"`
	Issues           []RootkitIssue   `json:"issues"`
	RiskLevel        string           `json:"risk_level"`     // LOW, MEDIUM, HIGH, CRITICAL
	SecurityScore    int              `json:"security_score"` // 0-100
}

// RkhunterInfo represents rkhunter status
type RkhunterInfo struct {
	Installed       bool      `json:"installed"`
	Version         string    `json:"version,omitempty"`
	LastUpdate      time.Time `json:"last_update,omitempty"`
	LastScan        time.Time `json:"last_scan,omitempty"`
	DatabaseVersion string    `json:"database_version,omitempty"`
	WarningsFound   int       `json:"warnings_found"`
	SuspiciousFiles []string  `json:"suspicious_files,omitempty"`
	Status          string    `json:"status"`
}

// ChkrootkitInfo represents chkrootkit status
type ChkrootkitInfo struct {
	Installed       bool      `json:"installed"`
	Version         string    `json:"version,omitempty"`
	LastScan        time.Time `json:"last_scan,omitempty"`
	InfectionsFound int       `json:"infections_found"`
	SuspiciousItems []string  `json:"suspicious_items,omitempty"`
	Status          string    `json:"status"`
}

// RootkitWarning represents a rootkit detection warning
type RootkitWarning struct {
	Tool        string `json:"tool"`     // rkhunter or chkrootkit
	Severity    string `json:"severity"` // CRITICAL, HIGH, MEDIUM, LOW
	Item        string `json:"item"`     // File, process, or check name
	Description string `json:"description"`
}

// RootkitIssue represents a rootkit security concern
type RootkitIssue struct {
	Severity       string `json:"severity"` // CRITICAL, HIGH, MEDIUM, LOW
	Issue          string `json:"issue"`
	Recommendation string `json:"recommendation"`
}

// AnalyzeRootkit performs rootkit detection checks
func AnalyzeRootkit() *RootkitStatus {
	status := &RootkitStatus{
		Warnings:      []RootkitWarning{},
		Issues:        []RootkitIssue{},
		SecurityScore: 100,
	}

	// Check rkhunter
	status.RkhunterStatus = checkRkhunter()

	// Check chkrootkit
	status.ChkrootkitStatus = checkChkrootkit()

	// Evaluate overall status
	status.evaluateRootkitStatus()

	// Calculate risk level
	status.calculateRootkitRisk()

	return status
}

// checkRkhunter checks rkhunter installation and status
func checkRkhunter() RkhunterInfo {
	info := RkhunterInfo{
		Installed:       false,
		WarningsFound:   0,
		SuspiciousFiles: []string{},
		Status:          "Not installed",
	}

	// Check if rkhunter is installed
	path, err := exec.LookPath("rkhunter")
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
			if strings.Contains(line, "version") {
				parts := strings.Fields(line)
				if len(parts) >= 2 {
					info.Version = parts[len(parts)-1]
				}
				break
			}
		}
	}

	// Check if database is up to date
	info.DatabaseVersion = getRkhunterDatabaseVersion()

	// Try to get last scan results from log
	info.LastScan, info.WarningsFound, info.SuspiciousFiles = parseRkhunterLog()

	// Determine status
	if info.WarningsFound > 0 {
		info.Status = fmt.Sprintf("%d warning(s) found - Review required", info.WarningsFound)
	} else if !info.LastScan.IsZero() {
		daysSince := int(time.Since(info.LastScan).Hours() / 24)
		if daysSince > 30 {
			info.Status = fmt.Sprintf("Last scan: %d days ago (scan recommended)", daysSince)
		} else {
			info.Status = fmt.Sprintf("Last scan: %d days ago - No warnings", daysSince)
		}
	} else {
		info.Status = "Installed - No scan results found"
	}

	return info
}

// getRkhunterDatabaseVersion gets rkhunter database version
func getRkhunterDatabaseVersion() string {
	cmd := exec.Command("rkhunter", "--versioncheck")
	output, err := cmd.Output()
	if err != nil {
		return "unknown"
	}

	lines := strings.Split(string(output), "\n")
	for _, line := range lines {
		if strings.Contains(line, "database") || strings.Contains(line, "version") {
			parts := strings.Fields(line)
			if len(parts) > 0 {
				return parts[len(parts)-1]
			}
		}
	}

	return "unknown"
}

// parseRkhunterLog parses the rkhunter log file for recent scan results
func parseRkhunterLog() (time.Time, int, []string) {
	var lastScan time.Time
	warnings := 0
	suspicious := []string{}

	// Common log locations
	logPaths := []string{
		"/var/log/rkhunter.log",
		"/var/log/rkhunter/rkhunter.log",
	}

	var logFile string
	for _, path := range logPaths {
		if _, err := os.Stat(path); err == nil {
			logFile = path
			break
		}
	}

	if logFile == "" {
		return lastScan, warnings, suspicious
	}

	file, err := os.Open(logFile)
	if err != nil {
		return lastScan, warnings, suspicious
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	dateRegex := regexp.MustCompile(`\[([\d\-]+\s+[\d:]+)\]`)
	warningRegex := regexp.MustCompile(`(?i)warning|suspicious|infected`)

	var currentDate time.Time

	for scanner.Scan() {
		line := scanner.Text()

		// Extract timestamp
		if matches := dateRegex.FindStringSubmatch(line); len(matches) > 1 {
			if t, err := time.Parse("2006-01-02 15:04:05", matches[1]); err == nil {
				currentDate = t
				if lastScan.IsZero() || currentDate.After(lastScan) {
					lastScan = currentDate
				}
			}
		}

		// Look for warnings
		if warningRegex.MatchString(line) {
			warnings++
			// Extract suspicious file/item
			if strings.Contains(line, "Warning:") {
				parts := strings.Split(line, "Warning:")
				if len(parts) > 1 {
					item := strings.TrimSpace(parts[1])
					if len(item) > 0 && len(item) < 200 {
						suspicious = append(suspicious, item)
					}
				}
			}
		}
	}

	// Limit suspicious items to prevent huge arrays
	if len(suspicious) > 10 {
		suspicious = suspicious[:10]
	}

	return lastScan, warnings, suspicious
}

// checkChkrootkit checks chkrootkit installation and status
func checkChkrootkit() ChkrootkitInfo {
	info := ChkrootkitInfo{
		Installed:       false,
		InfectionsFound: 0,
		SuspiciousItems: []string{},
		Status:          "Not installed",
	}

	// Check if chkrootkit is installed
	path, err := exec.LookPath("chkrootkit")
	if err != nil {
		return info
	}

	info.Installed = true

	// Get version
	cmd := exec.Command(path, "-V")
	output, err := cmd.Output()
	if err == nil {
		version := strings.TrimSpace(string(output))
		if len(version) > 0 && len(version) < 50 {
			info.Version = version
		}
	}

	// Try to get last scan results from log
	info.LastScan, info.InfectionsFound, info.SuspiciousItems = parseChkrootkitLog()

	// Determine status
	if info.InfectionsFound > 0 {
		info.Status = fmt.Sprintf("%d potential infection(s) found - URGENT review required", info.InfectionsFound)
	} else if !info.LastScan.IsZero() {
		daysSince := int(time.Since(info.LastScan).Hours() / 24)
		if daysSince > 30 {
			info.Status = fmt.Sprintf("Last scan: %d days ago (scan recommended)", daysSince)
		} else {
			info.Status = fmt.Sprintf("Last scan: %d days ago - Clean", daysSince)
		}
	} else {
		info.Status = "Installed - No scan results found"
	}

	return info
}

// parseChkrootkitLog parses the chkrootkit log file for recent scan results
func parseChkrootkitLog() (time.Time, int, []string) {
	var lastScan time.Time
	infections := 0
	suspicious := []string{}

	// Common log locations
	logPaths := []string{
		"/var/log/chkrootkit.log",
		"/var/log/chkrootkit/chkrootkit.log",
	}

	var logFile string
	for _, path := range logPaths {
		if _, err := os.Stat(path); err == nil {
			logFile = path
			break
		}
	}

	if logFile == "" {
		return lastScan, infections, suspicious
	}

	file, err := os.Open(logFile)
	if err != nil {
		return lastScan, infections, suspicious
	}
	defer file.Close()

	// Get file modification time as last scan time
	if stat, err := file.Stat(); err == nil {
		lastScan = stat.ModTime()
	}

	scanner := bufio.NewScanner(file)
	infectedRegex := regexp.MustCompile(`(?i)INFECTED|Vulnerable`)

	for scanner.Scan() {
		line := scanner.Text()

		// Look for infections
		if infectedRegex.MatchString(line) {
			infections++
			item := strings.TrimSpace(line)
			if len(item) > 0 && len(item) < 200 {
				suspicious = append(suspicious, item)
			}
		}
	}

	// Limit suspicious items
	if len(suspicious) > 10 {
		suspicious = suspicious[:10]
	}

	return lastScan, infections, suspicious
}

// evaluateRootkitStatus evaluates rootkit detection status and creates issues
func (r *RootkitStatus) evaluateRootkitStatus() {
	// Check if any rootkit scanner is installed
	if !r.RkhunterStatus.Installed && !r.ChkrootkitStatus.Installed {
		r.Issues = append(r.Issues, RootkitIssue{
			Severity:       "HIGH",
			Issue:          "No rootkit detection tools installed",
			Recommendation: "Install rkhunter: sudo apt-get install rkhunter (Debian/Ubuntu) or sudo yum install rkhunter (RHEL/CentOS)",
		})
		r.SecurityScore -= 25
		return
	}

	// Evaluate rkhunter
	if r.RkhunterStatus.Installed {
		if r.RkhunterStatus.WarningsFound > 0 {
			severity := "MEDIUM"
			if r.RkhunterStatus.WarningsFound >= 5 {
				severity = "HIGH"
			}
			if r.RkhunterStatus.WarningsFound >= 10 {
				severity = "CRITICAL"
			}

			r.Issues = append(r.Issues, RootkitIssue{
				Severity:       severity,
				Issue:          fmt.Sprintf("rkhunter found %d warning(s)", r.RkhunterStatus.WarningsFound),
				Recommendation: "Review warnings: sudo rkhunter --check --report-warnings-only",
			})

			// Add individual warnings
			for i, item := range r.RkhunterStatus.SuspiciousFiles {
				if i >= 5 {
					break // Limit to 5 warnings
				}
				r.Warnings = append(r.Warnings, RootkitWarning{
					Tool:        "rkhunter",
					Severity:    severity,
					Item:        item,
					Description: "Suspicious file or configuration detected",
				})
			}

			r.SecurityScore -= (r.RkhunterStatus.WarningsFound * 5)
		}

		// Check if scan is outdated
		if !r.RkhunterStatus.LastScan.IsZero() {
			daysSince := int(time.Since(r.RkhunterStatus.LastScan).Hours() / 24)
			if daysSince > 30 {
				r.Issues = append(r.Issues, RootkitIssue{
					Severity:       "MEDIUM",
					Issue:          fmt.Sprintf("rkhunter scan is %d days old", daysSince),
					Recommendation: "Run scan: sudo rkhunter --check --skip-keypress",
				})
				r.SecurityScore -= 10
			}
		} else {
			r.Issues = append(r.Issues, RootkitIssue{
				Severity:       "MEDIUM",
				Issue:          "No rkhunter scan results found",
				Recommendation: "Run initial scan: sudo rkhunter --update && sudo rkhunter --propupd && sudo rkhunter --check --skip-keypress",
			})
			r.SecurityScore -= 10
		}

		// Update last scan time
		if !r.RkhunterStatus.LastScan.IsZero() && (r.LastScanTime.IsZero() || r.RkhunterStatus.LastScan.After(r.LastScanTime)) {
			r.LastScanTime = r.RkhunterStatus.LastScan
		}
	}

	// Evaluate chkrootkit
	if r.ChkrootkitStatus.Installed {
		if r.ChkrootkitStatus.InfectionsFound > 0 {
			severity := "HIGH"
			if r.ChkrootkitStatus.InfectionsFound >= 5 {
				severity = "CRITICAL"
			}

			r.Issues = append(r.Issues, RootkitIssue{
				Severity:       severity,
				Issue:          fmt.Sprintf("chkrootkit found %d potential infection(s)", r.ChkrootkitStatus.InfectionsFound),
				Recommendation: "URGENT: Review detections: sudo chkrootkit",
			})

			// Add individual infections
			for i, item := range r.ChkrootkitStatus.SuspiciousItems {
				if i >= 5 {
					break
				}
				r.Warnings = append(r.Warnings, RootkitWarning{
					Tool:        "chkrootkit",
					Severity:    severity,
					Item:        item,
					Description: "Potential rootkit or suspicious activity",
				})
			}

			r.SecurityScore -= (r.ChkrootkitStatus.InfectionsFound * 10)
		}

		// Check if scan is outdated
		if !r.ChkrootkitStatus.LastScan.IsZero() {
			daysSince := int(time.Since(r.ChkrootkitStatus.LastScan).Hours() / 24)
			if daysSince > 30 {
				r.Issues = append(r.Issues, RootkitIssue{
					Severity:       "MEDIUM",
					Issue:          fmt.Sprintf("chkrootkit scan is %d days old", daysSince),
					Recommendation: "Run scan: sudo chkrootkit",
				})
				r.SecurityScore -= 10
			}
		} else {
			r.Issues = append(r.Issues, RootkitIssue{
				Severity:       "MEDIUM",
				Issue:          "No chkrootkit scan results found",
				Recommendation: "Run initial scan: sudo chkrootkit | tee /var/log/chkrootkit.log",
			})
			r.SecurityScore -= 10
		}

		// Update last scan time
		if !r.ChkrootkitStatus.LastScan.IsZero() && (r.LastScanTime.IsZero() || r.ChkrootkitStatus.LastScan.After(r.LastScanTime)) {
			r.LastScanTime = r.ChkrootkitStatus.LastScan
		}
	}

	// Recommend having both tools
	if r.RkhunterStatus.Installed && !r.ChkrootkitStatus.Installed {
		r.Issues = append(r.Issues, RootkitIssue{
			Severity:       "LOW",
			Issue:          "Only rkhunter installed (chkrootkit provides additional coverage)",
			Recommendation: "Install chkrootkit: sudo apt-get install chkrootkit",
		})
		r.SecurityScore -= 5
	} else if !r.RkhunterStatus.Installed && r.ChkrootkitStatus.Installed {
		r.Issues = append(r.Issues, RootkitIssue{
			Severity:       "LOW",
			Issue:          "Only chkrootkit installed (rkhunter provides additional coverage)",
			Recommendation: "Install rkhunter: sudo apt-get install rkhunter",
		})
		r.SecurityScore -= 5
	}
}

// calculateRootkitRisk determines the overall rootkit detection risk level
func (r *RootkitStatus) calculateRootkitRisk() {
	// Ensure score doesn't go negative
	if r.SecurityScore < 0 {
		r.SecurityScore = 0
	}

	// Determine risk level based on score
	if r.SecurityScore >= 80 {
		r.RiskLevel = "LOW"
	} else if r.SecurityScore >= 60 {
		r.RiskLevel = "MEDIUM"
	} else if r.SecurityScore >= 40 {
		r.RiskLevel = "HIGH"
	} else {
		r.RiskLevel = "CRITICAL"
	}
}

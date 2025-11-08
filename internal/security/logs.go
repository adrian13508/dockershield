package security

import (
	"bufio"
	"fmt"
	"os"
	"os/exec"
	"regexp"
	"sort"
	"strings"
)

// LogAnalysisStatus represents system log analysis results
type LogAnalysisStatus struct {
	AuthLog        AuthLogAnalysis   `json:"auth_log"`
	SudoLog        SudoLogAnalysis   `json:"sudo_log"`
	SystemLog      SystemLogAnalysis `json:"system_log,omitempty"`
	SecurityEvents []SecurityEvent   `json:"security_events"`
	Issues         []LogIssue        `json:"issues"`
	RiskLevel      string            `json:"risk_level"`     // LOW, MEDIUM, HIGH, CRITICAL
	SecurityScore  int               `json:"security_score"` // 0-100
}

// AuthLogAnalysis represents authentication log analysis
type AuthLogAnalysis struct {
	LogFile             string         `json:"log_file"`
	LogAvailable        bool           `json:"log_available"`
	AnalyzedLines       int            `json:"analyzed_lines"`
	TimeRange           string         `json:"time_range"`
	FailedLogins        int            `json:"failed_logins"`
	SuccessfulLogins    int            `json:"successful_logins"`
	FailedUsers         map[string]int `json:"failed_users"`
	SuccessfulUsers     map[string]int `json:"successful_users"`
	FailedIPs           map[string]int `json:"failed_ips"`
	SuspiciousActivity  []string       `json:"suspicious_activity,omitempty"`
	RootLoginAttempts   int            `json:"root_login_attempts"`
	InvalidUserAttempts int            `json:"invalid_user_attempts"`
}

// SudoLogAnalysis represents sudo usage analysis
type SudoLogAnalysis struct {
	LogAvailable       bool           `json:"log_available"`
	AnalyzedLines      int            `json:"analyzed_lines"`
	TimeRange          string         `json:"time_range"`
	SudoCommands       int            `json:"sudo_commands_executed"`
	SudoUsers          map[string]int `json:"sudo_users"`
	FailedSudoAttempts int            `json:"failed_sudo_attempts"`
	RootSessions       int            `json:"root_sessions"`
	SuspiciousCommands []SudoCommand  `json:"suspicious_commands,omitempty"`
}

// SystemLogAnalysis represents general system log analysis
type SystemLogAnalysis struct {
	LogAvailable    bool `json:"log_available"`
	Errors          int  `json:"errors"`
	Warnings        int  `json:"warnings"`
	CriticalEvents  int  `json:"critical_events"`
	ServiceFailures int  `json:"service_failures"`
}

// SudoCommand represents a sudo command execution
type SudoCommand struct {
	Timestamp  string `json:"timestamp"`
	User       string `json:"user"`
	Command    string `json:"command"`
	Suspicious bool   `json:"suspicious"`
	Reason     string `json:"reason,omitempty"`
}

// SecurityEvent represents a security-relevant event
type SecurityEvent struct {
	Timestamp   string `json:"timestamp"`
	Severity    string `json:"severity"` // CRITICAL, HIGH, MEDIUM, LOW
	Source      string `json:"source"`   // auth, sudo, system
	Event       string `json:"event"`
	Description string `json:"description"`
}

// LogIssue represents a log analysis security concern
type LogIssue struct {
	Severity       string `json:"severity"` // CRITICAL, HIGH, MEDIUM, LOW
	Issue          string `json:"issue"`
	Recommendation string `json:"recommendation"`
}

// AnalyzeLogs performs comprehensive system log analysis
func AnalyzeLogs() *LogAnalysisStatus {
	status := &LogAnalysisStatus{
		SecurityEvents: []SecurityEvent{},
		Issues:         []LogIssue{},
		SecurityScore:  100,
	}

	// Analyze authentication logs
	status.AuthLog = analyzeAuthLogs()

	// Analyze sudo logs
	status.SudoLog = analyzeSudoLogs()

	// Analyze system logs (optional, lighter check)
	status.SystemLog = analyzeSystemLogs()

	// Extract security events
	status.extractSecurityEvents()

	// Evaluate log analysis findings
	status.evaluateLogFindings()

	// Calculate risk level
	status.calculateLogRisk()

	return status
}

// analyzeAuthLogs analyzes authentication logs
func analyzeAuthLogs() AuthLogAnalysis {
	analysis := AuthLogAnalysis{
		LogAvailable:       false,
		FailedUsers:        make(map[string]int),
		SuccessfulUsers:    make(map[string]int),
		FailedIPs:          make(map[string]int),
		SuspiciousActivity: []string{},
	}

	// Find auth log file
	logPaths := []string{
		"/var/log/auth.log",
		"/var/log/secure",
	}

	var logFile string
	for _, path := range logPaths {
		if _, err := os.Stat(path); err == nil {
			logFile = path
			analysis.LogFile = path
			break
		}
	}

	if logFile == "" {
		return analysis
	}

	analysis.LogAvailable = true

	// Open log file
	file, err := os.Open(logFile)
	if err != nil {
		return analysis
	}
	defer file.Close()

	// Regex patterns
	failedLoginRegex := regexp.MustCompile(`(?i)failed password|authentication failure|invalid user`)
	successLoginRegex := regexp.MustCompile(`(?i)accepted password|accepted publickey|session opened`)
	userRegex := regexp.MustCompile(`for\s+(\w+)\s+from`)
	ipRegex := regexp.MustCompile(`from\s+([\d\.]+)`)
	rootLoginRegex := regexp.MustCompile(`(?i)for root|user root`)
	invalidUserRegex := regexp.MustCompile(`(?i)invalid user\s+(\w+)`)

	scanner := bufio.NewScanner(file)
	var firstTime, lastTime string

	// Limit analysis to last 10000 lines for performance
	lines := []string{}
	for scanner.Scan() {
		lines = append(lines, scanner.Text())
	}

	// Analyze last 10000 lines
	startIdx := 0
	if len(lines) > 10000 {
		startIdx = len(lines) - 10000
	}

	for i := startIdx; i < len(lines); i++ {
		line := lines[i]
		analysis.AnalyzedLines++

		// Extract timestamp (first occurrence)
		if firstTime == "" && len(line) > 15 {
			firstTime = line[:15]
		}
		if len(line) > 15 {
			lastTime = line[:15]
		}

		// Check for failed logins
		if failedLoginRegex.MatchString(line) {
			analysis.FailedLogins++

			// Extract username
			if matches := userRegex.FindStringSubmatch(line); len(matches) > 1 {
				username := matches[1]
				analysis.FailedUsers[username]++
			}

			// Extract IP
			if matches := ipRegex.FindStringSubmatch(line); len(matches) > 1 {
				ip := matches[1]
				analysis.FailedIPs[ip]++
			}

			// Check for root attempts
			if rootLoginRegex.MatchString(line) {
				analysis.RootLoginAttempts++
			}

			// Check for invalid users
			if invalidUserRegex.MatchString(line) {
				analysis.InvalidUserAttempts++
			}
		}

		// Check for successful logins
		if successLoginRegex.MatchString(line) {
			analysis.SuccessfulLogins++

			// Extract username
			if matches := userRegex.FindStringSubmatch(line); len(matches) > 1 {
				username := matches[1]
				analysis.SuccessfulUsers[username]++
			}
		}
	}

	analysis.TimeRange = fmt.Sprintf("%s to %s", firstTime, lastTime)

	// Detect suspicious patterns
	// 1. Multiple failed attempts from same IP
	for ip, count := range analysis.FailedIPs {
		if count > 10 {
			analysis.SuspiciousActivity = append(analysis.SuspiciousActivity,
				fmt.Sprintf("IP %s: %d failed login attempts (possible brute force)", ip, count))
		}
	}

	// 2. Failed attempts for non-existent users
	if analysis.InvalidUserAttempts > 5 {
		analysis.SuspiciousActivity = append(analysis.SuspiciousActivity,
			fmt.Sprintf("Username enumeration: %d attempts with invalid usernames", analysis.InvalidUserAttempts))
	}

	// 3. Root login attempts
	if analysis.RootLoginAttempts > 0 {
		analysis.SuspiciousActivity = append(analysis.SuspiciousActivity,
			fmt.Sprintf("Direct root login attempts: %d (should be disabled)", analysis.RootLoginAttempts))
	}

	return analysis
}

// analyzeSudoLogs analyzes sudo command usage
func analyzeSudoLogs() SudoLogAnalysis {
	analysis := SudoLogAnalysis{
		LogAvailable:       false,
		SudoUsers:          make(map[string]int),
		SuspiciousCommands: []SudoCommand{},
	}

	// Find auth log (sudo logs are usually in auth.log)
	logPaths := []string{
		"/var/log/auth.log",
		"/var/log/secure",
	}

	var logFile string
	for _, path := range logPaths {
		if _, err := os.Stat(path); err == nil {
			logFile = path
			break
		}
	}

	if logFile == "" {
		return analysis
	}

	analysis.LogAvailable = true

	file, err := os.Open(logFile)
	if err != nil {
		return analysis
	}
	defer file.Close()

	sudoRegex := regexp.MustCompile(`sudo:?\s+(\w+)\s+:.*COMMAND=(.+)`)
	sudoFailRegex := regexp.MustCompile(`sudo:?\s+(\w+)\s+:.*NOT in sudoers`)
	suSessionRegex := regexp.MustCompile(`su\[\d+\]:\s+\(to root\)`)

	scanner := bufio.NewScanner(file)
	var firstTime, lastTime string

	// Limit analysis
	lines := []string{}
	for scanner.Scan() {
		lines = append(lines, scanner.Text())
	}

	startIdx := 0
	if len(lines) > 10000 {
		startIdx = len(lines) - 10000
	}

	for i := startIdx; i < len(lines); i++ {
		line := lines[i]

		if !strings.Contains(line, "sudo") && !strings.Contains(line, "su[") {
			continue
		}

		analysis.AnalyzedLines++

		// Extract timestamp
		if firstTime == "" && len(line) > 15 {
			firstTime = line[:15]
		}
		if len(line) > 15 {
			lastTime = line[:15]
		}

		// Check for sudo commands
		if matches := sudoRegex.FindStringSubmatch(line); len(matches) > 2 {
			user := matches[1]
			command := matches[2]

			analysis.SudoCommands++
			analysis.SudoUsers[user]++

			// Check for suspicious commands
			suspicious := false
			reason := ""

			suspiciousPatterns := map[string]string{
				"rm -rf /":       "Dangerous delete command",
				"chmod 777":      "Insecure permission change",
				"iptables -F":    "Firewall flush",
				"ufw disable":    "Firewall disable",
				"setenforce 0":   "SELinux disable",
				"passwd":         "Password change",
				"userdel":        "User deletion",
				"visudo":         "Sudoers modification",
				"/etc/shadow":    "Shadow file access",
				"pkill":          "Process termination",
				"systemctl stop": "Service stop",
			}

			for pattern, desc := range suspiciousPatterns {
				if strings.Contains(strings.ToLower(command), strings.ToLower(pattern)) {
					suspicious = true
					reason = desc
					break
				}
			}

			if suspicious {
				cmd := SudoCommand{
					Timestamp:  firstTime,
					User:       user,
					Command:    command,
					Suspicious: true,
					Reason:     reason,
				}
				analysis.SuspiciousCommands = append(analysis.SuspiciousCommands, cmd)
			}
		}

		// Check for failed sudo attempts
		if sudoFailRegex.MatchString(line) {
			analysis.FailedSudoAttempts++
		}

		// Check for su to root
		if suSessionRegex.MatchString(line) {
			analysis.RootSessions++
		}
	}

	analysis.TimeRange = fmt.Sprintf("%s to %s", firstTime, lastTime)

	return analysis
}

// analyzeSystemLogs performs light analysis of system logs
func analyzeSystemLogs() SystemLogAnalysis {
	analysis := SystemLogAnalysis{
		LogAvailable: false,
	}

	logPaths := []string{
		"/var/log/syslog",
		"/var/log/messages",
	}

	var logFile string
	for _, path := range logPaths {
		if _, err := os.Stat(path); err == nil {
			logFile = path
			break
		}
	}

	if logFile == "" {
		return analysis
	}

	analysis.LogAvailable = true

	// Use journalctl if available for better performance
	if _, err := exec.LookPath("journalctl"); err == nil {
		// Get error count from last 24 hours
		cmd := exec.Command("journalctl", "--since", "24 hours ago", "-p", "err", "--no-pager")
		output, err := cmd.Output()
		if err == nil {
			lines := strings.Split(string(output), "\n")
			analysis.Errors = len(lines) - 1 // subtract header
		}

		// Get warnings
		cmd = exec.Command("journalctl", "--since", "24 hours ago", "-p", "warning", "--no-pager")
		output, err = cmd.Output()
		if err == nil {
			lines := strings.Split(string(output), "\n")
			analysis.Warnings = len(lines) - 1
		}

		// Get critical
		cmd = exec.Command("journalctl", "--since", "24 hours ago", "-p", "crit", "--no-pager")
		output, err = cmd.Output()
		if err == nil {
			lines := strings.Split(string(output), "\n")
			analysis.CriticalEvents = len(lines) - 1
		}
	}

	return analysis
}

// extractSecurityEvents consolidates security events from all logs
func (l *LogAnalysisStatus) extractSecurityEvents() {
	// Add failed login events
	if l.AuthLog.FailedLogins > 20 {
		severity := "MEDIUM"
		if l.AuthLog.FailedLogins > 100 {
			severity = "HIGH"
		}
		if l.AuthLog.FailedLogins > 500 {
			severity = "CRITICAL"
		}

		l.SecurityEvents = append(l.SecurityEvents, SecurityEvent{
			Timestamp:   l.AuthLog.TimeRange,
			Severity:    severity,
			Source:      "auth",
			Event:       "multiple_failed_logins",
			Description: fmt.Sprintf("%d failed login attempts", l.AuthLog.FailedLogins),
		})
	}

	// Add suspicious sudo commands
	for _, cmd := range l.SudoLog.SuspiciousCommands {
		l.SecurityEvents = append(l.SecurityEvents, SecurityEvent{
			Timestamp:   cmd.Timestamp,
			Severity:    "MEDIUM",
			Source:      "sudo",
			Event:       "suspicious_sudo_command",
			Description: fmt.Sprintf("User %s executed: %s (%s)", cmd.User, cmd.Command, cmd.Reason),
		})
	}

	// Add root login attempts
	if l.AuthLog.RootLoginAttempts > 0 {
		l.SecurityEvents = append(l.SecurityEvents, SecurityEvent{
			Timestamp:   l.AuthLog.TimeRange,
			Severity:    "HIGH",
			Source:      "auth",
			Event:       "root_login_attempt",
			Description: fmt.Sprintf("%d direct root login attempts", l.AuthLog.RootLoginAttempts),
		})
	}

	// Sort events by severity
	sort.Slice(l.SecurityEvents, func(i, j int) bool {
		severityOrder := map[string]int{"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1}
		return severityOrder[l.SecurityEvents[i].Severity] > severityOrder[l.SecurityEvents[j].Severity]
	})

	// Limit to top 20 events
	if len(l.SecurityEvents) > 20 {
		l.SecurityEvents = l.SecurityEvents[:20]
	}
}

// evaluateLogFindings evaluates log analysis findings
func (l *LogAnalysisStatus) evaluateLogFindings() {
	// Check if logs are available
	if !l.AuthLog.LogAvailable {
		l.Issues = append(l.Issues, LogIssue{
			Severity:       "HIGH",
			Issue:          "Authentication logs not found or not readable",
			Recommendation: "Check /var/log/auth.log or /var/log/secure permissions",
		})
		l.SecurityScore -= 20
		return
	}

	// Analyze failed logins
	if l.AuthLog.FailedLogins > 500 {
		l.Issues = append(l.Issues, LogIssue{
			Severity:       "CRITICAL",
			Issue:          fmt.Sprintf("%d failed login attempts detected (possible attack)", l.AuthLog.FailedLogins),
			Recommendation: "Review fail2ban status, check suspicious IPs, consider blocking ranges",
		})
		l.SecurityScore -= 30
	} else if l.AuthLog.FailedLogins > 100 {
		l.Issues = append(l.Issues, LogIssue{
			Severity:       "HIGH",
			Issue:          fmt.Sprintf("%d failed login attempts detected", l.AuthLog.FailedLogins),
			Recommendation: "Enable fail2ban or review firewall rules to block repeated attempts",
		})
		l.SecurityScore -= 20
	} else if l.AuthLog.FailedLogins > 20 {
		l.Issues = append(l.Issues, LogIssue{
			Severity:       "MEDIUM",
			Issue:          fmt.Sprintf("%d failed login attempts detected", l.AuthLog.FailedLogins),
			Recommendation: "Monitor authentication logs regularly",
		})
		l.SecurityScore -= 10
	}

	// Check for root login attempts
	if l.AuthLog.RootLoginAttempts > 0 {
		l.Issues = append(l.Issues, LogIssue{
			Severity:       "HIGH",
			Issue:          fmt.Sprintf("%d direct root login attempts (root login should be disabled)", l.AuthLog.RootLoginAttempts),
			Recommendation: "Disable root login in SSH: Set 'PermitRootLogin no' in /etc/ssh/sshd_config",
		})
		l.SecurityScore -= 15
	}

	// Check for username enumeration
	if l.AuthLog.InvalidUserAttempts > 10 {
		l.Issues = append(l.Issues, LogIssue{
			Severity:       "MEDIUM",
			Issue:          fmt.Sprintf("%d invalid username attempts (username enumeration attack)", l.AuthLog.InvalidUserAttempts),
			Recommendation: "Configure fail2ban to block repeated invalid user attempts",
		})
		l.SecurityScore -= 10
	}

	// Check suspicious sudo commands
	if len(l.SudoLog.SuspiciousCommands) > 0 {
		l.Issues = append(l.Issues, LogIssue{
			Severity:       "MEDIUM",
			Issue:          fmt.Sprintf("%d suspicious sudo commands executed", len(l.SudoLog.SuspiciousCommands)),
			Recommendation: "Review sudo command history and verify administrative actions",
		})
		l.SecurityScore -= (len(l.SudoLog.SuspiciousCommands) * 5)
	}

	// Check failed sudo attempts
	if l.SudoLog.FailedSudoAttempts > 5 {
		l.Issues = append(l.Issues, LogIssue{
			Severity:       "MEDIUM",
			Issue:          fmt.Sprintf("%d failed sudo attempts (unauthorized privilege escalation?)", l.SudoLog.FailedSudoAttempts),
			Recommendation: "Investigate users attempting unauthorized sudo access",
		})
		l.SecurityScore -= 10
	}

	// Check system errors
	if l.SystemLog.LogAvailable && l.SystemLog.CriticalEvents > 10 {
		l.Issues = append(l.Issues, LogIssue{
			Severity:       "MEDIUM",
			Issue:          fmt.Sprintf("%d critical system events in last 24 hours", l.SystemLog.CriticalEvents),
			Recommendation: "Review system logs: journalctl -p crit --since '24 hours ago'",
		})
		l.SecurityScore -= 5
	}

	// Add suspicious IP summary
	if len(l.AuthLog.FailedIPs) > 0 {
		topIPs := getTopFailedIPs(l.AuthLog.FailedIPs, 5)
		if len(topIPs) > 0 {
			ipList := []string{}
			for _, ip := range topIPs {
				ipList = append(ipList, fmt.Sprintf("%s (%d attempts)", ip.IP, ip.Count))
			}

			l.Issues = append(l.Issues, LogIssue{
				Severity:       "INFO",
				Issue:          fmt.Sprintf("Top attacking IPs: %s", strings.Join(ipList, ", ")),
				Recommendation: "Consider blocking these IPs in firewall or adding to fail2ban",
			})
		}
	}
}

// IPCount for sorting IPs by failure count
type IPCount struct {
	IP    string
	Count int
}

// getTopFailedIPs returns top N IPs by failed login count
func getTopFailedIPs(failedIPs map[string]int, n int) []IPCount {
	ipCounts := []IPCount{}
	for ip, count := range failedIPs {
		ipCounts = append(ipCounts, IPCount{IP: ip, Count: count})
	}

	sort.Slice(ipCounts, func(i, j int) bool {
		return ipCounts[i].Count > ipCounts[j].Count
	})

	if len(ipCounts) > n {
		ipCounts = ipCounts[:n]
	}

	return ipCounts
}

// calculateLogRisk determines the overall log analysis risk level
func (l *LogAnalysisStatus) calculateLogRisk() {
	// Ensure score doesn't go negative
	if l.SecurityScore < 0 {
		l.SecurityScore = 0
	}

	// Determine risk level based on score
	if l.SecurityScore >= 85 {
		l.RiskLevel = "LOW"
	} else if l.SecurityScore >= 70 {
		l.RiskLevel = "MEDIUM"
	} else if l.SecurityScore >= 50 {
		l.RiskLevel = "HIGH"
	} else {
		l.RiskLevel = "CRITICAL"
	}
}

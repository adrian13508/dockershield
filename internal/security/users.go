package security

import (
	"bufio"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"
)

// UserHardeningStatus represents user and sudo security configuration
type UserHardeningStatus struct {
	SudoConfig     SudoConfig          `json:"sudo_config"`
	UserAccounts   []UserAccount       `json:"user_accounts"`
	PasswordPolicy PasswordPolicy      `json:"password_policy"`
	LoginConfig    LoginConfig         `json:"login_config"`
	Issues         []UserSecurityIssue `json:"issues"`
	RiskLevel      string              `json:"risk_level"`     // LOW, MEDIUM, HIGH, CRITICAL
	SecurityScore  int                 `json:"security_score"` // 0-100
}

// SudoConfig represents sudo configuration
type SudoConfig struct {
	SudoersFile       string   `json:"sudoers_file"`
	NoPasswordUsers   []string `json:"nopasswd_users"`
	PasswordlessCount int      `json:"passwordless_count"`
	SudoGroupMembers  []string `json:"sudo_group_members"`
	CustomSudoers     []string `json:"custom_sudoers_files"`
	UseTimestamp      bool     `json:"use_timestamp"`
	TimestampTimeout  int      `json:"timestamp_timeout_minutes"`
	RequireTTY        bool     `json:"require_tty"`
	Issues            []string `json:"issues"`
}

// UserAccount represents a system user account
type UserAccount struct {
	Username        string `json:"username"`
	UID             int    `json:"uid"`
	GID             int    `json:"gid"`
	Home            string `json:"home"`
	Shell           string `json:"shell"`
	EmptyPassword   bool   `json:"empty_password"`
	Locked          bool   `json:"locked"`
	PasswordExpired bool   `json:"password_expired"`
	InSudoGroup     bool   `json:"in_sudo_group"`
	LastLogin       string `json:"last_login,omitempty"`
	RiskLevel       string `json:"risk_level"` // OK, LOW, MEDIUM, HIGH, CRITICAL
}

// PasswordPolicy represents system password policy settings
type PasswordPolicy struct {
	MinLength         int    `json:"min_length"`
	MaxDays           int    `json:"max_days"`
	MinDays           int    `json:"min_days"`
	WarnAge           int    `json:"warn_age"`
	RequireUppercase  bool   `json:"require_uppercase"`
	RequireLowercase  bool   `json:"require_lowercase"`
	RequireDigits     bool   `json:"require_digits"`
	RequireSpecial    bool   `json:"require_special"`
	RememberPasswords int    `json:"remember_passwords"`
	PolicySource      string `json:"policy_source"` // /etc/login.defs, PAM, etc.
}

// LoginConfig represents login security settings
type LoginConfig struct {
	LoginTimeout  int    `json:"login_timeout_seconds"`
	LoginRetries  int    `json:"login_retries"`
	FailDelay     int    `json:"fail_delay_seconds"`
	UmaskValue    string `json:"umask"`
	CreateHomeDir bool   `json:"create_home_dir"`
	EncryptMethod string `json:"encrypt_method"`
}

// UserSecurityIssue represents a user/sudo security concern
type UserSecurityIssue struct {
	Severity       string `json:"severity"` // CRITICAL, HIGH, MEDIUM, LOW
	Issue          string `json:"issue"`
	Recommendation string `json:"recommendation"`
}

// AnalyzeUserSecurity performs comprehensive user and sudo security checks
func AnalyzeUserSecurity() *UserHardeningStatus {
	status := &UserHardeningStatus{
		Issues:        []UserSecurityIssue{},
		SecurityScore: 100,
	}

	// Analyze sudo configuration
	status.SudoConfig = analyzeSudoConfig()

	// Analyze user accounts
	status.UserAccounts = analyzeUserAccounts()

	// Check password policy
	status.PasswordPolicy = analyzePasswordPolicy()

	// Check login configuration
	status.LoginConfig = analyzeLoginConfig()

	// Evaluate security issues
	status.evaluateUserSecurity()

	// Calculate overall risk
	status.calculateUserRiskLevel()

	return status
}

// analyzeSudoConfig analyzes sudo configuration
func analyzeSudoConfig() SudoConfig {
	config := SudoConfig{
		SudoersFile:       "/etc/sudoers",
		NoPasswordUsers:   []string{},
		CustomSudoers:     []string{},
		PasswordlessCount: 0,
		SudoGroupMembers:  []string{},
		TimestampTimeout:  15, // default
		RequireTTY:        false,
		Issues:            []string{},
	}

	// Check if sudoers file exists
	if _, err := os.Stat(config.SudoersFile); os.IsNotExist(err) {
		config.Issues = append(config.Issues, "Sudoers file not found")
		return config
	}

	// Parse sudoers file (need root privileges)
	parseSudoersFile(&config)

	// Check for custom sudoers files in /etc/sudoers.d/
	customFiles, err := filepath.Glob("/etc/sudoers.d/*")
	if err == nil {
		config.CustomSudoers = customFiles
	}

	// Get members of sudo group
	config.SudoGroupMembers = getSudoGroupMembers()

	return config
}

// parseSudoersFile parses the sudoers configuration
func parseSudoersFile(config *SudoConfig) {
	// Try to read sudoers file (may need root)
	file, err := os.Open(config.SudoersFile)
	if err != nil {
		config.Issues = append(config.Issues, fmt.Sprintf("Cannot read sudoers file: %v (need root)", err))
		return
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	nopasswdRegex := regexp.MustCompile(`(?i)NOPASSWD`)
	timestampRegex := regexp.MustCompile(`Defaults\s+timestamp_timeout=(\d+)`)
	requireTTYRegex := regexp.MustCompile(`Defaults\s+requiretty`)
	commentRegex := regexp.MustCompile(`^\s*#`)

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())

		// Skip comments and empty lines
		if line == "" || commentRegex.MatchString(line) {
			continue
		}

		// Check for NOPASSWD entries
		if nopasswdRegex.MatchString(line) {
			config.PasswordlessCount++
			// Extract username if possible
			parts := strings.Fields(line)
			if len(parts) > 0 && !strings.HasPrefix(parts[0], "Defaults") {
				username := parts[0]
				if !strings.HasPrefix(username, "%") { // not a group
					config.NoPasswordUsers = append(config.NoPasswordUsers, username)
				}
			}
		}

		// Check for timestamp_timeout
		if matches := timestampRegex.FindStringSubmatch(line); len(matches) > 1 {
			if timeout, err := strconv.Atoi(matches[1]); err == nil {
				config.TimestampTimeout = timeout
				config.UseTimestamp = true
			}
		}

		// Check for requiretty
		if requireTTYRegex.MatchString(line) {
			config.RequireTTY = true
		}
	}
}

// getSudoGroupMembers gets members of the sudo/wheel group
func getSudoGroupMembers() []string {
	members := []string{}

	// Try sudo group (Debian/Ubuntu)
	members = append(members, getGroupMembers("sudo")...)

	// Try wheel group (RHEL/CentOS)
	members = append(members, getGroupMembers("wheel")...)

	// Try admin group
	members = append(members, getGroupMembers("admin")...)

	return uniqueStrings(members)
}

// getGroupMembers returns members of a specific group
func getGroupMembers(groupName string) []string {
	members := []string{}

	file, err := os.Open("/etc/group")
	if err != nil {
		return members
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := scanner.Text()
		parts := strings.Split(line, ":")
		if len(parts) >= 4 && parts[0] == groupName {
			if parts[3] != "" {
				members = strings.Split(parts[3], ",")
			}
			break
		}
	}

	return members
}

// analyzeUserAccounts analyzes system user accounts
func analyzeUserAccounts() []UserAccount {
	accounts := []UserAccount{}

	// Read /etc/passwd
	file, err := os.Open("/etc/passwd")
	if err != nil {
		return accounts
	}
	defer file.Close()

	// Read shadow file for password status (requires root)
	shadowPasswords := readShadowFile()

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := scanner.Text()
		parts := strings.Split(line, ":")
		if len(parts) < 7 {
			continue
		}

		username := parts[0]
		uid, _ := strconv.Atoi(parts[2])
		gid, _ := strconv.Atoi(parts[3])
		home := parts[5]
		shell := parts[6]

		// Skip system accounts (UID < 1000) except root
		if uid < 1000 && uid != 0 {
			continue
		}

		account := UserAccount{
			Username: username,
			UID:      uid,
			GID:      gid,
			Home:     home,
			Shell:    shell,
		}

		// Check password status from shadow
		if shadowInfo, exists := shadowPasswords[username]; exists {
			account.EmptyPassword = shadowInfo.emptyPassword
			account.Locked = shadowInfo.locked
			account.PasswordExpired = shadowInfo.expired
		}

		// Check if in sudo group
		account.InSudoGroup = isUserInSudoGroup(username)

		// Get last login
		account.LastLogin = getLastLogin(username)

		// Determine risk level
		account.RiskLevel = calculateAccountRisk(account)

		accounts = append(accounts, account)
	}

	return accounts
}

// shadowInfo holds password information from /etc/shadow
type shadowInfo struct {
	emptyPassword bool
	locked        bool
	expired       bool
}

// readShadowFile reads password information from /etc/shadow
func readShadowFile() map[string]shadowInfo {
	shadowData := make(map[string]shadowInfo)

	file, err := os.Open("/etc/shadow")
	if err != nil {
		return shadowData // May not have permission
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := scanner.Text()
		parts := strings.Split(line, ":")
		if len(parts) < 2 {
			continue
		}

		username := parts[0]
		password := parts[1]

		info := shadowInfo{}

		// Check password field
		switch {
		case password == "" || password == "!":
			info.emptyPassword = true
		case strings.HasPrefix(password, "!") || strings.HasPrefix(password, "*"):
			info.locked = true
		}

		// Check if password expired (would need to parse expiry fields)
		if len(parts) >= 8 && parts[7] != "" {
			if expiry, err := strconv.ParseInt(parts[7], 10, 64); err == nil {
				if expiry > 0 {
					expiryDate := time.Unix(expiry*86400, 0)
					info.expired = expiryDate.Before(time.Now())
				}
			}
		}

		shadowData[username] = info
	}

	return shadowData
}

// isUserInSudoGroup checks if user is in sudo/wheel/admin group
func isUserInSudoGroup(username string) bool {
	cmd := exec.Command("groups", username)
	output, err := cmd.Output()
	if err != nil {
		return false
	}

	groups := strings.ToLower(string(output))
	return strings.Contains(groups, "sudo") ||
		strings.Contains(groups, "wheel") ||
		strings.Contains(groups, "admin")
}

// getLastLogin gets the last login time for a user
func getLastLogin(username string) string {
	cmd := exec.Command("lastlog", "-u", username)
	output, err := cmd.Output()
	if err != nil {
		return "unknown"
	}

	lines := strings.Split(string(output), "\n")
	if len(lines) < 2 {
		return "never"
	}

	// Parse lastlog output (skip header)
	info := strings.Fields(lines[1])
	if len(info) < 4 {
		return "never"
	}

	// Check if never logged in
	if strings.Contains(strings.ToLower(lines[1]), "never") {
		return "never"
	}

	// Return login info
	return strings.Join(info[3:], " ")
}

// calculateAccountRisk determines risk level for an account
func calculateAccountRisk(account UserAccount) string {
	// Root account with empty password is CRITICAL
	if account.UID == 0 && account.EmptyPassword {
		return "CRITICAL"
	}

	// Sudo user with empty password is HIGH
	if account.InSudoGroup && account.EmptyPassword {
		return "HIGH"
	}

	// Any user with empty password is MEDIUM
	if account.EmptyPassword {
		return "MEDIUM"
	}

	// Locked or expired accounts are OK
	if account.Locked || account.PasswordExpired {
		return "OK"
	}

	// Regular accounts are LOW risk
	return "LOW"
}

// analyzePasswordPolicy checks system password policy
func analyzePasswordPolicy() PasswordPolicy {
	policy := PasswordPolicy{
		MinLength:    0,
		MaxDays:      99999, // default
		MinDays:      0,
		WarnAge:      7,
		PolicySource: "/etc/login.defs",
	}

	// Read from /etc/login.defs
	file, err := os.Open("/etc/login.defs")
	if err != nil {
		return policy
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	commentRegex := regexp.MustCompile(`^\s*#`)

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())

		if line == "" || commentRegex.MatchString(line) {
			continue
		}

		parts := strings.Fields(line)
		if len(parts) < 2 {
			continue
		}

		key := parts[0]
		value := parts[1]

		switch key {
		case "PASS_MAX_DAYS":
			policy.MaxDays, _ = strconv.Atoi(value)
		case "PASS_MIN_DAYS":
			policy.MinDays, _ = strconv.Atoi(value)
		case "PASS_WARN_AGE":
			policy.WarnAge, _ = strconv.Atoi(value)
		case "PASS_MIN_LEN":
			policy.MinLength, _ = strconv.Atoi(value)
		case "ENCRYPT_METHOD":
			// This is in LoginConfig but we can capture it
		}
	}

	// Check PAM password requirements
	checkPAMPasswordPolicy(&policy)

	return policy
}

// checkPAMPasswordPolicy checks PAM password policy
func checkPAMPasswordPolicy(policy *PasswordPolicy) {
	// Read common-password PAM file
	pamFiles := []string{
		"/etc/pam.d/common-password",
		"/etc/pam.d/system-auth",
		"/etc/pam.d/password-auth",
	}

	for _, pamFile := range pamFiles {
		file, err := os.Open(pamFile)
		if err != nil {
			continue
		}
		defer file.Close()

		scanner := bufio.NewScanner(file)
		for scanner.Scan() {
			line := scanner.Text()

			// Look for pam_pwquality or pam_cracklib
			if strings.Contains(line, "pam_pwquality") || strings.Contains(line, "pam_cracklib") {
				policy.PolicySource = pamFile

				// Parse minlen
				if matches := regexp.MustCompile(`minlen=(\d+)`).FindStringSubmatch(line); len(matches) > 1 {
					policy.MinLength, _ = strconv.Atoi(matches[1])
				}

				// Check for character class requirements
				policy.RequireUppercase = strings.Contains(line, "ucredit") || strings.Contains(line, "minclass")
				policy.RequireLowercase = strings.Contains(line, "lcredit") || strings.Contains(line, "minclass")
				policy.RequireDigits = strings.Contains(line, "dcredit") || strings.Contains(line, "minclass")
				policy.RequireSpecial = strings.Contains(line, "ocredit") || strings.Contains(line, "minclass")
			}

			// Look for password history
			if strings.Contains(line, "pam_pwhistory") || strings.Contains(line, "remember=") {
				if matches := regexp.MustCompile(`remember=(\d+)`).FindStringSubmatch(line); len(matches) > 1 {
					policy.RememberPasswords, _ = strconv.Atoi(matches[1])
				}
			}
		}
	}
}

// analyzeLoginConfig checks login security settings
func analyzeLoginConfig() LoginConfig {
	config := LoginConfig{
		LoginTimeout:  60,
		LoginRetries:  3,
		FailDelay:     3,
		UmaskValue:    "022",
		CreateHomeDir: true,
		EncryptMethod: "SHA512",
	}

	file, err := os.Open("/etc/login.defs")
	if err != nil {
		return config
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	commentRegex := regexp.MustCompile(`^\s*#`)

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())

		if line == "" || commentRegex.MatchString(line) {
			continue
		}

		parts := strings.Fields(line)
		if len(parts) < 2 {
			continue
		}

		key := parts[0]
		value := parts[1]

		switch key {
		case "LOGIN_TIMEOUT":
			config.LoginTimeout, _ = strconv.Atoi(value)
		case "LOGIN_RETRIES":
			config.LoginRetries, _ = strconv.Atoi(value)
		case "FAIL_DELAY":
			config.FailDelay, _ = strconv.Atoi(value)
		case "UMASK":
			config.UmaskValue = value
		case "CREATE_HOME":
			config.CreateHomeDir = (strings.ToLower(value) == "yes")
		case "ENCRYPT_METHOD":
			config.EncryptMethod = value
		}
	}

	return config
}

// evaluateUserSecurity evaluates user/sudo security and adds issues
func (u *UserHardeningStatus) evaluateUserSecurity() {
	// Check sudo NOPASSWD entries
	if u.SudoConfig.PasswordlessCount > 0 {
		u.Issues = append(u.Issues, UserSecurityIssue{
			Severity:       "HIGH",
			Issue:          fmt.Sprintf("Found %d NOPASSWD sudo entries", u.SudoConfig.PasswordlessCount),
			Recommendation: "Remove NOPASSWD from sudo configuration for better security",
		})
		u.SecurityScore -= 15
	}

	// Check sudo timestamp timeout
	if u.SudoConfig.TimestampTimeout > 15 {
		u.Issues = append(u.Issues, UserSecurityIssue{
			Severity:       "MEDIUM",
			Issue:          fmt.Sprintf("Sudo timestamp timeout is %d minutes (long)", u.SudoConfig.TimestampTimeout),
			Recommendation: "Consider reducing timestamp_timeout to 5-10 minutes in /etc/sudoers",
		})
		u.SecurityScore -= 5
	}

	// Check accounts with empty passwords
	emptyPasswordAccounts := []string{}
	for _, account := range u.UserAccounts {
		if account.EmptyPassword && !account.Locked {
			emptyPasswordAccounts = append(emptyPasswordAccounts, account.Username)

			severity := "MEDIUM"
			if account.UID == 0 {
				severity = "CRITICAL"
				u.SecurityScore -= 30
			} else if account.InSudoGroup {
				severity = "HIGH"
				u.SecurityScore -= 20
			} else {
				u.SecurityScore -= 10
			}

			u.Issues = append(u.Issues, UserSecurityIssue{
				Severity:       severity,
				Issue:          fmt.Sprintf("User '%s' has empty or no password set", account.Username),
				Recommendation: fmt.Sprintf("Set a strong password: sudo passwd %s", account.Username),
			})
		}
	}

	// Check password policy
	if u.PasswordPolicy.MinLength < 12 {
		u.Issues = append(u.Issues, UserSecurityIssue{
			Severity:       "MEDIUM",
			Issue:          fmt.Sprintf("Minimum password length is %d (recommended: 12+)", u.PasswordPolicy.MinLength),
			Recommendation: "Update PASS_MIN_LEN in /etc/login.defs or minlen in PAM configuration",
		})
		u.SecurityScore -= 5
	}

	if u.PasswordPolicy.MaxDays > 90 {
		u.Issues = append(u.Issues, UserSecurityIssue{
			Severity:       "LOW",
			Issue:          fmt.Sprintf("Password expiry is %d days (recommended: 90 or less)", u.PasswordPolicy.MaxDays),
			Recommendation: "Set PASS_MAX_DAYS=90 in /etc/login.defs",
		})
		u.SecurityScore -= 3
	}

	if u.PasswordPolicy.RememberPasswords < 5 {
		u.Issues = append(u.Issues, UserSecurityIssue{
			Severity:       "LOW",
			Issue:          "Password history not enforced or too short",
			Recommendation: "Configure PAM to remember at least 5 previous passwords",
		})
		u.SecurityScore -= 3
	}

	// Check login configuration
	if u.LoginConfig.EncryptMethod != "SHA512" && u.LoginConfig.EncryptMethod != "YESCRYPT" {
		u.Issues = append(u.Issues, UserSecurityIssue{
			Severity:       "HIGH",
			Issue:          fmt.Sprintf("Weak password encryption method: %s", u.LoginConfig.EncryptMethod),
			Recommendation: "Set ENCRYPT_METHOD=SHA512 in /etc/login.defs",
		})
		u.SecurityScore -= 10
	}

	// Check umask (should be 027 or 077 for better security)
	if u.LoginConfig.UmaskValue == "022" {
		u.Issues = append(u.Issues, UserSecurityIssue{
			Severity:       "LOW",
			Issue:          "Umask is 022 (files readable by others)",
			Recommendation: "Consider setting UMASK=027 in /etc/login.defs for better privacy",
		})
		u.SecurityScore -= 2
	}
}

// calculateUserRiskLevel determines the overall user security risk level
func (u *UserHardeningStatus) calculateUserRiskLevel() {
	// Ensure score doesn't go negative
	if u.SecurityScore < 0 {
		u.SecurityScore = 0
	}

	// Determine risk level based on score
	if u.SecurityScore >= 85 {
		u.RiskLevel = "LOW"
	} else if u.SecurityScore >= 70 {
		u.RiskLevel = "MEDIUM"
	} else if u.SecurityScore >= 50 {
		u.RiskLevel = "HIGH"
	} else {
		u.RiskLevel = "CRITICAL"
	}
}

// uniqueStrings removes duplicates from string slice
func uniqueStrings(slice []string) []string {
	keys := make(map[string]bool)
	result := []string{}

	for _, entry := range slice {
		if _, exists := keys[entry]; !exists {
			keys[entry] = true
			result = append(result, entry)
		}
	}

	return result
}

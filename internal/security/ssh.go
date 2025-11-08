package security

import (
	"bufio"
	"fmt"
	"os"
	"regexp"
	"strconv"
	"strings"
)

// SSHConfig represents SSH server configuration and security posture
type SSHConfig struct {
	ConfigFile          string             `json:"config_file"`
	Port                int                `json:"port"`
	PermitRootLogin     string             `json:"permit_root_login"`
	PasswordAuth        string             `json:"password_authentication"`
	PubkeyAuth          string             `json:"pubkey_authentication"`
	PermitEmptyPassword string             `json:"permit_empty_passwords"`
	ChallengeResponse   string             `json:"challenge_response_auth"`
	Issues              []SSHSecurityIssue `json:"issues"`
	RiskLevel           string             `json:"risk_level"`     // LOW, MEDIUM, HIGH, CRITICAL
	SecurityScore       int                `json:"security_score"` // 0-100
}

// SSHSecurityIssue represents a specific SSH security concern
type SSHSecurityIssue struct {
	Severity       string `json:"severity"` // CRITICAL, HIGH, MEDIUM, LOW
	Issue          string `json:"issue"`
	Recommendation string `json:"recommendation"`
}

// AnalyzeSSHConfig reads and analyzes SSH server configuration
func AnalyzeSSHConfig() *SSHConfig {
	config := &SSHConfig{
		ConfigFile:          "/etc/ssh/sshd_config",
		Port:                22,
		PermitRootLogin:     "unknown",
		PasswordAuth:        "unknown",
		PubkeyAuth:          "unknown",
		PermitEmptyPassword: "unknown",
		ChallengeResponse:   "unknown",
		Issues:              []SSHSecurityIssue{},
		SecurityScore:       100,
	}

	// Check if config file exists
	if _, err := os.Stat(config.ConfigFile); os.IsNotExist(err) {
		config.Issues = append(config.Issues, SSHSecurityIssue{
			Severity:       "HIGH",
			Issue:          fmt.Sprintf("SSH config file not found: %s", config.ConfigFile),
			Recommendation: "SSH server may not be installed or config is in non-standard location",
		})
		config.RiskLevel = "HIGH"
		config.SecurityScore = 50
		return config
	}

	// Parse SSH config
	if err := config.parseConfig(); err != nil {
		config.Issues = append(config.Issues, SSHSecurityIssue{
			Severity:       "MEDIUM",
			Issue:          fmt.Sprintf("Cannot read SSH config: %v", err),
			Recommendation: "Check file permissions or run with sudo",
		})
		config.RiskLevel = "MEDIUM"
		config.SecurityScore = 60
		return config
	}

	// Analyze configuration and identify issues
	config.analyzeSecurityPosture()

	return config
}

// parseConfig reads and parses the SSH configuration file
func (s *SSHConfig) parseConfig() error {
	file, err := os.Open(s.ConfigFile)
	if err != nil {
		return err
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	commentRegex := regexp.MustCompile(`^\s*#`)

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())

		// Skip comments and empty lines
		if line == "" || commentRegex.MatchString(line) {
			continue
		}

		// Split line into directive and value
		parts := strings.Fields(line)
		if len(parts) < 2 {
			continue
		}

		directive := strings.ToLower(parts[0])
		value := parts[1]

		// Parse relevant directives
		switch directive {
		case "port":
			if port, err := strconv.Atoi(value); err == nil {
				s.Port = port
			}
		case "permitrootlogin":
			s.PermitRootLogin = strings.ToLower(value)
		case "passwordauthentication":
			s.PasswordAuth = strings.ToLower(value)
		case "pubkeyauthentication":
			s.PubkeyAuth = strings.ToLower(value)
		case "permitemptypasswords":
			s.PermitEmptyPassword = strings.ToLower(value)
		case "challengeresponseauthentication":
			s.ChallengeResponse = strings.ToLower(value)
		}
	}

	return scanner.Err()
}

// analyzeSecurityPosture evaluates SSH configuration security
func (s *SSHConfig) analyzeSecurityPosture() {
	// Check PermitRootLogin
	if s.PermitRootLogin == "yes" {
		s.Issues = append(s.Issues, SSHSecurityIssue{
			Severity:       "CRITICAL",
			Issue:          "Root login via SSH is enabled",
			Recommendation: "Set 'PermitRootLogin no' or 'PermitRootLogin prohibit-password' in /etc/ssh/sshd_config",
		})
		s.SecurityScore -= 30
	} else if s.PermitRootLogin == "prohibit-password" || s.PermitRootLogin == "without-password" {
		// This is acceptable - root can login but only with keys
		s.Issues = append(s.Issues, SSHSecurityIssue{
			Severity:       "LOW",
			Issue:          "Root login allowed with key authentication only",
			Recommendation: "Consider disabling root login entirely for maximum security",
		})
		s.SecurityScore -= 5
	} else if s.PermitRootLogin == "no" {
		// Good configuration
	} else if s.PermitRootLogin == "unknown" {
		s.Issues = append(s.Issues, SSHSecurityIssue{
			Severity:       "MEDIUM",
			Issue:          "PermitRootLogin directive not found (may be using default)",
			Recommendation: "Explicitly set 'PermitRootLogin no' in /etc/ssh/sshd_config",
		})
		s.SecurityScore -= 10
	}

	// Check PasswordAuthentication
	if s.PasswordAuth == "yes" {
		s.Issues = append(s.Issues, SSHSecurityIssue{
			Severity:       "HIGH",
			Issue:          "Password authentication is enabled",
			Recommendation: "Disable password auth and use key-based authentication: Set 'PasswordAuthentication no'",
		})
		s.SecurityScore -= 20
	} else if s.PasswordAuth == "no" {
		// Good configuration
	} else if s.PasswordAuth == "unknown" {
		s.Issues = append(s.Issues, SSHSecurityIssue{
			Severity:       "MEDIUM",
			Issue:          "PasswordAuthentication directive not found (may be using default 'yes')",
			Recommendation: "Explicitly set 'PasswordAuthentication no' and use SSH keys",
		})
		s.SecurityScore -= 15
	}

	// Check PermitEmptyPasswords
	if s.PermitEmptyPassword == "yes" {
		s.Issues = append(s.Issues, SSHSecurityIssue{
			Severity:       "CRITICAL",
			Issue:          "Empty passwords are permitted",
			Recommendation: "Set 'PermitEmptyPasswords no' immediately",
		})
		s.SecurityScore -= 30
	}

	// Check SSH port
	if s.Port == 22 {
		s.Issues = append(s.Issues, SSHSecurityIssue{
			Severity:       "LOW",
			Issue:          "SSH is running on default port 22",
			Recommendation: "Consider changing to non-standard port to reduce automated attacks",
		})
		s.SecurityScore -= 5
	}

	// Check PubkeyAuthentication
	if s.PubkeyAuth == "no" {
		s.Issues = append(s.Issues, SSHSecurityIssue{
			Severity:       "HIGH",
			Issue:          "Public key authentication is disabled",
			Recommendation: "Enable key-based authentication: Set 'PubkeyAuthentication yes'",
		})
		s.SecurityScore -= 20
	}

	// Determine overall risk level
	if s.SecurityScore >= 80 {
		s.RiskLevel = "LOW"
	} else if s.SecurityScore >= 60 {
		s.RiskLevel = "MEDIUM"
	} else if s.SecurityScore >= 40 {
		s.RiskLevel = "HIGH"
	} else {
		s.RiskLevel = "CRITICAL"
	}

	// Ensure score doesn't go negative
	if s.SecurityScore < 0 {
		s.SecurityScore = 0
	}

	// Add positive note if configuration is good
	if len(s.Issues) == 0 || (len(s.Issues) == 1 && s.Issues[0].Severity == "LOW") {
		s.Issues = append([]SSHSecurityIssue{
			{
				Severity:       "INFO",
				Issue:          "SSH configuration follows security best practices",
				Recommendation: "Current configuration is secure",
			},
		}, s.Issues...)
	}
}

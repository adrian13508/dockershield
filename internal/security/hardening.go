package security

import (
	"fmt"
	"os"
	"os/exec"
	"regexp"
	"strconv"
	"strings"
)

// HardeningStatus represents system hardening configuration and security posture
type HardeningStatus struct {
	SysctlChecks     []SysctlCheck     `json:"sysctl_checks"`
	KernelParameters []KernelParameter `json:"kernel_parameters"`
	SELinuxStatus    SELinuxInfo       `json:"selinux_status"`
	AppArmorStatus   AppArmorInfo      `json:"apparmor_status"`
	Issues           []HardeningIssue  `json:"issues"`
	RiskLevel        string            `json:"risk_level"`     // LOW, MEDIUM, HIGH, CRITICAL
	SecurityScore    int               `json:"security_score"` // 0-100
}

// SysctlCheck represents a sysctl parameter check
type SysctlCheck struct {
	Parameter        string `json:"parameter"`
	CurrentValue     string `json:"current_value"`
	RecommendedValue string `json:"recommended_value"`
	Compliant        bool   `json:"compliant"`
	Severity         string `json:"severity"` // CRITICAL, HIGH, MEDIUM, LOW
	Description      string `json:"description"`
}

// KernelParameter represents a kernel security parameter
type KernelParameter struct {
	Parameter   string `json:"parameter"`
	Value       string `json:"value"`
	Description string `json:"description"`
}

// SELinuxInfo represents SELinux status
type SELinuxInfo struct {
	Installed bool   `json:"installed"`
	Enabled   bool   `json:"enabled"`
	Mode      string `json:"mode"` // enforcing, permissive, disabled
	Status    string `json:"status"`
}

// AppArmorInfo represents AppArmor status
type AppArmorInfo struct {
	Installed bool   `json:"installed"`
	Enabled   bool   `json:"enabled"`
	Profiles  int    `json:"profiles_loaded"`
	Mode      string `json:"mode"`
	Status    string `json:"status"`
}

// HardeningIssue represents a system hardening security concern
type HardeningIssue struct {
	Severity       string `json:"severity"` // CRITICAL, HIGH, MEDIUM, LOW
	Issue          string `json:"issue"`
	Recommendation string `json:"recommendation"`
}

// AnalyzeSystemHardening performs comprehensive system hardening checks
func AnalyzeSystemHardening() *HardeningStatus {
	status := &HardeningStatus{
		SysctlChecks:     []SysctlCheck{},
		KernelParameters: []KernelParameter{},
		Issues:           []HardeningIssue{},
		SecurityScore:    100,
	}

	// Check sysctl parameters
	status.checkSysctlParameters()

	// Check kernel parameters
	status.checkKernelParameters()

	// Check SELinux
	status.SELinuxStatus = checkSELinux()

	// Check AppArmor
	status.AppArmorStatus = checkAppArmor()

	// Analyze MAC (Mandatory Access Control) status
	status.analyzeMAC()

	// Calculate overall security posture
	status.calculateRiskLevel()

	return status
}

// checkSysctlParameters checks critical sysctl security parameters
func (h *HardeningStatus) checkSysctlParameters() {
	// Define critical sysctl parameters to check
	criticalParams := map[string]struct {
		recommended string
		severity    string
		description string
	}{
		// Network security
		"net.ipv4.conf.all.accept_source_route": {
			recommended: "0",
			severity:    "HIGH",
			description: "Disable source packet routing (prevents IP spoofing)",
		},
		"net.ipv4.conf.default.accept_source_route": {
			recommended: "0",
			severity:    "HIGH",
			description: "Disable source packet routing on new interfaces",
		},
		"net.ipv4.conf.all.accept_redirects": {
			recommended: "0",
			severity:    "MEDIUM",
			description: "Disable ICMP redirects (prevents MITM attacks)",
		},
		"net.ipv4.conf.default.accept_redirects": {
			recommended: "0",
			severity:    "MEDIUM",
			description: "Disable ICMP redirects on new interfaces",
		},
		"net.ipv4.conf.all.secure_redirects": {
			recommended: "0",
			severity:    "MEDIUM",
			description: "Disable secure ICMP redirects",
		},
		"net.ipv4.conf.default.secure_redirects": {
			recommended: "0",
			severity:    "MEDIUM",
			description: "Disable secure ICMP redirects on new interfaces",
		},
		"net.ipv4.conf.all.send_redirects": {
			recommended: "0",
			severity:    "MEDIUM",
			description: "Disable sending ICMP redirects",
		},
		"net.ipv4.conf.default.send_redirects": {
			recommended: "0",
			severity:    "MEDIUM",
			description: "Disable sending ICMP redirects on new interfaces",
		},
		"net.ipv4.icmp_echo_ignore_broadcasts": {
			recommended: "1",
			severity:    "LOW",
			description: "Ignore ICMP broadcast requests (prevents Smurf attacks)",
		},
		"net.ipv4.icmp_ignore_bogus_error_responses": {
			recommended: "1",
			severity:    "LOW",
			description: "Ignore bogus ICMP error responses",
		},
		"net.ipv4.tcp_syncookies": {
			recommended: "1",
			severity:    "HIGH",
			description: "Enable SYN flood protection",
		},
		"net.ipv4.conf.all.rp_filter": {
			recommended: "1",
			severity:    "HIGH",
			description: "Enable reverse path filtering (anti-spoofing)",
		},
		"net.ipv4.conf.default.rp_filter": {
			recommended: "1",
			severity:    "HIGH",
			description: "Enable reverse path filtering on new interfaces",
		},
		"net.ipv4.conf.all.log_martians": {
			recommended: "1",
			severity:    "LOW",
			description: "Log suspicious packets (martian packets)",
		},
		"net.ipv4.conf.default.log_martians": {
			recommended: "1",
			severity:    "LOW",
			description: "Log suspicious packets on new interfaces",
		},
		// IPv6 security
		"net.ipv6.conf.all.accept_source_route": {
			recommended: "0",
			severity:    "HIGH",
			description: "Disable IPv6 source packet routing",
		},
		"net.ipv6.conf.default.accept_source_route": {
			recommended: "0",
			severity:    "HIGH",
			description: "Disable IPv6 source packet routing on new interfaces",
		},
		"net.ipv6.conf.all.accept_redirects": {
			recommended: "0",
			severity:    "MEDIUM",
			description: "Disable IPv6 ICMP redirects",
		},
		"net.ipv6.conf.default.accept_redirects": {
			recommended: "0",
			severity:    "MEDIUM",
			description: "Disable IPv6 ICMP redirects on new interfaces",
		},
		// Kernel security
		"kernel.randomize_va_space": {
			recommended: "2",
			severity:    "CRITICAL",
			description: "Enable full ASLR (Address Space Layout Randomization)",
		},
		"kernel.dmesg_restrict": {
			recommended: "1",
			severity:    "MEDIUM",
			description: "Restrict dmesg access to root only",
		},
		"kernel.kptr_restrict": {
			recommended: "2",
			severity:    "HIGH",
			description: "Hide kernel pointers (prevents kernel exploits)",
		},
		"kernel.yama.ptrace_scope": {
			recommended: "1",
			severity:    "MEDIUM",
			description: "Restrict ptrace to parent-child only (prevents process injection)",
		},
		"fs.suid_dumpable": {
			recommended: "0",
			severity:    "HIGH",
			description: "Disable core dumps for SUID programs (prevents info leakage)",
		},
		"fs.protected_hardlinks": {
			recommended: "1",
			severity:    "MEDIUM",
			description: "Protect hardlinks from exploitation",
		},
		"fs.protected_symlinks": {
			recommended: "1",
			severity:    "MEDIUM",
			description: "Protect symlinks from exploitation",
		},
	}

	// Read current sysctl values
	for param, config := range criticalParams {
		currentValue := getSysctlValue(param)
		compliant := (currentValue == config.recommended)

		check := SysctlCheck{
			Parameter:        param,
			CurrentValue:     currentValue,
			RecommendedValue: config.recommended,
			Compliant:        compliant,
			Severity:         config.severity,
			Description:      config.description,
		}

		h.SysctlChecks = append(h.SysctlChecks, check)

		// Add issue if not compliant
		if !compliant && currentValue != "" {
			issue := HardeningIssue{
				Severity:       config.severity,
				Issue:          fmt.Sprintf("sysctl %s is set to '%s' (recommended: '%s')", param, currentValue, config.recommended),
				Recommendation: fmt.Sprintf("Run: sudo sysctl -w %s=%s && echo '%s=%s' | sudo tee -a /etc/sysctl.conf", param, config.recommended, param, config.recommended),
			}
			h.Issues = append(h.Issues, issue)

			// Deduct points based on severity
			switch config.severity {
			case "CRITICAL":
				h.SecurityScore -= 20
			case "HIGH":
				h.SecurityScore -= 10
			case "MEDIUM":
				h.SecurityScore -= 5
			case "LOW":
				h.SecurityScore -= 2
			}
		}
	}
}

// getSysctlValue reads a sysctl parameter value
func getSysctlValue(param string) string {
	cmd := exec.Command("sysctl", "-n", param)
	output, err := cmd.Output()
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(output))
}

// checkKernelParameters checks important kernel parameters
func (h *HardeningStatus) checkKernelParameters() {
	// Check kernel version
	cmd := exec.Command("uname", "-r")
	output, err := cmd.Output()
	if err == nil {
		h.KernelParameters = append(h.KernelParameters, KernelParameter{
			Parameter:   "kernel.version",
			Value:       strings.TrimSpace(string(output)),
			Description: "Kernel version",
		})
	}

	// Check if ASLR is enabled
	aslrValue := getSysctlValue("kernel.randomize_va_space")
	if aslrValue != "" {
		aslrInt, _ := strconv.Atoi(aslrValue)
		var aslrStatus string
		switch aslrInt {
		case 0:
			aslrStatus = "Disabled (CRITICAL RISK)"
		case 1:
			aslrStatus = "Partial (stack randomization only)"
		case 2:
			aslrStatus = "Full (recommended)"
		default:
			aslrStatus = "Unknown"
		}

		h.KernelParameters = append(h.KernelParameters, KernelParameter{
			Parameter:   "ASLR",
			Value:       aslrStatus,
			Description: "Address Space Layout Randomization",
		})
	}

	// Check if kernel modules can be loaded
	modulesPath := "/proc/sys/kernel/modules_disabled"
	if data, err := os.ReadFile(modulesPath); err == nil {
		value := strings.TrimSpace(string(data))
		h.KernelParameters = append(h.KernelParameters, KernelParameter{
			Parameter:   "kernel.modules_disabled",
			Value:       value,
			Description: "Kernel module loading (1=disabled, 0=enabled)",
		})
	}
}

// checkSELinux checks SELinux status
func checkSELinux() SELinuxInfo {
	info := SELinuxInfo{
		Installed: false,
		Enabled:   false,
		Mode:      "not installed",
		Status:    "Not available",
	}

	// Check if SELinux is installed
	if _, err := exec.LookPath("getenforce"); err != nil {
		return info
	}

	info.Installed = true

	// Get SELinux status
	cmd := exec.Command("getenforce")
	output, err := cmd.Output()
	if err != nil {
		info.Status = fmt.Sprintf("Error: %v", err)
		return info
	}

	mode := strings.TrimSpace(strings.ToLower(string(output)))
	info.Mode = mode

	switch mode {
	case "enforcing":
		info.Enabled = true
		info.Status = "Active and enforcing policies"
	case "permissive":
		info.Enabled = true
		info.Status = "Active but not enforcing (logs only)"
	case "disabled":
		info.Enabled = false
		info.Status = "Disabled"
	default:
		info.Status = "Unknown status"
	}

	return info
}

// checkAppArmor checks AppArmor status
func checkAppArmor() AppArmorInfo {
	info := AppArmorInfo{
		Installed: false,
		Enabled:   false,
		Profiles:  0,
		Mode:      "not installed",
		Status:    "Not available",
	}

	// Check if AppArmor is installed
	if _, err := exec.LookPath("aa-status"); err != nil {
		return info
	}

	info.Installed = true

	// Check if AppArmor is enabled
	cmd := exec.Command("aa-enabled")
	if err := cmd.Run(); err == nil {
		info.Enabled = true
		info.Mode = "enabled"
	} else {
		info.Mode = "disabled"
		info.Status = "Installed but not enabled"
		return info
	}

	// Get number of loaded profiles
	cmd = exec.Command("aa-status", "--profiled")
	output, err := cmd.Output()
	if err == nil {
		// Parse the number from output
		re := regexp.MustCompile(`(\d+)`)
		if matches := re.FindStringSubmatch(string(output)); len(matches) > 1 {
			if count, err := strconv.Atoi(matches[1]); err == nil {
				info.Profiles = count
			}
		}
	}

	if info.Profiles > 0 {
		info.Status = fmt.Sprintf("Active with %d profile(s) loaded", info.Profiles)
	} else {
		info.Status = "Enabled but no profiles loaded"
	}

	return info
}

// analyzeMAC analyzes Mandatory Access Control status
func (h *HardeningStatus) analyzeMAC() {
	// Check if either SELinux or AppArmor is active
	hasMAC := false

	if h.SELinuxStatus.Enabled && h.SELinuxStatus.Mode == "enforcing" {
		hasMAC = true
		h.Issues = append(h.Issues, HardeningIssue{
			Severity:       "INFO",
			Issue:          "SELinux is enabled and enforcing",
			Recommendation: "Good: Mandatory Access Control is active",
		})
	} else if h.SELinuxStatus.Installed && h.SELinuxStatus.Mode == "permissive" {
		h.Issues = append(h.Issues, HardeningIssue{
			Severity:       "MEDIUM",
			Issue:          "SELinux is in permissive mode (not enforcing)",
			Recommendation: "Consider enabling enforcing mode: sudo setenforce 1",
		})
		h.SecurityScore -= 10
	}

	if h.AppArmorStatus.Enabled && h.AppArmorStatus.Profiles > 0 {
		hasMAC = true
		h.Issues = append(h.Issues, HardeningIssue{
			Severity:       "INFO",
			Issue:          fmt.Sprintf("AppArmor is enabled with %d profiles", h.AppArmorStatus.Profiles),
			Recommendation: "Good: Mandatory Access Control is active",
		})
	} else if h.AppArmorStatus.Installed && !h.AppArmorStatus.Enabled {
		h.Issues = append(h.Issues, HardeningIssue{
			Severity:       "MEDIUM",
			Issue:          "AppArmor is installed but not enabled",
			Recommendation: "Consider enabling AppArmor for additional security",
		})
		h.SecurityScore -= 10
	}

	// Warn if no MAC is active
	if !hasMAC {
		h.Issues = append(h.Issues, HardeningIssue{
			Severity:       "HIGH",
			Issue:          "No Mandatory Access Control (MAC) system active",
			Recommendation: "Install and enable either SELinux or AppArmor for enhanced security",
		})
		h.SecurityScore -= 15
	}
}

// calculateRiskLevel determines the overall hardening risk level
func (h *HardeningStatus) calculateRiskLevel() {
	// Ensure score doesn't go negative
	if h.SecurityScore < 0 {
		h.SecurityScore = 0
	}

	// Determine risk level based on score
	if h.SecurityScore >= 85 {
		h.RiskLevel = "LOW"
	} else if h.SecurityScore >= 70 {
		h.RiskLevel = "MEDIUM"
	} else if h.SecurityScore >= 50 {
		h.RiskLevel = "HIGH"
	} else {
		h.RiskLevel = "CRITICAL"
	}

	// Add summary issue
	if h.SecurityScore < 85 {
		criticalCount := 0
		highCount := 0
		mediumCount := 0

		for _, issue := range h.Issues {
			switch issue.Severity {
			case "CRITICAL":
				criticalCount++
			case "HIGH":
				highCount++
			case "MEDIUM":
				mediumCount++
			}
		}

		summary := fmt.Sprintf("System hardening needs improvement (%d critical, %d high, %d medium issues)",
			criticalCount, highCount, mediumCount)

		h.Issues = append([]HardeningIssue{
			{
				Severity:       h.RiskLevel,
				Issue:          summary,
				Recommendation: "Review and apply the hardening recommendations below",
			},
		}, h.Issues...)
	}
}

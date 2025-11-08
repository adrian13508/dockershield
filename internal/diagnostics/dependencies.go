package diagnostics

import (
	"os/exec"
)

// CheckDependencies performs dependency checks
func CheckDependencies() *DependencyInfo {
	return &DependencyInfo{
		IptablesInstalled:      checkIptablesInstalled(),
		IptablesSaveAccessible: checkIptablesSaveAccessible(),
		UFWInstalled:           checkUFWInstalled(),
	}
}

// checkIptablesInstalled checks if iptables is installed
func checkIptablesInstalled() CheckResult {
	_, err := exec.LookPath("iptables")
	if err != nil {
		return CheckResult{
			Status:  StatusWarning,
			Value:   "no",
			Message: "iptables is not installed",
			Fix:     "Install iptables: sudo apt-get install iptables",
		}
	}

	return CheckResult{
		Status:  StatusPass,
		Value:   "yes",
		Message: "iptables is installed",
	}
}

// checkIptablesSaveAccessible checks if iptables-save is accessible
func checkIptablesSaveAccessible() CheckResult {
	path, err := exec.LookPath("iptables-save")
	if err != nil {
		return CheckResult{
			Status:  StatusWarning,
			Value:   "no",
			Message: "iptables-save is not found",
			Fix:     "Install iptables: sudo apt-get install iptables",
		}
	}

	return CheckResult{
		Status:  StatusPass,
		Value:   path,
		Message: "iptables-save found at: " + path,
	}
}

// checkUFWInstalled checks if UFW is installed (optional)
func checkUFWInstalled() CheckResult {
	_, err := exec.LookPath("ufw")
	if err != nil {
		return CheckResult{
			Status:  StatusWarning,
			Value:   "no",
			Message: "UFW is not installed (optional)",
			Fix:     "Install UFW: sudo apt-get install ufw",
		}
	}

	// Check if UFW is active
	cmd := exec.Command("ufw", "status")
	output, err := cmd.Output()
	if err != nil {
		return CheckResult{
			Status:  StatusPass,
			Value:   "installed",
			Message: "UFW is installed but status unknown",
		}
	}

	// Simple check if UFW is active
	if len(output) > 0 {
		return CheckResult{
			Status:  StatusPass,
			Value:   "installed",
			Message: "UFW is installed",
		}
	}

	return CheckResult{
		Status:  StatusPass,
		Value:   "installed",
		Message: "UFW is installed",
	}
}

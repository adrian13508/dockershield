package diagnostics

import (
	"fmt"
	"os"
	"os/exec"
	"runtime"
	"strings"
)

// CheckSystem performs system-level diagnostic checks
func CheckSystem() *SystemInfo {
	return &SystemInfo{
		OS:           checkOS(),
		Architecture: checkArchitecture(),
		Kernel:       checkKernel(),
		IsRoot:       checkIsRoot(),
		Hostname:     checkHostname(),
	}
}

// checkOS detects the operating system and version
func checkOS() CheckResult {
	osInfo := runtime.GOOS

	var detailedOS string
	var status CheckStatus = StatusPass

	switch osInfo {
	case "linux":
		// Try to get more details from /etc/os-release
		detailedOS = getLinuxDistribution()
		if detailedOS == "" {
			detailedOS = "Linux (unknown distribution)"
		}
	case "darwin":
		detailedOS = "macOS"
	case "windows":
		detailedOS = "Windows"
	default:
		detailedOS = osInfo
	}

	return CheckResult{
		Status:  status,
		Value:   detailedOS,
		Message: fmt.Sprintf("Operating System: %s", detailedOS),
	}
}

// getLinuxDistribution reads /etc/os-release to get distribution info
func getLinuxDistribution() string {
	data, err := os.ReadFile("/etc/os-release")
	if err != nil {
		return ""
	}

	lines := strings.Split(string(data), "\n")
	var prettyName string

	for _, line := range lines {
		if strings.HasPrefix(line, "PRETTY_NAME=") {
			prettyName = strings.TrimPrefix(line, "PRETTY_NAME=")
			prettyName = strings.Trim(prettyName, "\"")
			return prettyName
		}
	}

	return ""
}

// checkArchitecture detects the system architecture
func checkArchitecture() CheckResult {
	arch := runtime.GOARCH

	return CheckResult{
		Status:  StatusPass,
		Value:   arch,
		Message: fmt.Sprintf("Architecture: %s", arch),
	}
}

// checkKernel gets the kernel version (Linux only)
func checkKernel() CheckResult {
	if runtime.GOOS != "linux" {
		return CheckResult{
			Status:  StatusSkipped,
			Value:   "N/A",
			Message: "Kernel check skipped (not Linux)",
		}
	}

	cmd := exec.Command("uname", "-r")
	output, err := cmd.Output()
	if err != nil {
		return CheckResult{
			Status:  StatusWarning,
			Value:   "unknown",
			Message: "Could not determine kernel version",
		}
	}

	kernel := strings.TrimSpace(string(output))

	return CheckResult{
		Status:  StatusPass,
		Value:   kernel,
		Message: fmt.Sprintf("Kernel: %s", kernel),
	}
}

// checkIsRoot checks if the program is running as root
func checkIsRoot() CheckResult {
	isRoot := os.Geteuid() == 0

	if isRoot {
		return CheckResult{
			Status:  StatusPass,
			Value:   "yes",
			Message: "Running as root",
		}
	}

	return CheckResult{
		Status:  StatusWarning,
		Value:   "no",
		Message: "Not running as root (some features require sudo)",
		Fix:     "Run with sudo for full functionality: sudo dockershield scan",
	}
}

// checkHostname gets the system hostname
func checkHostname() CheckResult {
	hostname, err := os.Hostname()
	if err != nil {
		return CheckResult{
			Status:  StatusWarning,
			Value:   "unknown",
			Message: "Could not determine hostname",
		}
	}

	return CheckResult{
		Status:  StatusPass,
		Value:   hostname,
		Message: fmt.Sprintf("Hostname: %s", hostname),
	}
}

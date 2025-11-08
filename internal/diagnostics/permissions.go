package diagnostics

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
)

// CheckPermissions performs permission-related diagnostic checks
func CheckPermissions() *PermissionInfo {
	return &PermissionInfo{
		CanReadIptables:  checkCanReadIptables(),
		CanAccessDocker:  checkCanAccessDocker(),
		CanWriteState:    checkCanWriteState(),
		CanReadSSHConfig: checkCanReadSSHConfig(),
	}
}

// checkCanReadIptables checks if we can read iptables
func checkCanReadIptables() CheckResult {
	// Try to execute iptables-save
	cmd := exec.Command("iptables-save")
	err := cmd.Run()

	if err != nil {
		// Check if it's a permission error
		if exitErr, ok := err.(*exec.ExitError); ok {
			if exitErr.ExitCode() == 1 || exitErr.ExitCode() == 4 {
				return CheckResult{
					Status:  StatusFail,
					Value:   "no",
					Message: "Cannot read iptables (need root)",
					Fix:     "Run with sudo for iptables analysis: sudo dockershield scan",
				}
			}
		}

		// Command not found or other error
		return CheckResult{
			Status:  StatusWarning,
			Value:   "no",
			Message: "iptables-save not accessible",
			Fix:     "Install iptables or run with sudo",
		}
	}

	return CheckResult{
		Status:  StatusPass,
		Value:   "yes",
		Message: "Can read iptables rules",
	}
}

// checkCanAccessDocker checks if we can access Docker socket
func checkCanAccessDocker() CheckResult {
	socketPath := "/var/run/docker.sock"

	// Check if we can access the socket
	_, err := os.Stat(socketPath)
	if err != nil {
		if os.IsNotExist(err) {
			return CheckResult{
				Status:  StatusFail,
				Value:   "no",
				Message: "Docker socket not found",
			}
		}
		return CheckResult{
			Status:  StatusFail,
			Value:   "no",
			Message: "Cannot access Docker socket",
		}
	}

	// Try to open the socket
	file, err := os.OpenFile(socketPath, os.O_RDWR, 0)
	if err != nil {
		return CheckResult{
			Status:  StatusWarning,
			Value:   "limited",
			Message: "Docker socket has permission restrictions",
			Fix:     "Add user to docker group: sudo usermod -aG docker $USER",
		}
	}
	file.Close()

	return CheckResult{
		Status:  StatusPass,
		Value:   "yes",
		Message: "Docker socket is accessible",
	}
}

// checkCanWriteState checks if we can write to state directory
func checkCanWriteState() CheckResult {
	// Get home directory
	homeDir, err := os.UserHomeDir()
	if err != nil {
		return CheckResult{
			Status:  StatusWarning,
			Value:   "unknown",
			Message: "Cannot determine home directory",
		}
	}

	stateDir := filepath.Join(homeDir, ".dockershield")

	// Create directory if it doesn't exist
	err = os.MkdirAll(stateDir, 0755)
	if err != nil {
		return CheckResult{
			Status:  StatusFail,
			Value:   "no",
			Message: "Cannot create state directory",
			Fix:     "Check permissions on home directory",
		}
	}

	// Try to write a test file
	testFile := filepath.Join(stateDir, ".write_test")
	err = os.WriteFile(testFile, []byte("test"), 0644)
	if err != nil {
		return CheckResult{
			Status:  StatusFail,
			Value:   "no",
			Message: "Cannot write to state directory",
			Fix:     "Check permissions on ~/.dockershield/",
		}
	}

	// Clean up test file
	os.Remove(testFile)

	return CheckResult{
		Status:  StatusPass,
		Value:   "yes",
		Message: fmt.Sprintf("State directory is writable: %s", stateDir),
	}
}

// checkCanReadSSHConfig checks if we can read SSH configuration
func checkCanReadSSHConfig() CheckResult {
	sshConfigPath := "/etc/ssh/sshd_config"

	data, err := os.ReadFile(sshConfigPath)
	if err != nil {
		if os.IsPermission(err) {
			return CheckResult{
				Status:  StatusWarning,
				Value:   "no",
				Message: "Cannot read SSH config (need root)",
				Fix:     "Run with sudo for SSH configuration analysis",
			}
		}
		if os.IsNotExist(err) {
			return CheckResult{
				Status:  StatusWarning,
				Value:   "no",
				Message: "SSH config file not found",
			}
		}
		return CheckResult{
			Status:  StatusWarning,
			Value:   "no",
			Message: "Cannot read SSH config",
		}
	}

	// Successfully read
	return CheckResult{
		Status:  StatusPass,
		Value:   "yes",
		Message: fmt.Sprintf("Can read SSH config (%d bytes)", len(data)),
	}
}

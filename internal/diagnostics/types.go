package diagnostics

import "time"

// CheckStatus represents the result of a diagnostic check
type CheckStatus string

const (
	StatusPass    CheckStatus = "pass"
	StatusWarning CheckStatus = "warning"
	StatusFail    CheckStatus = "fail"
	StatusSkipped CheckStatus = "skipped"
)

// CheckResult represents the result of a single check
type CheckResult struct {
	Status  CheckStatus
	Message string
	Value   string
	Fix     string // Optional fix suggestion
}

// DiagnosticResults contains all diagnostic check results
type DiagnosticResults struct {
	Timestamp    time.Time
	System       *SystemInfo
	Docker       *DockerInfo
	Permissions  *PermissionInfo
	Dependencies *DependencyInfo
	Config       *ConfigInfo
	DockerShield *DockerShieldInfo
}

// SystemInfo contains system-level diagnostic information
type SystemInfo struct {
	OS           CheckResult
	Architecture CheckResult
	Kernel       CheckResult
	IsRoot       CheckResult
	Hostname     CheckResult
}

// DockerInfo contains Docker-related diagnostic information
type DockerInfo struct {
	Installed         CheckResult
	DaemonRunning     CheckResult
	SocketAccessible  CheckResult
	APIVersion        CheckResult
	CanListContainers CheckResult
	CanListNetworks   CheckResult
}

// PermissionInfo contains permission-related checks
type PermissionInfo struct {
	CanReadIptables  CheckResult
	CanAccessDocker  CheckResult
	CanWriteState    CheckResult
	CanReadSSHConfig CheckResult
}

// DependencyInfo contains dependency checks
type DependencyInfo struct {
	IptablesInstalled      CheckResult
	IptablesSaveAccessible CheckResult
	UFWInstalled           CheckResult
}

// ConfigInfo contains configuration file checks
type ConfigInfo struct {
	ConfigDirExists  CheckResult
	ConfigFileExists CheckResult
	ConfigFileValid  CheckResult
	StateDirExists   CheckResult
	StateDirWritable CheckResult
	StateFileExists  CheckResult
}

// DockerShieldInfo contains DockerShield-specific information
type DockerShieldInfo struct {
	Version        CheckResult
	BinaryLocation CheckResult
	BuildInfo      CheckResult
}

// HasErrors returns true if any critical errors were found
func (r *DiagnosticResults) HasErrors() bool {
	// Check all results for failures
	checks := []CheckResult{
		r.System.OS,
		r.Docker.Installed,
		r.Docker.DaemonRunning,
		r.Docker.SocketAccessible,
	}

	for _, check := range checks {
		if check.Status == StatusFail {
			return true
		}
	}

	return false
}

// HasWarnings returns true if any warnings were found
func (r *DiagnosticResults) HasWarnings() bool {
	// This would require iterating through all checks
	// For now, we'll check key indicators
	if r.System.IsRoot.Status == StatusWarning {
		return true
	}
	if r.Permissions.CanReadIptables.Status == StatusWarning || r.Permissions.CanReadIptables.Status == StatusFail {
		return true
	}
	if r.Dependencies.UFWInstalled.Status == StatusWarning {
		return true
	}

	return false
}

// GetIssues returns a list of all issues found
func (r *DiagnosticResults) GetIssues() []Issue {
	var issues []Issue

	// Check permissions
	if r.Permissions.CanReadIptables.Status == StatusFail {
		issues = append(issues, Issue{
			Severity: "warning",
			Category: "permissions",
			Message:  r.Permissions.CanReadIptables.Message,
			Fix:      r.Permissions.CanReadIptables.Fix,
		})
	}

	// Check Docker
	if r.Docker.Installed.Status == StatusFail {
		issues = append(issues, Issue{
			Severity: "error",
			Category: "docker",
			Message:  "Docker is not installed",
			Fix:      "Install Docker: https://docs.docker.com/engine/install/",
		})
	}

	if r.Docker.DaemonRunning.Status == StatusFail {
		issues = append(issues, Issue{
			Severity: "error",
			Category: "docker",
			Message:  "Docker daemon is not running",
			Fix:      "sudo systemctl start docker",
		})
	}

	// Check dependencies
	if r.Dependencies.UFWInstalled.Status == StatusWarning {
		issues = append(issues, Issue{
			Severity: "warning",
			Category: "dependencies",
			Message:  "UFW is not installed (optional)",
			Fix:      "sudo apt-get install ufw",
		})
	}

	return issues
}

// Issue represents a diagnostic issue
type Issue struct {
	Severity string // "error", "warning", "info"
	Category string // "system", "docker", "permissions", etc.
	Message  string
	Fix      string
}

package diagnostics

import (
	"time"
)

// RunAll performs all diagnostic checks
func RunAll(version, commit string, verbose bool) *DiagnosticResults {
	results := &DiagnosticResults{
		Timestamp: time.Now(),
	}

	// Run all checks
	results.System = CheckSystem()
	results.Docker = CheckDocker()
	results.Permissions = CheckPermissions()
	results.Dependencies = CheckDependencies()
	results.Config = CheckConfig()
	results.DockerShield = CheckDockerShield(version, commit)

	return results
}

// GetStatusMessage returns an overall status message
func (r *DiagnosticResults) GetStatusMessage() string {
	if r.HasErrors() {
		return "Issues found"
	}
	if r.HasWarnings() {
		return "Mostly healthy"
	}
	return "All checks passed"
}

// GetExitCode returns the appropriate exit code
func (r *DiagnosticResults) GetExitCode() int {
	if r.HasErrors() {
		return 2 // Major issues
	}
	if r.HasWarnings() {
		return 1 // Minor issues
	}
	return 0 // All good
}

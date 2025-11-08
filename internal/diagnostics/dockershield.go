package diagnostics

import (
	"fmt"
	"os"
	"path/filepath"
	"runtime"
)

// CheckDockerShield performs DockerShield-specific checks
func CheckDockerShield(version, commit string) *DockerShieldInfo {
	return &DockerShieldInfo{
		Version:        checkVersion(version),
		BinaryLocation: checkBinaryLocation(),
		BuildInfo:      checkBuildInfo(commit),
	}
}

// checkVersion returns version information
func checkVersion(version string) CheckResult {
	return CheckResult{
		Status:  StatusPass,
		Value:   version,
		Message: fmt.Sprintf("Version: %s", version),
	}
}

// checkBinaryLocation finds where the binary is located
func checkBinaryLocation() CheckResult {
	executable, err := os.Executable()
	if err != nil {
		return CheckResult{
			Status:  StatusWarning,
			Value:   "unknown",
			Message: "Cannot determine binary location",
		}
	}

	// Resolve symlinks
	realPath, err := filepath.EvalSymlinks(executable)
	if err != nil {
		realPath = executable
	}

	return CheckResult{
		Status:  StatusPass,
		Value:   realPath,
		Message: fmt.Sprintf("Binary: %s", realPath),
	}
}

// checkBuildInfo returns build information
func checkBuildInfo(commit string) CheckResult {
	buildInfo := fmt.Sprintf("go%s %s/%s", runtime.Version(), runtime.GOOS, runtime.GOARCH)

	if commit != "unknown" && commit != "" {
		buildInfo = fmt.Sprintf("%s (commit: %s)", buildInfo, commit)
	}

	return CheckResult{
		Status:  StatusPass,
		Value:   buildInfo,
		Message: fmt.Sprintf("Build: %s", buildInfo),
	}
}

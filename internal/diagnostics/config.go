package diagnostics

import (
	"fmt"
	"os"
	"path/filepath"
)

// CheckConfig performs configuration file checks
func CheckConfig() *ConfigInfo {
	homeDir, _ := os.UserHomeDir()
	configDir := filepath.Join(homeDir, ".dockershield")

	return &ConfigInfo{
		ConfigDirExists:  checkConfigDirExists(configDir),
		ConfigFileExists: checkConfigFileExists(configDir),
		ConfigFileValid:  checkConfigFileValid(configDir),
		StateDirExists:   checkStateDirExists(configDir),
		StateDirWritable: checkStateDirWritable(configDir),
		StateFileExists:  checkStateFileExists(configDir),
	}
}

// checkConfigDirExists checks if config directory exists
func checkConfigDirExists(configDir string) CheckResult {
	info, err := os.Stat(configDir)
	if err != nil {
		if os.IsNotExist(err) {
			return CheckResult{
				Status:  StatusWarning,
				Value:   "no",
				Message: "Config directory does not exist",
				Fix:     fmt.Sprintf("Will be created automatically at: %s", configDir),
			}
		}
		return CheckResult{
			Status:  StatusWarning,
			Value:   "unknown",
			Message: "Cannot check config directory",
		}
	}

	if !info.IsDir() {
		return CheckResult{
			Status:  StatusFail,
			Value:   "no",
			Message: "Config path exists but is not a directory",
		}
	}

	return CheckResult{
		Status:  StatusPass,
		Value:   configDir,
		Message: fmt.Sprintf("Config directory exists: %s", configDir),
	}
}

// checkConfigFileExists checks if config.yaml exists
func checkConfigFileExists(configDir string) CheckResult {
	configFile := filepath.Join(configDir, "config.yaml")

	_, err := os.Stat(configFile)
	if err != nil {
		if os.IsNotExist(err) {
			return CheckResult{
				Status:  StatusWarning,
				Value:   "no",
				Message: "Config file not found (using defaults)",
			}
		}
		return CheckResult{
			Status:  StatusWarning,
			Value:   "unknown",
			Message: "Cannot check config file",
		}
	}

	return CheckResult{
		Status:  StatusPass,
		Value:   configFile,
		Message: fmt.Sprintf("Config file exists: %s", configFile),
	}
}

// checkConfigFileValid checks if config file is valid YAML
func checkConfigFileValid(configDir string) CheckResult {
	configFile := filepath.Join(configDir, "config.yaml")

	// Check if file exists first
	_, err := os.Stat(configFile)
	if err != nil {
		return CheckResult{
			Status:  StatusSkipped,
			Value:   "N/A",
			Message: "Config file does not exist",
		}
	}

	// Try to read it
	data, err := os.ReadFile(configFile)
	if err != nil {
		return CheckResult{
			Status:  StatusFail,
			Value:   "no",
			Message: "Cannot read config file",
		}
	}

	// Basic validation - just check it's readable
	if len(data) == 0 {
		return CheckResult{
			Status:  StatusWarning,
			Value:   "empty",
			Message: "Config file is empty",
		}
	}

	// TODO: Parse YAML to validate structure
	// For now, just return pass if readable

	return CheckResult{
		Status:  StatusPass,
		Value:   "yes",
		Message: "Config file is readable",
	}
}

// checkStateDirExists checks if state directory exists
func checkStateDirExists(configDir string) CheckResult {
	// State dir is same as config dir
	info, err := os.Stat(configDir)
	if err != nil {
		if os.IsNotExist(err) {
			return CheckResult{
				Status:  StatusWarning,
				Value:   "no",
				Message: "State directory does not exist",
				Fix:     "Will be created automatically",
			}
		}
		return CheckResult{
			Status:  StatusWarning,
			Value:   "unknown",
			Message: "Cannot check state directory",
		}
	}

	if !info.IsDir() {
		return CheckResult{
			Status:  StatusFail,
			Value:   "no",
			Message: "State path exists but is not a directory",
		}
	}

	return CheckResult{
		Status:  StatusPass,
		Value:   configDir,
		Message: "State directory exists",
	}
}

// checkStateDirWritable checks if state directory is writable
func checkStateDirWritable(configDir string) CheckResult {
	// Try to create directory if it doesn't exist
	err := os.MkdirAll(configDir, 0755)
	if err != nil {
		return CheckResult{
			Status:  StatusFail,
			Value:   "no",
			Message: "Cannot create state directory",
			Fix:     "Check permissions on home directory",
		}
	}

	// Try to write a test file
	testFile := filepath.Join(configDir, ".write_test")
	err = os.WriteFile(testFile, []byte("test"), 0644)
	if err != nil {
		return CheckResult{
			Status:  StatusFail,
			Value:   "no",
			Message: "State directory is not writable",
			Fix:     fmt.Sprintf("Check permissions on %s", configDir),
		}
	}

	// Clean up test file
	os.Remove(testFile)

	return CheckResult{
		Status:  StatusPass,
		Value:   "yes",
		Message: "State directory is writable",
	}
}

// checkStateFileExists checks if state.json exists
func checkStateFileExists(configDir string) CheckResult {
	stateFile := filepath.Join(configDir, "state.json")

	info, err := os.Stat(stateFile)
	if err != nil {
		if os.IsNotExist(err) {
			return CheckResult{
				Status:  StatusWarning,
				Value:   "no",
				Message: "No previous scan state found",
			}
		}
		return CheckResult{
			Status:  StatusWarning,
			Value:   "unknown",
			Message: "Cannot check state file",
		}
	}

	return CheckResult{
		Status:  StatusPass,
		Value:   stateFile,
		Message: fmt.Sprintf("State file found (%d bytes)", info.Size()),
	}
}

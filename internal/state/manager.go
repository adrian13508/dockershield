package state

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/adrian13508/dockershield/pkg/models"
)

const (
	stateFileName = "state.json"
	configDirName = ".dockershield"
)

// Manager handles state persistence
type Manager struct {
	stateDir  string
	stateFile string
}

// NewManager creates a new state manager
func NewManager() (*Manager, error) {
	homeDir, err := os.UserHomeDir()
	if err != nil {
		return nil, fmt.Errorf("failed to get home directory: %w", err)
	}

	stateDir := filepath.Join(homeDir, configDirName)
	stateFile := filepath.Join(stateDir, stateFileName)

	return &Manager{
		stateDir:  stateDir,
		stateFile: stateFile,
	}, nil
}

// Save saves scan results to state file
func (m *Manager) Save(result *models.ScanResult) error {
	// Ensure directory exists
	err := os.MkdirAll(m.stateDir, 0755)
	if err != nil {
		return fmt.Errorf("failed to create state directory: %w", err)
	}

	// Marshal to JSON
	data, err := json.MarshalIndent(result, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal state: %w", err)
	}

	// Use atomic write pattern to prevent corruption
	// Write to temporary file first, then rename
	tempFile := m.stateFile + ".tmp"

	// Write to temp file with restrictive permissions (owner read/write only)
	err = os.WriteFile(tempFile, data, 0600)
	if err != nil {
		return fmt.Errorf("failed to write temporary state file: %w", err)
	}

	// Atomically replace the state file
	err = os.Rename(tempFile, m.stateFile)
	if err != nil {
		// Clean up temp file on failure
		os.Remove(tempFile)
		return fmt.Errorf("failed to update state file: %w", err)
	}

	return nil
}

// Load loads scan results from state file
func (m *Manager) Load() (*models.ScanResult, error) {
	// Check if file exists
	_, err := os.Stat(m.stateFile)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, fmt.Errorf("no previous scan found")
		}
		return nil, fmt.Errorf("failed to access state file: %w", err)
	}

	// Read file
	data, err := os.ReadFile(m.stateFile)
	if err != nil {
		return nil, fmt.Errorf("failed to read state file: %w", err)
	}

	// Unmarshal
	var result models.ScanResult
	err = json.Unmarshal(data, &result)
	if err != nil {
		return nil, fmt.Errorf("failed to parse state file: %w", err)
	}

	return &result, nil
}

// Exists checks if a state file exists
func (m *Manager) Exists() bool {
	_, err := os.Stat(m.stateFile)
	return err == nil
}

// GetAge returns how old the state is
func (m *Manager) GetAge() (time.Duration, error) {
	result, err := m.Load()
	if err != nil {
		return 0, err
	}

	return time.Since(result.Timestamp), nil
}

// IsStale checks if state is older than the given duration
func (m *Manager) IsStale(maxAge time.Duration) (bool, error) {
	age, err := m.GetAge()
	if err != nil {
		return false, err
	}

	return age > maxAge, nil
}

// GetPath returns the state file path
func (m *Manager) GetPath() string {
	return m.stateFile
}

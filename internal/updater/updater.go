package updater

import (
	"fmt"
	"time"

	"github.com/blang/semver"
	"github.com/rhysd/go-github-selfupdate/selfupdate"
)

const (
	// GitHubOwner is the repository owner
	GitHubOwner = "adrian13508"
	// GitHubRepo is the repository name
	GitHubRepo = "dockershield"
)

// UpdateInfo contains information about an available update
type UpdateInfo struct {
	CurrentVersion string
	LatestVersion  string
	UpdateURL      string
	ReleaseNotes   string
	Available      bool
}

// CheckForUpdates checks if a newer version is available
func CheckForUpdates(currentVersion string) (*UpdateInfo, error) {
	// Parse current version
	current, err := semver.Parse(currentVersion)
	if err != nil {
		return nil, fmt.Errorf("invalid current version: %w", err)
	}

	// Check for updates
	latest, found, err := selfupdate.DetectLatest(GitHubOwner + "/" + GitHubRepo)
	if err != nil {
		return nil, fmt.Errorf("failed to check for updates: %w", err)
	}

	// Handle case where no releases are found (private repo or no releases published)
	if !found || latest == nil {
		return &UpdateInfo{
			CurrentVersion: currentVersion,
			LatestVersion:  currentVersion,
			UpdateURL:      "",
			ReleaseNotes:   "",
			Available:      false,
		}, fmt.Errorf("no releases found - repository may be private or has no published releases")
	}

	info := &UpdateInfo{
		CurrentVersion: currentVersion,
		LatestVersion:  latest.Version.String(),
		UpdateURL:      latest.URL,
		ReleaseNotes:   latest.ReleaseNotes,
		Available:      found && latest.Version.GT(current),
	}

	return info, nil
}

// DoSelfUpdate performs the self-update
func DoSelfUpdate(currentVersion string) error {
	// Parse current version
	current, err := semver.Parse(currentVersion)
	if err != nil {
		return fmt.Errorf("invalid current version: %w", err)
	}

	// Check and update
	latest, err := selfupdate.UpdateSelf(current, GitHubOwner+"/"+GitHubRepo)
	if err != nil {
		return fmt.Errorf("failed to update: %w", err)
	}

	// Handle case where latest is nil (no releases available)
	if latest == nil {
		return fmt.Errorf("no releases found - repository may be private or has no published releases")
	}

	if latest.Version.Equals(current) {
		return fmt.Errorf("already on latest version %s", current)
	}

	return nil
}

// ShouldCheckForUpdates determines if we should check for updates
// (to avoid checking on every command run)
func ShouldCheckForUpdates(lastCheck time.Time) bool {
	// Check once per day
	return time.Since(lastCheck) > 24*time.Hour
}

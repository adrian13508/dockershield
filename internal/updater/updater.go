package updater

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"net/http"
	"os"
	"path"
	"strings"
	"time"

	"github.com/blang/semver"
	"github.com/inconshreveable/go-update"
	"github.com/rhysd/go-github-selfupdate/selfupdate"
)

const (
	// GitHubOwner is the repository owner
	GitHubOwner = "adrian13508"
	// GitHubRepo is the repository name
	GitHubRepo = "dockershield"

	binaryName    = "dockershield"
	checksumsFile = "checksums.txt"
	maxDownload   = 200 << 20 // refuse absurdly large downloads
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
	current, err := semver.Parse(currentVersion)
	if err != nil {
		return nil, fmt.Errorf("invalid current version: %w", err)
	}

	latest, found, err := selfupdate.DetectLatest(GitHubOwner + "/" + GitHubRepo)
	if err != nil {
		return nil, fmt.Errorf("failed to check for updates: %w", err)
	}
	if !found || latest == nil {
		return nil, fmt.Errorf("no releases found for this platform")
	}

	return &UpdateInfo{
		CurrentVersion: currentVersion,
		LatestVersion:  latest.Version.String(),
		UpdateURL:      latest.URL,
		ReleaseNotes:   latest.ReleaseNotes,
		Available:      latest.Version.GT(current),
	}, nil
}

// DoSelfUpdate downloads the latest release, verifies its SHA256 against the
// release's checksums.txt and replaces the running binary.
func DoSelfUpdate(currentVersion string) error {
	current, err := semver.Parse(currentVersion)
	if err != nil {
		return fmt.Errorf("invalid current version: %w", err)
	}

	latest, found, err := selfupdate.DetectLatest(GitHubOwner + "/" + GitHubRepo)
	if err != nil {
		return fmt.Errorf("failed to check for updates: %w", err)
	}
	if !found || latest == nil {
		return fmt.Errorf("no releases found for this platform")
	}
	if !latest.Version.GT(current) {
		return fmt.Errorf("already on latest version %s", current)
	}

	exe, err := os.Executable()
	if err != nil {
		return fmt.Errorf("cannot locate the running binary: %w", err)
	}
	client := &http.Client{Timeout: 5 * time.Minute}
	return installVerified(client, latest.AssetURL, exe)
}

// installVerified downloads the archive once, checks it against checksums.txt
// from the same release, and only then replaces target with the binary inside.
func installVerified(client *http.Client, assetURL, target string) error {
	archive, err := fetch(client, assetURL)
	if err != nil {
		return err
	}
	sums, err := fetch(client, assetURL[:strings.LastIndex(assetURL, "/")+1]+checksumsFile)
	if err != nil {
		return err
	}
	if err := verifyChecksum(sums, path.Base(assetURL), archive); err != nil {
		return err
	}

	binary, err := selfupdate.UncompressCommand(bytes.NewReader(archive), assetURL, binaryName)
	if err != nil {
		return fmt.Errorf("failed to unpack release archive: %w", err)
	}
	return update.Apply(binary, update.Options{TargetPath: target})
}

// verifyChecksum checks data against the entry for name in a sha256sum-style
// checksums file ("<hex>  <name>" per line).
func verifyChecksum(checksums []byte, name string, data []byte) error {
	for _, line := range strings.Split(string(checksums), "\n") {
		fields := strings.Fields(line)
		if len(fields) != 2 || strings.TrimPrefix(fields[1], "*") != name {
			continue
		}
		sum := sha256.Sum256(data)
		if got := hex.EncodeToString(sum[:]); !strings.EqualFold(got, fields[0]) {
			return fmt.Errorf("checksum mismatch for %s: expected %s, got %s", name, fields[0], got)
		}
		return nil
	}
	return fmt.Errorf("%s is not listed in %s; refusing to install an unverified binary", name, checksumsFile)
}

func fetch(client *http.Client, url string) ([]byte, error) {
	resp, err := client.Get(url)
	if err != nil {
		return nil, fmt.Errorf("download failed: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("download of %s failed: %s", url, resp.Status)
	}
	data, err := io.ReadAll(io.LimitReader(resp.Body, maxDownload+1))
	if err != nil {
		return nil, fmt.Errorf("download of %s failed: %w", url, err)
	}
	if len(data) > maxDownload {
		return nil, fmt.Errorf("download of %s exceeds %d bytes", url, maxDownload)
	}
	return data, nil
}

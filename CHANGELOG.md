# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- `scan --fail-on <severity>` exits with code 2 when findings at or above the given severity exist (critical, high, medium, low)
- `version --check` asks GitHub whether a newer release exists
- `install.sh` verifies the SHA256 checksum of the downloaded archive against `checksums.txt` and aborts on mismatch; `DOCKERSHIELD_VERSION` pins a release, `INSTALL_DIR` changes the target directory
- CI workflow: gofmt, `go vet`, `go test -race`, golangci-lint, shellcheck on every pull request
- Issue templates, `HOW_THIS_IS_BUILT.md`, test environment in `test/exposed/compose.yml`

### Changed
- `scan` and `version` no longer contact GitHub to look for a newer release. Use `version --check` or `upgrade`
- The rootkit check no longer runs `rkhunter --versioncheck` (a network request). The JSON field `database_version` is now omitted
- README rewritten: statistics without a source removed, added "How it works", "Limitations" and a comparison with other tools
- `EXAMPLE_OUTPUT.md` and `example_report.json` replaced with output from a real run
- SECURITY.md: corrected the claim that `upgrade` verifies checksums (it does not); new contact address
- `install.sh` uses `mktemp -d` instead of a predictable directory in `/tmp`

### Fixed
- `go.mod` listed direct dependencies as indirect
- Release workflow used a Go version older than the one in `go.mod`

## [0.1.3] - 2026-07-14

### Added
- **Prometheus Metrics Output**
  - New `scan --prometheus` flag emits metrics in the Prometheus text exposition format
  - Designed for the node_exporter textfile collector: `dockershield scan --prometheus > dockershield.prom`
  - Metrics: security score, risk counts by severity, publicly exposed ports per container, UFW status, Docker firewall bypass status, container counts by state, last scan timestamp
  - Enables continuous monitoring and alerting via cron + Prometheus/Alertmanager/Grafana — no daemon required
  - See the "Continuous Monitoring (Prometheus)" section in the README for cron and alert rule examples

### Fixed
- `TestJSONWriteToFile` used an absolute path rejected by `WriteToFile` path validation

## [0.1.2] - 2025-11-09

### Fixed
- **Upgrade Command Compatibility**
  - Fixed GoReleaser archive naming to use lowercase OS names (darwin, linux, windows)
  - Corrected issue where `dockershield upgrade` failed with "no releases found" error
  - go-github-selfupdate library now properly detects and downloads release assets

- **Developer Experience**
  - Added current version display to upgrade command output
  - Fixed .gitignore pattern to only ignore root binary, not source directory

### Technical Details
- Changed GoReleaser template from `{{- title .Os }}_` to `{{- .Os }}_`
- Archive names now match Go's runtime.GOOS values for proper asset detection
- Release assets: `dockershield_0.1.2_darwin_arm64.tar.gz` (lowercase) instead of `dockershield_0.1.2_Darwin_arm64.tar.gz` (title case)

## [0.1.1] - 2025-11-09

### Fixed
- Updated install script to work with GoReleaser archive structure
- Fixed automated release workflow to use GoReleaser v2

## [0.1.0] - 2025-11-07

### Added
- **Docker Security Scanning**
  - Container listing and port extraction
  - Network topology analysis
  - Port risk analysis for 50+ dangerous ports (databases, admin panels, remote access)
  - UFW bypass detection
  - iptables/firewall monitoring

- **System Security Checks**
  - SSH configuration audit (root login, password auth, key-only setup)
  - fail2ban intrusion prevention status
  - System update tracking (pending updates, security patches, reboot requirements)

- **CLI Commands**
  - `scan` - Full security scan with detailed report
  - `status` - Quick cached summary of security status
  - `check <category>` - Focused scans (docker, ssh, fail2ban, updates)
  - `doctor` - System diagnostics and health check
  - `upgrade` - Auto-update to latest version

- **Reporting & Output**
  - Security scoring (0-100) with EXCELLENT/GOOD/FAIR/POOR/CRITICAL ratings
  - Risk classification (CRITICAL/HIGH/MEDIUM/LOW)
  - Actionable recommendations with exact commands to fix issues
  - JSON output format for CI/CD and automation
  - Color-coded terminal output
  - Verbose mode with network information

- **Distribution & Updates**
  - Auto-update system with release notifications
  - One-line installer script
  - Cross-platform builds (Linux amd64/arm64/arm, macOS Intel/M1/M2, Windows)
  - GitHub Actions CI/CD pipeline

- **Documentation**
  - Comprehensive README with examples
  - Example output scenarios
  - Project structure documentation
  - Installation and usage guides

### Security
- Port exposure detection for critical services
- Public vs localhost binding analysis
- SSH hardening recommendations
- Intrusion prevention monitoring

---

## Release Notes

### v0.1.0 - Initial Release

DockerShield's first public release provides comprehensive VPS security scanning with a focus on Docker container security. This release addresses the common problem where Docker bypasses UFW firewall rules, potentially exposing critical services to the internet.

**Key Highlights:**
- Scans Docker containers in under 5 seconds
- Detects 50+ dangerous ports with risk classification
- Provides actionable fix commands for every issue
- Zero configuration required - works out of the box
- Lightweight (8MB binary, ~15MB memory usage)

**Who should use this:**
- Indie developers running VPS instances
- Self-hosters managing Docker containers
- DevOps teams needing quick security visibility
- Anyone concerned about accidental port exposure

**Known Limitations:**
- Requires Docker API access (typically requires root/sudo)
- Currently Linux-focused (macOS/Windows support experimental)
- No persistent state tracking (coming in v0.2.0)

**Upgrade Path:**
- This is the initial release
- Future updates will maintain backward compatibility
- Breaking changes will only occur in major version bumps (v2.0.0, etc.)

[Unreleased]: https://github.com/adrian13508/dockershield/compare/v0.1.3...HEAD
[0.1.3]: https://github.com/adrian13508/dockershield/compare/v0.1.2...v0.1.3
[0.1.2]: https://github.com/adrian13508/dockershield/compare/v0.1.1...v0.1.2
[0.1.1]: https://github.com/adrian13508/dockershield/compare/v0.1.0...v0.1.1
[0.1.0]: https://github.com/adrian13508/dockershield/releases/tag/v0.1.0

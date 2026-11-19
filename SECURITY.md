# Security Policy

## Supported versions

Only the latest release receives fixes.

## Reporting a vulnerability

Do not open a public issue for a vulnerability.

- Preferred: a private [GitHub Security Advisory](https://github.com/adrian13508/dockershield/security/advisories/new)
- Or email: adrian@kurowski.dev

Include the version (`dockershield version`), what you observed, and steps to reproduce.

DockerShield is maintained by one person in spare time. There is no guaranteed response
time and no bug bounty. The project has not had an external security audit.

## What the tool does on your system

- It needs the Docker socket. Access to the Docker socket is equivalent to root on the host.
- The firewall and host checks need root. The README section "How it works" lists every
  command that is run and every file that is read.
- `probe` connects to TCP ports of the host you name, and only after you confirm with
  `--i-own-this-host` that the host is yours. It sends no credentials.
- `scan`, `status`, `check` and `doctor` make no network requests. `upgrade` and
  `version --check` contact GitHub. Releases up to and including v0.1.3 also
  contacted GitHub at the end of every text-mode scan.
- There is no telemetry.
- It writes `~/.dockershield/state.json` after each scan, and the file given to `-o`.
  It changes nothing else. `upgrade` replaces the DockerShield binary.

## Supply chain

- Releases are built by GitHub Actions with GoReleaser from a tag. Each release includes
  `checksums.txt` (SHA256).
- `install.sh` and the manual install steps in the README verify the SHA256 checksum.
- `dockershield upgrade` downloads the release archive and `checksums.txt` and replaces
  the binary only if the SHA256 matches. Releases up to and including v0.1.3 did not
  verify anything during `upgrade`; from those versions, update with `install.sh` or by hand.
- Releases are not signed. The checksums are hosted next to the binaries, so they do not
  protect against a compromised GitHub account or release pipeline.

## Reports

Scan reports describe your SSH configuration, user accounts and open ports. Treat them as
sensitive. Files written with `-o` are created with mode `0600`.

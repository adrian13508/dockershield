# How this code is written and checked

DockerShield is written by one person, with AI coding tools.

## Use of AI tools

- Changes made after v0.1.3 are written with an AI coding assistant (Claude Code). That
  includes code, tests, the README and this file.
- TODO(Adrian): State how the releases up to v0.1.3 were written: which parts by hand,
  which with which tool. Only what you remember for certain.
- The assistant works in the repository under the maintainer's direction. The maintainer
  decides what gets built, reads the changes and merges them.
- TODO(Adrian): One or two sentences on how you review a change before merging: what you
  read, what you run, on which machines.

## What is checked, and how

- `go vet`, `go test ./...`, `golangci-lint` and `shellcheck install.sh` run in CI on
  every pull request.
- Unit tests cover the port risk rating, the score, the JSON and Prometheus reporters and
  the `--fail-on` logic.
- The scanner is run against a set of deliberately misconfigured containers in
  `test/exposed/compose.yml`. The example output in the README and in `EXAMPLE_OUTPUT.md`
  is copied from such a run, not written by hand.
- The install script was run against a real release, and against a release with a
  tampered checksum to confirm that it refuses to install.

## What is not checked

- The firewall, SSH, fail2ban and other host checks have no automated tests. They shell
  out to system tools and read system files, and have only been run by hand.
- No distribution matrix. TODO(Adrian): list the distributions and Docker versions you
  have actually run it on.
- No external security audit.

The README section "Limitations" lists the known wrong results. If you find a claim in
the documentation that the code does not back up, please open an issue.

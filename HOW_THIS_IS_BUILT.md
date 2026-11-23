# How this code is written and checked

Skobel is written by one person, with AI coding tools.

## Use of AI tools

- Changes made after v0.1.3 are written with an AI coding assistant (Claude Code). That
  includes code, tests, the README and this file.
- The assistant works in the repository under the maintainer's direction. The maintainer
  decides what gets built, reads the changes and merges them.

## What is checked, and how

- `go vet`, `go test ./...`, `golangci-lint` and `shellcheck install.sh` run in CI on
  every pull request.
- Unit tests cover address classification, the port risk rating, findings and the score,
  parsing of iptables rules and Docker daemon settings, the SSH config parser, the JSON
  and Prometheus reporters, checksum verification in `upgrade`, and the `--fail-on` logic.
- An integration test in CI starts the deliberately misconfigured containers in
  `test/exposed/compose.yml`, runs the built scanner and checks the findings. It then
  starts `compose.fixed.yml` and checks that the findings are gone.
- `probe` is tested against local fake servers for each protocol it recognises, and in
  the integration test against the real PostgreSQL and nginx containers. It was also run
  between two containers on a dual-stack network, with one port blocked for IPv4 only.
- `scan --report` and `compare` are covered by the integration test. The HTML report was
  also opened in Chrome and printed to PDF once by hand.
- The example output in the README and in `EXAMPLE_OUTPUT.md` is copied from such a run,
  not written by hand.
- The install script was run against a real release, and against a release with a
  tampered checksum to confirm that it refuses to install.

## What is not checked

- The firewall findings are tested against saved rule sets, including the rules that
  ufw-docker installs, but not against a live host with UFW.
- The fail2ban, update, user, rootkit, integrity and log checks have no automated tests.
  They shell out to system tools and read system files, and have only been run by hand.
- No distribution matrix.
- No external security audit.

The README section "Limitations" lists the known wrong results. If you find a claim in
the documentation that the code does not back up, please open an issue.

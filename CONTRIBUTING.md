# Contributing

Bug reports, false positive reports and pull requests are welcome.

## Reporting a problem

Use the issue templates. For a wrong result (a false alarm or a missed exposure) the most
useful things are the output of `docker inspect` for the affected container, the
`ports` section of `skobel scan --json`, and for firewall findings the output of
`sudo iptables-save`. Remove anything you consider private first.

Security vulnerabilities in Skobel itself: see [SECURITY.md](SECURITY.md).

## Development

Requires the Go version in [go.mod](go.mod) and, for the test environment, Docker with
the compose plugin.

```bash
make build
go vet ./...
go test ./...
golangci-lint run          # config in .golangci.yml
shellcheck install.sh
```

CI runs all of these on every pull request, plus the integration test below.
A pull request is merged only when CI passes.

Integration test (starts and removes the containers in `test/exposed/`; use a Docker
daemon with nothing else running on the same ports):

```bash
go build -o skobel ./cmd/skobel
SKOBEL_BIN=$PWD/skobel go test -tags integration ./test/
```

A set of deliberately misconfigured services lives in `test/exposed/compose.yml`:

```bash
docker compose -f test/exposed/compose.yml up -d
./skobel scan
docker compose -f test/exposed/compose.yml down
```

Do not start it on a machine that is reachable from the internet.

## Rules for changes

- New behaviour comes with a unit test.
- Flags and JSON fields are not renamed or removed. New JSON fields may be added.
- The scanner makes no network requests unless the user runs a command whose purpose is
  network access (`upgrade`, `version --check`). No telemetry.
- The scanner does not modify the host.
- Documentation states only what the code does. No statistics without a source.
- Add a line to `CHANGELOG.md` under "Unreleased".

One pull request per topic. Commit messages follow
[Conventional Commits](https://www.conventionalcommits.org/) (`feat:`, `fix:`, `docs:`),
because the release notes are generated from them.

[HOW_THIS_IS_BUILT.md](HOW_THIS_IS_BUILT.md) describes how the maintainer writes and checks
code, including the use of AI tools. The same expectations apply to contributions: you are
responsible for what you submit, whatever tool produced it.

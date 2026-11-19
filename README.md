# DockerShield

[![Release](https://img.shields.io/github/v/release/adrian13508/dockershield)](https://github.com/adrian13508/dockershield/releases)
[![CI](https://github.com/adrian13508/dockershield/actions/workflows/ci.yml/badge.svg)](https://github.com/adrian13508/dockershield/actions/workflows/ci.yml)
[![License](https://img.shields.io/github/license/adrian13508/dockershield)](LICENSE)

Docker publishes container ports by writing its own iptables rules, so a port mapped
with `-p 5432:5432` is reachable from outside even when UFW says it is denied
([Docker documentation](https://docs.docker.com/engine/network/packet-filtering-firewalls/#docker-and-ufw)).
DockerShield is a read-only command-line scanner that lists which container ports are
published and on which addresses, checks whether UFW or the `DOCKER-USER` chain filters
them, and audits a few host settings such as the SSH configuration.
It does not change any configuration and it does not fix anything. A scan on the server
cannot tell whether a port is reachable from the internet; for that, the separate
`probe` command connects to the ports from another machine.

> This README describes the `main` branch. The latest release is v0.1.3 and predates
> the findings list, the IPv6 checks, `probe` and the checksum-verified `upgrade` described here.
> See [CHANGELOG.md](CHANGELOG.md).

## Example

Real output, shortened. The scan ran against the test services in
[test/exposed/compose.yml](test/exposed/compose.yml). The full, unedited output is in
[EXAMPLE_OUTPUT.md](EXAMPLE_OUTPUT.md).

```
$ dockershield scan
[...]
┌────────────────────────────────────────────┐
│  SECURITY SUMMARY                          │
├────────────────────────────────────────────┤
│  Security Score: 45/100 (POOR)             │
│                                            │
│  🔴 Critical Issues: 1                     │
│  ⚠️ High Issues: 2                        │
│  🟡 Medium Issues: 2                       │
│  ℹ️ Low Issues: 2                          │
└────────────────────────────────────────────┘


📦 RUNNING CONTAINERS
═══════════════════════════════════════════════
❌ ISSUES dockershield-test-db-1 - CRITICAL×1
✅ OK dockershield-test-cache-1
❌ ISSUES dockershield-test-admin-1 - HIGH×1
✅ OK dockershield-test-web-1
⚠️  WARN dockershield-test-watcher-1 - MEDIUM×1
❌ ISSUES dockershield-test-hostnet-1 - HIGH×1


🔧 FINDINGS AND FIXES
═══════════════════════════════════════════════

1. [CRITICAL] Container 'dockershield-test-db-1': PostgreSQL published on all interfaces
   Port: 5432/tcp on 0.0.0.0, ::
   Why: Other machines can connect to this port unless a firewall outside Docker blocks it. UFW rules do not apply to published container ports by default.
   Fix:
     In compose, bind the port to localhost:
       ports:
         - "127.0.0.1:5432:5432"
     With docker run:
       -p 127.0.0.1:5432:5432
     If only other containers use it, remove the `ports:` entry; containers on the same compose network reach it by service name on port 5432.
[...]
```

With the suggested fixes applied
([test/exposed/compose.fixed.yml](test/exposed/compose.fixed.yml)) the same scan
reports 95/100. The remaining finding is about the test host itself.

## Install

DockerShield needs access to the Docker socket. The firewall and host checks need root.
The host checks are written for Linux. On macOS and Windows only the container scan
works.

### Release binary, verified by hand

```bash
VERSION=0.1.3
ARCHIVE=dockershield_${VERSION}_linux_x86_64.tar.gz   # or linux_arm64, linux_armv7, darwin_arm64, darwin_x86_64
BASE=https://github.com/adrian13508/dockershield/releases/download/v${VERSION}

curl -sSLO "$BASE/$ARCHIVE"
curl -sSLO "$BASE/checksums.txt"
sha256sum -c checksums.txt --ignore-missing
tar -xzf "$ARCHIVE" dockershield
sudo install -m 0755 dockershield /usr/local/bin/dockershield
```

`checksums.txt` is published with every release. It protects against a corrupted or
swapped download. It does not protect against a compromised GitHub account, because
the checksums come from the same place as the binaries. Releases are not signed.

### From source

```bash
go install github.com/adrian13508/dockershield/cmd/dockershield@latest
```

Requires the Go version listed in [go.mod](go.mod).

### Install script

The script does the same steps as the manual install above, including the SHA256 check,
and stops if the checksum does not match. Download it and read it before running it:

```bash
curl -sSLO https://raw.githubusercontent.com/adrian13508/dockershield/main/install.sh
less install.sh
bash install.sh
```

`DOCKERSHIELD_VERSION=v0.1.3` pins a release. `INSTALL_DIR` changes the target directory
(default `/usr/local/bin`, which uses `sudo`).

## Usage

```bash
sudo dockershield scan                     # full scan, text output
sudo dockershield scan --verbose           # include stopped containers and networks
sudo dockershield scan --json              # JSON on stdout
sudo dockershield scan --json -o report.json
sudo dockershield scan --prometheus        # metrics for the node_exporter textfile collector
sudo dockershield scan --fail-on critical  # exit code 2 if a finding at or above this level exists

dockershield status                        # summary of the last scan, read from ~/.dockershield/state.json
dockershield check firewall                # one category: ports, networks, firewall, containers
dockershield doctor                        # checks that the scanner's own requirements are met
dockershield version --check               # asks GitHub whether a newer release exists
dockershield upgrade                       # replaces the binary with the latest release
dockershield probe HOST --from-report report.json   # from another machine, see below
```

`-o` accepts relative paths only. For an absolute path, redirect stdout.

## Checking from outside: probe

A scan shows what the server publishes. It cannot see a provider firewall or a rule in
`DOCKER-USER` that happens to cover the port. `probe` connects to the ports from another
machine and reports what answers.

```bash
# on the server
sudo dockershield scan --json > report.json

# on a different machine, after copying report.json there
dockershield probe my-server.example.com --from-report report.json --i-own-this-host
```

Output from the test setup, after PostgreSQL was blocked for IPv4 only (full run in
[EXAMPLE_OUTPUT.md](EXAMPLE_OUTPUT.md)):

```
5432/tcp  (container dockershield-test-db-1; expected PostgreSQL; bound on 0.0.0.0, ::)
  192.168.0.2                             published but blocked on the way (no answer)
  fd00:d5:d5::2                           published and confirmed from outside: PostgreSQL, answered the SSL negotiation request
```

**Only probe servers you own or are authorized to test.** Connecting to ports of other
people's systems may be illegal. The first probe of a host is refused unless you pass
`--i-own-this-host`; the confirmation is remembered per host in
`~/.dockershield/probe_hosts`.

What it does:

- Resolves the host and probes every address, IPv4 and IPv6 separately (`-4` or `-6` to
  pick one).
- Opens one TCP connection per port and address. `open` means the connection was
  established, `closed` means it was refused, `filtered` means no answer within the
  timeout.
- Waits up to 1.5 s for a banner the server sends on its own (SSH, MySQL, SMTP, FTP, VNC).
- If there is none and the port is expected to be PostgreSQL, Redis or HTTP, sends one
  message: an SSL negotiation request, `PING`, or `HEAD / HTTP/1.0`. Nothing is sent to
  a port whose expected service is unknown. It never sends credentials.

Which ports:

| Option | Ports |
|--------|-------|
| none | the 38 ports of the scanner's table |
| `--from-report report.json` | TCP ports the scan found published on all interfaces or on a public address |
| `--ports 22,5432` | the listed ports |

Limits: one host per run, no ranges, at most 200 ports, at most 32 connections at a time
(default 10), timeout at most 30 s (default 3 s). `--json` prints the results as JSON.
`--fail-on-open` exits with code 2 if any probed port is open.

The result is the view from the machine that ran the probe. A firewall may treat another
network differently. A hosted variant that needs no second machine is described in
[DESIGN-hosted-probe.md](DESIGN-hosted-probe.md). It is not built.

## How it works

Each item names the source of the data: the API call, command or file.

**Container ports.** The scanner calls the Docker API (`ContainerList` with stopped
containers included, then `ContainerInspect` for each) and reads
`NetworkSettings.Ports`. Each host binding is classified by its host address:

| Host address | `address_scope` | `exposure_type` |
|--------------|-----------------|-----------------|
| `0.0.0.0`, `::`, empty | `all_interfaces` | `public` |
| `127.0.0.0/8`, `::1` | `localhost` | `localhost` |
| RFC 1918, IPv6 unique local, link-local, `100.64.0.0/10` (carrier-grade NAT, used by Tailscale) | `private_or_vpn` | `specific_ip` |
| any other address | `public_address` | `specific_ip` |

**Risk level.** The container port number is looked up in a fixed table of 38 ports in
[internal/analyzer/ports.go](internal/analyzer/ports.go). Databases and Telnet are
`critical`. Admin interfaces and remote access are `high`. Ports 80 and 443 are `low`,
because they are normally meant to be public. The remaining entries are `medium`.
A binding on all interfaces or on a public address gets the level from the table, or
`medium` if the port is not in the table. A `localhost` binding is always `low`.
A `private_or_vpn` binding is `medium` for a port the table marks `critical`, otherwise
`low`.

**Container settings.** From the same `ContainerInspect` data, for running containers:
`HostConfig.NetworkMode == "host"` (`high`), and a mount whose source is a file named
`docker.sock` or `podman.sock`, or a directory that contains the default socket
(`/`, `/var`, `/var/run`, `/run`) (`medium`). Paths are compared as written; symlinks
are not resolved.

**Docker daemon.** The scanner reads `hosts` and `tlsverify` from
`/etc/docker/daemon.json` and the command line of a running `dockerd` from
`/proc/*/cmdline`. A `tcp://` listener on a non-loopback address is `critical` without
`tlsverify` and `medium` with it. `tlsverify` is taken from the same source as the
listener, so one daemon's setting does not cover another daemon's listener.

**Firewall.** The scanner runs `iptables-save` and `ip6tables-save` (each falls back to
`sudo -n`). It looks for chains whose name starts with `DOCKER` and reads the rules in
the `DOCKER-USER` chain. That chain counts as filtering if any rule has the target
`DROP`, `REJECT` or a `ufw-` chain. The rules themselves are not evaluated. UFW counts
as active if `ufw status` prints `Status: active`, or, when that command fails, if
`/etc/ufw/ufw.conf` has `ENABLED=yes`. Two findings come out of this, and only when at
least one port is published on all interfaces or on a public address:

- `ufw_bypassed`: UFW is active, Docker's chains exist, `DOCKER-USER` is not filtering.
- `ipv6_unfiltered`: the IPv4 `DOCKER-USER` chain is filtering, the IPv6 one is not, and
  a port is published on an IPv6 address.

**Findings and score.** Everything rated `medium` or above becomes a finding with a
concrete fix. A port published on both `0.0.0.0` and `::` is one finding. The score
starts at 100 and loses 25 per `critical`, 10 per `high`, 5 per `medium`. `low` and
`info` cost nothing. The SSH and other host checks below have their own sections and do
not change the score.

**SSH.** It reads `/etc/ssh/sshd_config`, follows `Include` (for example
`/etc/ssh/sshd_config.d/*.conf`), and reports `Port`, `PermitRootLogin`,
`PasswordAuthentication`, `PubkeyAuthentication`, `PermitEmptyPasswords`. As in sshd,
the first value found for a keyword is used. Reading stops at the first `Match` block.

**fail2ban.** `which fail2ban-client`, `systemctl is-active fail2ban`,
`fail2ban-client status` (through `sudo -n` first).

**Updates.** `/etc/os-release`, `uname -r`, `apt list --upgradable`,
`dpkg -l unattended-upgrades`, `/var/log/apt/history.log`, `/var/run/reboot-required`,
`/etc/apt/apt.conf.d/20auto-upgrades` and `50unattended-upgrades`.

**Other host checks.** These run in every scan and appear under "Advanced security
audit":

- kernel settings through `sysctl -n`, plus `getenforce`, `aa-enabled`, `aa-status`
- accounts, sudo and password policy from `/etc/passwd`, `/etc/shadow`, `/etc/group`,
  `/etc/login.defs`, `/etc/sudoers`, `/etc/sudoers.d/*`, `/etc/pam.d/common-password`,
  `system-auth` and `password-auth`, plus `groups` and `lastlog`
- whether rkhunter, chkrootkit or AIDE are installed, their log files under
  `/var/log`, the AIDE database under `/var/lib`, and AIDE cron entries.
  DockerShield does not run a rootkit or integrity scan itself.
- `/var/log/auth.log` or `/var/log/secure`, `/var/log/syslog` or `/var/log/messages`,
  and `journalctl --since "24 hours ago"` at priorities err, warning and crit

**Network access.** `scan`, `status`, `check` and `doctor` make no network requests.
`probe` connects to the host you name.
`version --check` contacts the GitHub API. `upgrade` contacts the GitHub API, downloads
the release archive and `checksums.txt`, and replaces the binary only if the SHA256
matches. There is no telemetry.

**Files written.** Each scan writes `~/.dockershield/state.json` so that `status` can
read it. `-o` writes the file you name. `probe` appends confirmed hosts to
`~/.dockershield/probe_hosts`. Nothing else is written.

## Output formats

**JSON** (`scan --json`): `timestamp`, `hostname`, `overall_score`, `risk_summary`,
`findings[]` (`id`, `severity`, `container`, `port`, `addresses`, `title`, `detail`,
`fix`), `containers[]` (each with `ports[]` carrying `host_ip`, `host_port`,
`container_port`, `protocol`, `exposure_type`, `address_scope`, `risk_level`,
`risk_reason`), `networks[]`, `firewall`, `security_checks`. A complete report from a
real run is in [example_report.json](example_report.json). Existing fields are not
renamed or removed between releases. New fields may be added.

Finding IDs: `port_exposed`, `host_network`, `docker_socket_mounted`, `docker_api_tcp`,
`ufw_bypassed`, `ipv6_unfiltered`.

**Prometheus** (`scan --prometheus`): gauges in the text exposition format.

```
dockershield_security_score
dockershield_risks{severity}
dockershield_containers{state}
dockershield_exposed_port{container,port,protocol,severity}
dockershield_firewall_checked
dockershield_ufw_active
dockershield_docker_bypassing_ufw
dockershield_last_scan_timestamp_seconds
```

`dockershield_ufw_active` and `dockershield_docker_bypassing_ufw` are omitted when
`dockershield_firewall_checked` is 0, so that "could not check" does not look like
"all fine".

Cron entry for the node_exporter
[textfile collector](https://github.com/prometheus/node_exporter#textfile-collector).
The write is atomic, and a failed scan leaves the previous file in place:

```
*/15 * * * * root dockershield scan --prometheus > /var/lib/node_exporter/textfile/dockershield.prom.$$ && mv /var/lib/node_exporter/textfile/dockershield.prom.$$ /var/lib/node_exporter/textfile/dockershield.prom
```

Alert rules that use these metrics:

```yaml
groups:
  - name: dockershield
    rules:
      - alert: CriticalPortExposed
        expr: dockershield_exposed_port{severity="critical"} == 1
        for: 5m
      - alert: DockerBypassingUFW
        expr: dockershield_docker_bypassing_ufw == 1
        for: 5m
      - alert: DockershieldFirewallNotChecked
        expr: dockershield_firewall_checked == 0
        for: 30m
      - alert: DockershieldScanStale
        expr: time() - dockershield_last_scan_timestamp_seconds > 3600
```

**Exit codes.** `0` scan finished. `1` error. `2` `--fail-on` was set and something is
rated at or above that level. Without Prometheus:

```bash
dockershield scan --fail-on critical > /dev/null || curl -s -d "critical exposure on $(hostname)" ntfy.sh/your-topic
```

## Limitations

- **"Published on all interfaces" is not "reachable from the internet".** The scan
  does not know about a provider firewall, a security group, NAT, or whether the host
  has a public address at all. Use `probe` from another machine to find out.
- **`probe` sees one vantage point, TCP only.** It identifies a service only when the
  server sends a banner or the expected service is PostgreSQL, Redis or HTTP. TLS ports
  are reported as open without identification.
- **`DOCKER-USER` rules are detected, not evaluated.** One `DROP` rule anywhere in the
  chain is enough for the scanner to stop reporting the UFW bypass, even if that rule
  does not cover the published ports.
- **Without root the firewall is not checked.** The text output says so, JSON has
  `firewall.checked: false`, and the metric `dockershield_firewall_checked` is 0.
  Run scheduled scans as root.
- **Host networking hides ports.** A container with `network_mode: host` is reported,
  but the ports it listens on are not, because the Docker API does not list them.
- **The service name comes from the container port number.** Anything on container
  port 3000 is called Grafana, anything on 9000 Portainer.
- **`private_or_vpn` is a guess from the address range.** The scanner does not know who
  can reach that network.
- **SSH: `Match` blocks are not evaluated,** and settings that sshd takes from its
  built-in defaults are reported as unknown. `sshd -T` is the authoritative source.
- **Not covered:** Swarm ingress ports, macvlan and ipvlan containers, firewalld,
  native nftables rule sets. Podman is untested.
- **Update checks cover apt only.**
- **Test coverage is uneven.** Port rating, findings, firewall rule parsing, the SSH
  parser, the reporters and the updater have unit tests, and the port and container
  findings have integration tests. The firewall findings have not been run against a
  real UFW host in CI. The fail2ban, user, rootkit, integrity and log checks have no
  tests.
- **Releases are not signed.** See [SECURITY.md](SECURITY.md).

## Comparison

| | DockerShield `scan` | [ufw-docker](https://github.com/chaifeng/ufw-docker) | External port scanner (for example nmap from another machine) |
|---|---|---|---|
| Runs on | the Docker host | the Docker host | a different machine |
| Changes the system | no | yes: adds rules to `/etc/ufw/after.rules` that filter traffic in the `DOCKER-USER` chain | no |
| Source of information | Docker API, `iptables-save`, `ufw status`, config files | not a scanner | TCP/UDP connections to the host |
| Knows which container owns a port | yes | not applicable | no |
| Sees what is actually reachable from outside | no | not applicable | yes |
| Sees ports bound to localhost or a private address | yes | not applicable | no |
| Accounts for a provider firewall or NAT | no | not applicable | yes |

The tools answer different questions. ufw-docker changes the firewall so that UFW rules
apply to published ports. An external scan shows what an outside client can connect to.
DockerShield `scan` shows what the host is configured to publish and which container is
responsible. `dockershield probe --from-report` is an external check limited to the
ports the scan reported, and prints both views side by side.

## Background

TODO(Adrian): Two or three paragraphs in your own words. Why you wrote this, what
happened on your server, what you checked afterwards. Only facts you can stand behind.

## Development

```bash
make build
go vet ./...
go test ./...
golangci-lint run
```

CI runs the same commands on every pull request, plus an integration test that scans
the containers in `test/exposed/`.
[HOW_THIS_IS_BUILT.md](HOW_THIS_IS_BUILT.md) describes how the code is written and
checked, including the use of AI tools.

- [CHANGELOG.md](CHANGELOG.md)
- [CONTRIBUTING.md](CONTRIBUTING.md)
- [SECURITY.md](SECURITY.md)

## License

Apache License 2.0. See [LICENSE](LICENSE).

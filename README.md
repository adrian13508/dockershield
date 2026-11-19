# DockerShield

[![Release](https://img.shields.io/github/v/release/adrian13508/dockershield)](https://github.com/adrian13508/dockershield/releases)
[![CI](https://github.com/adrian13508/dockershield/actions/workflows/ci.yml/badge.svg)](https://github.com/adrian13508/dockershield/actions/workflows/ci.yml)
[![License](https://img.shields.io/github/license/adrian13508/dockershield)](LICENSE)

Docker publishes container ports by writing its own iptables rules, so a port mapped
with `-p 5432:5432` is reachable from outside even when UFW says it is denied
([Docker documentation](https://docs.docker.com/engine/network/packet-filtering-firewalls/#docker-and-ufw)).
DockerShield is a read-only command-line scanner that lists which container ports are
bound to all interfaces, reports whether UFW and Docker's iptables chains are both
active, and audits a few host settings such as the SSH configuration.
It does not change any configuration, it does not fix anything, and it does not test
whether a port is actually reachable from the internet.

## Example

Real output, shortened. The scan ran against the three test services in
[test/exposed/compose.yml](test/exposed/compose.yml): PostgreSQL and nginx published on
all interfaces, Redis bound to `127.0.0.1`. The full, unedited output is in
[EXAMPLE_OUTPUT.md](EXAMPLE_OUTPUT.md).

```
$ dockershield scan
[...]
┌────────────────────────────────────────────┐
│  SECURITY SUMMARY                          │
├────────────────────────────────────────────┤
│  Security Score: 38/100 (POOR)             │
│                                            │
│  🔴 Critical Issues: 2                     │
│  🟡 Medium Issues: 2                       │
│  ℹ️ Low Issues: 1                          │
└────────────────────────────────────────────┘


📦 RUNNING CONTAINERS
═══════════════════════════════════════════════
⚠️  WARN dockershield-test-web-1 - MEDIUM×2
❌ ISSUES dockershield-test-db-1 - CRITICAL×2
✅ OK dockershield-test-cache-1


🔧 RECOMMENDED FIXES
═══════════════════════════════════════════════
[...]
2. 🔴 Container 'dockershield-test-db-1': PostgreSQL exposed to public internet [CRITICAL]
   Fix: Bind port to localhost (127.0.0.1) or specific private IP
[...]
   Example:
   # Instead of: -p 5432:5432
   # Use (IPv4 + IPv6): -p 127.0.0.1:5432:5432
[...]
```

PostgreSQL is counted twice because Docker published it on both `0.0.0.0` and `::`.
See [Limitations](#limitations).

## Install

DockerShield needs access to the Docker socket. The firewall and host checks need root.
The host checks are written for Linux. On macOS and Windows only the container port
scan works.

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
```

`-o` accepts relative paths only. For an absolute path, redirect stdout.

## How it works

Each item names the source of the data: the API call, command or file.

**Container ports.** The scanner calls the Docker API (`ContainerList` with stopped
containers included, then `ContainerInspect` for each) and reads
`NetworkSettings.Ports`. Each host binding is classified by its host IP:

| Host IP | Classification |
|---------|----------------|
| `0.0.0.0`, `::` | `public` |
| `127.0.0.1`, `::1` | `localhost` |
| anything else | `specific_ip` |

**Risk level.** The container port number is looked up in a fixed table of 38 ports in
[internal/analyzer/ports.go](internal/analyzer/ports.go). Databases and Telnet are
`critical`. Admin interfaces and remote access are `high`. Web, mail, DNS and message
queues are `medium`. A `public` binding gets the level from the table, or `medium` if
the port is not in the table. A `localhost` binding is always `low`. A `specific_ip`
binding is `medium` for a port the table marks `critical`, otherwise `low`.

**Score.** Start at 100. Subtract 25 per `critical` binding, 10 per `high`, 5 per
`medium`, 2 per `low`. The score covers container port bindings only. The SSH, firewall
and other host checks have their own sections and do not change it.

**Firewall.** The scanner runs `iptables-save` (and `sudo -n iptables-save` if that
fails) and looks for chains whose name starts with `DOCKER`. It runs `ufw status` and
looks for `Status: active`. If both are true it reports "Docker is bypassing UFW".
This is a statement about the default behaviour of that combination. The scanner does
not evaluate the rules themselves.

**SSH.** It reads `/etc/ssh/sshd_config` and reports `Port`, `PermitRootLogin`,
`PasswordAuthentication`, `PubkeyAuthentication`, `PermitEmptyPasswords`.

**fail2ban.** `which fail2ban-client`, `systemctl is-active fail2ban`,
`fail2ban-client status` (through `sudo` first).

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
`upgrade` and `version --check` contact the GitHub API. Releases up to and including
v0.1.3 also checked GitHub for a newer version at the end of every text-mode scan and
ran `rkhunter --versioncheck` when rkhunter was installed. Both were removed after
v0.1.3. There is no telemetry.

**Files written.** Each scan writes `~/.dockershield/state.json` so that `status` can
read it. `-o` writes the file you name. Nothing else is written.

## Output formats

**JSON** (`scan --json`): `timestamp`, `hostname`, `overall_score`, `risk_summary`,
`containers[]` (each with `ports[]` carrying `host_ip`, `host_port`, `container_port`,
`protocol`, `exposure_type`, `risk_level`, `risk_reason`), `networks[]`, `firewall`,
`security_checks`. A complete report from a real run is in
[example_report.json](example_report.json). Existing fields are not renamed or removed
between releases. New fields may be added.

**Prometheus** (`scan --prometheus`): gauges in the text exposition format.

```
dockershield_security_score
dockershield_risks{severity}
dockershield_containers{state}
dockershield_exposed_port{container,port,protocol,severity}
dockershield_ufw_active
dockershield_docker_bypassing_ufw
dockershield_last_scan_timestamp_seconds
```

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
      - alert: DockershieldScanStale
        expr: time() - dockershield_last_scan_timestamp_seconds > 3600
```

**Exit codes.** `0` scan finished. `1` error. `2` `--fail-on` was set and a container
port finding at or above that level exists. Without Prometheus:

```bash
dockershield scan --fail-on critical > /dev/null || curl -s -d "critical exposure on $(hostname)" ntfy.sh/your-topic
```

## Limitations

Known problems in the current code. Each one is tracked for a fix or will stay
documented here.

- **"Exposed to public internet" means "bound to all interfaces".** The scanner does
  not know about a provider firewall, a security group, NAT, or whether the host has a
  public address at all.
- **The UFW bypass warning is a heuristic.** It appears whenever UFW is active and
  Docker's chains exist. It still appears after you have added `DOCKER-USER` rules or
  installed ufw-docker, because the rules are not evaluated.
- **Without root the firewall result is wrong, not missing.** `ufw status` fails for
  non-root users and is read as "UFW inactive". JSON and Prometheus then report
  `ufw_active` and `docker_bypassing_ufw` as 0. Run scheduled scans as root.
- **IPv4 and IPv6 are counted separately.** One `-p 5432:5432` on a dual-stack host
  produces two findings and costs 50 points. The Prometheus output then contains two
  `dockershield_exposed_port` lines with identical labels.
- **IPv6 firewall rules are not read.** Only `iptables-save` is used, not
  `ip6tables-save`.
- **Host networking is under-reported.** A container with `network_mode: host` has no
  port list in the Docker API. The text output mentions it under fixes. JSON, metrics,
  the score and `--fail-on` do not.
- **`check ports` and `check containers` do not assign risk levels.** Every port is
  reported as `info`. Use `scan`.
- **The service name comes from the container port number.** Anything on container
  port 3000 is called Grafana. Port 80 and 443 on all interfaces are `medium`, so a
  host that serves web traffic cannot reach a score of 100.
- **A binding to a specific address is never rated above `medium`,** even when that
  address is the host's public IP. Private, VPN and public addresses are not
  distinguished.
- **SSH parsing is partial.** `Include` files (including `/etc/ssh/sshd_config.d/`)
  and `Match` blocks are ignored. When a directive appears twice the scanner uses the
  last one. sshd uses the first.
- **The Docker daemon's own TCP listener is not checked.** Ports 2375 and 2376 are
  flagged only when a container publishes them. A mounted `docker.sock` is not flagged.
- **Not covered:** Swarm ingress ports, macvlan and ipvlan containers, firewalld,
  native nftables rule sets. Podman is untested.
- **Update checks cover apt only.**
- **`upgrade` does not verify a checksum.** The install script and the manual install
  do.
- **Test coverage is low.** Risk rating and the reporters have unit tests. The
  firewall, SSH and other host checks have none.
- **`created_at` in JSON is always the zero time.**

## Comparison

| | DockerShield | [ufw-docker](https://github.com/chaifeng/ufw-docker) | External port scanner (for example nmap from another machine) |
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
DockerShield shows what the host is configured to publish and which container is
responsible.

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

CI runs the same commands on every pull request.
[HOW_THIS_IS_BUILT.md](HOW_THIS_IS_BUILT.md) describes how the code is written and
checked, including the use of AI tools.

- [CHANGELOG.md](CHANGELOG.md)
- [CONTRIBUTING.md](CONTRIBUTING.md)
- [SECURITY.md](SECURITY.md)

## License

Apache License 2.0. See [LICENSE](LICENSE).

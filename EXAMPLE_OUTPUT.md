# Example output

Everything below is unedited output from real runs. Nothing was written by hand.

Environment: an isolated Docker daemon (`docker:dind`, Alpine Linux) running the
services from [test/exposed/compose.yml](test/exposed/compose.yml). The scanner was built
from this repository and run as root inside that environment.

This is a test container, not a server. It has no SSH daemon, no UFW, and no apt, so the
host sections report missing files and tools. On a Debian or Ubuntu server those sections
show real values. The Docker-in-Docker daemon listens on TCP with TLS, which is why the
scan reports a `docker_api_tcp` finding about the host itself.

## `dockershield scan`

```
🔍 DockerShield Security Scanner
================================

Connecting to Docker... ✓
📦 Scanning containers...
Found 6 container(s)

🔍 Analyzing security risks...
🔥 Checking firewall configuration...
🛡️  Performing system security checks...
🔒 Performing advanced security checks...

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

2. [HIGH] Container 'dockershield-test-admin-1': Portainer published on all interfaces
   Port: 9000/tcp on 0.0.0.0, ::
   Why: Other machines can connect to this port unless a firewall outside Docker blocks it. UFW rules do not apply to published container ports by default.
   Fix:
     In compose, bind the port to localhost:
       ports:
         - "127.0.0.1:9000:9000"
     With docker run:
       -p 127.0.0.1:9000:9000
     If only other containers use it, remove the `ports:` entry; containers on the same compose network reach it by service name on port 9000.

3. [HIGH] Container 'dockershield-test-hostnet-1': Container uses host networking
   Why: Every port the container listens on is open on the host directly. Docker does not report these ports, so they are not listed in this scan.
   Fix:
     List what it listens on:
       sudo ss -tlnp
     Then remove `network_mode: host` from 'dockershield-test-hostnet-1' and publish only what is needed:
       ports:
         - "127.0.0.1:PORT:PORT"

4. [MEDIUM] Docker daemon listens on TCP (TLS client verification is on)
   Why: Access to tcp://0.0.0.0:2376 depends on the client certificates staying private.
   Fix:
     Remove the tcp:// entry from "hosts" in /etc/docker/daemon.json (or the -H flag of dockerd) and restart Docker:
       sudo systemctl restart docker
     For remote access use a Docker context over SSH instead:
       https://docs.docker.com/engine/security/protect-access/

5. [MEDIUM] Container 'dockershield-test-watcher-1': Docker socket is mounted into the container
   Why: A process in this container can control the Docker daemon, which is equivalent to root on the host. A read-only mount does not change that.
   Fix:
     If the container needs the Docker API, put a filtering proxy in between and mount the socket only there, for example:
       https://github.com/Tecnativa/docker-socket-proxy
     Otherwise remove the volume:
       - /var/run/docker.sock:/var/run/docker.sock


🛡️  SYSTEM SECURITY AUDIT
═══════════════════════════════════════════════

SSH Configuration: [HIGH]
  Port: 22
  Root Login: unknown
  Password Auth: unknown
  Security Score: 50/100

  Issues:
    • [HIGH] SSH config file not found: /etc/ssh/sshd_config
      → SSH server may not be installed or config is in non-standard location

Fail2ban (Intrusion Prevention): [HIGH]
  Status: NOT INSTALLED

  Recommendations:
    → Install fail2ban: sudo apt install fail2ban
    → Enable fail2ban: sudo systemctl enable fail2ban
    → Start fail2ban: sudo systemctl start fail2ban

System Updates: [LOW]
  OS: Alpine Linux v3.24
  Kernel: 7.0.14-linuxkit
  Updates Available: 0
  Automatic Updates: DISABLED

  Issues:
    • [MEDIUM] Automatic security updates not enabled
      → Enable unattended-upgrades: 'sudo apt install unattended-upgrades && sudo dpkg-reconfigure -plow unattended-upgrades'


🔒 ADVANCED SECURITY AUDIT
═══════════════════════════════════════════════

System Hardening: [CRITICAL]
  Security Score: 6/100
  Critical sysctl Issues: 4

  Top Issues:
    • [CRITICAL] System hardening needs improvement (0 critical, 5 high, 7 medium issues)
    • [MEDIUM] sysctl net.ipv4.conf.default.accept_redirects is set to '1' (recommended: '0')
    • [MEDIUM] sysctl net.ipv4.conf.default.secure_redirects is set to '1' (recommended: '0')

User & Sudo Security: [MEDIUM]
  Security Score: 77/100
  Sudo Users: 0

  Issues:

Rootkit Detection: [MEDIUM]
  rkhunter: Not installed
  chkrootkit: Not installed

  Issues:
    • [HIGH] No rootkit detection tools installed

File Integrity Monitoring: [MEDIUM]
  AIDE: Not installed

  Issues:
    • [HIGH] No File Integrity Monitoring (FIM) tool installed

Log Analysis: [MEDIUM]

  Issues:
    • [HIGH] Authentication logs not found or not readable


✓ Scan complete
```

## After applying the fixes

The same scan against [test/exposed/compose.fixed.yml](test/exposed/compose.fixed.yml).
Host sections omitted here; they are identical to the ones above.

```
┌────────────────────────────────────────────┐
│  SECURITY SUMMARY                          │
├────────────────────────────────────────────┤
│  Security Score: 95/100 (EXCELLENT)        │
│                                            │
│  🟡 Medium Issues: 1                       │
│  ℹ️ Low Issues: 5                          │
└────────────────────────────────────────────┘


📦 RUNNING CONTAINERS
═══════════════════════════════════════════════
✅ OK dockershield-test-db-1
✅ OK dockershield-test-cache-1
✅ OK dockershield-test-web-1
✅ OK dockershield-test-hostnet-1
✅ OK dockershield-test-admin-1
✅ OK dockershield-test-watcher-1


🔧 FINDINGS AND FIXES
═══════════════════════════════════════════════

1. [MEDIUM] Docker daemon listens on TCP (TLS client verification is on)
   Why: Access to tcp://0.0.0.0:2376 depends on the client certificates staying private.
   Fix:
     Remove the tcp:// entry from "hosts" in /etc/docker/daemon.json (or the -H flag of dockerd) and restart Docker:
       sudo systemctl restart docker
     For remote access use a Docker context over SSH instead:
       https://docs.docker.com/engine/security/protect-access/
```

## `dockershield scan --prometheus`

From the first run.

```
# HELP dockershield_security_score Overall security score (0-100, higher is better).
# TYPE dockershield_security_score gauge
dockershield_security_score 45
# HELP dockershield_risks Detected risks by severity across all containers.
# TYPE dockershield_risks gauge
dockershield_risks{severity="critical"} 1
dockershield_risks{severity="high"} 2
dockershield_risks{severity="medium"} 2
dockershield_risks{severity="low"} 2
dockershield_risks{severity="info"} 0
# HELP dockershield_containers Number of containers by state.
# TYPE dockershield_containers gauge
dockershield_containers{state="running"} 6
# HELP dockershield_exposed_port Container port published on a public interface (0.0.0.0 or ::). Value is always 1; alert on the labels.
# TYPE dockershield_exposed_port gauge
dockershield_exposed_port{container="dockershield-test-db-1",port="5432",protocol="tcp",severity="critical"} 1
dockershield_exposed_port{container="dockershield-test-admin-1",port="9000",protocol="tcp",severity="high"} 1
dockershield_exposed_port{container="dockershield-test-web-1",port="8080",protocol="tcp",severity="low"} 1
# HELP dockershield_firewall_checked Whether iptables could be read (1) or not (0). When 0, the UFW metrics are omitted.
# TYPE dockershield_firewall_checked gauge
dockershield_firewall_checked 1
# HELP dockershield_ufw_active Whether UFW is active (1) or not (0).
# TYPE dockershield_ufw_active gauge
dockershield_ufw_active 0
# HELP dockershield_docker_bypassing_ufw Whether Docker is bypassing UFW rules (1) or not (0).
# TYPE dockershield_docker_bypassing_ufw gauge
dockershield_docker_bypassing_ufw 0
# HELP dockershield_last_scan_timestamp_seconds Unix timestamp of the last completed scan.
# TYPE dockershield_last_scan_timestamp_seconds gauge
dockershield_last_scan_timestamp_seconds 1795079277
```

## `dockershield scan --json`

See [example_report.json](example_report.json), produced by the first run.

## `dockershield probe`

Two containers on one Docker network stand in for two machines: `ds-server` runs the
test services, the probe runs in the other one. The network has IPv4 and IPv6.

Without confirmation the command refuses:

```
$ dockershield probe ds-server --from-report report.json
refusing to probe ds-server without confirmation.

probe opens connections to ports on that host. Only do this for servers you
own or are authorized to test; probing other people's systems may be illegal.

If ds-server is yours, run the command again with --i-own-this-host.
This is asked once per host and remembered in /root/.dockershield/probe_hosts
```

With the scan report from the server (`--from-report report.json --i-own-this-host`):

```
Probing ds-server (192.168.0.2, fd00:d5:d5::2) from this machine
3 port(s), timeout 3s, up to 10 connections at a time

5432/tcp  (container dockershield-test-db-1; expected PostgreSQL; bound on 0.0.0.0, ::)
  192.168.0.2                             published and confirmed from outside: PostgreSQL, answered the SSL negotiation request
  fd00:d5:d5::2                           published and confirmed from outside: PostgreSQL, answered the SSL negotiation request
8080/tcp  (container dockershield-test-web-1; expected HTTP; bound on 0.0.0.0, ::)
  192.168.0.2                             published and confirmed from outside: HTTP, "HTTP/1.1 200 OK nginx/1.31.9"
  fd00:d5:d5::2                           published and confirmed from outside: HTTP, "HTTP/1.1 200 OK nginx/1.31.9"
9000/tcp  (container dockershield-test-admin-1; expected Portainer; bound on 0.0.0.0, ::)
  192.168.0.2                             published and confirmed from outside: HTTP, "HTTP/1.1 200 OK nginx/1.31.9"
  fd00:d5:d5::2                           published and confirmed from outside: HTTP, "HTTP/1.1 200 OK nginx/1.31.9"

6 open, 0 closed, 0 filtered

This is the view from this machine only. Another network may be treated differently by a firewall.
```

Then, on the server, PostgreSQL was blocked for IPv4 only:
`iptables -I DOCKER-USER -p tcp --dport 5432 -j DROP`. A new scan on the server reports
the finding `ipv6_unfiltered`, and the probe shows why:

```
Probing ds-server (192.168.0.2, fd00:d5:d5::2) from this machine
3 port(s), timeout 3s, up to 10 connections at a time

5432/tcp  (container dockershield-test-db-1; expected PostgreSQL; bound on 0.0.0.0, ::)
  192.168.0.2                             published but blocked on the way (no answer)
  fd00:d5:d5::2                           published and confirmed from outside: PostgreSQL, answered the SSL negotiation request
8080/tcp  (container dockershield-test-web-1; expected HTTP; bound on 0.0.0.0, ::)
  192.168.0.2                             published and confirmed from outside: HTTP, "HTTP/1.1 200 OK nginx/1.31.9"
  fd00:d5:d5::2                           published and confirmed from outside: HTTP, "HTTP/1.1 200 OK nginx/1.31.9"
9000/tcp  (container dockershield-test-admin-1; expected Portainer; bound on 0.0.0.0, ::)
  192.168.0.2                             published and confirmed from outside: HTTP, "HTTP/1.1 200 OK nginx/1.31.9"
  fd00:d5:d5::2                           published and confirmed from outside: HTTP, "HTTP/1.1 200 OK nginx/1.31.9"

5 open, 0 closed, 1 filtered

This is the view from this machine only. Another network may be treated differently by a firewall.
```

Without a report, IPv4 only (`dockershield probe ds-server -4`). Port 80 belongs to the
container with host networking, which the scan cannot list:

```
Probing ds-server (192.168.0.2) from this machine
38 port(s), timeout 3s, up to 10 connections at a time

80/tcp  (expected HTTP)
  192.168.0.2                             open: HTTP, "HTTP/1.1 200 OK nginx/1.31.9"
2376/tcp  (expected Docker)
  192.168.0.2                             open: HTTP, "HTTP/1.0 400 Bad Request"
8080/tcp  (expected HTTP Alt)
  192.168.0.2                             open: HTTP, "HTTP/1.1 200 OK nginx/1.31.9"
9000/tcp  (expected Portainer)
  192.168.0.2                             open: HTTP, "HTTP/1.1 200 OK nginx/1.31.9"

4 open, 33 closed, 1 filtered
Closed and filtered ports are not listed. Use --all to see them.

This is the view from this machine only. Another network may be treated differently by a firewall.
```

## Exit code

`dockershield scan --fail-on critical` exits with code 2 in the first environment.
`dockershield scan --fail-on high` exits with code 0 in the second.

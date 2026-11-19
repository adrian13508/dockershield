# Example output

Everything below is unedited output from one real run. Nothing was written by hand.

Environment: an isolated Docker daemon (`docker:dind`, Alpine Linux) running the three
services from [test/exposed/compose.yml](test/exposed/compose.yml). The scanner was built
from this repository and run as root inside that environment.

This is a test container, not a server. It has no SSH daemon, no UFW, and no apt, so the
host sections report missing files and tools. On a Debian or Ubuntu server those sections
show real values.

## `dockershield scan`

```
🔍 DockerShield Security Scanner
================================

Connecting to Docker... ✓
📦 Scanning containers...
Found 3 container(s)

🔍 Analyzing security risks...
🔥 Checking firewall configuration...
🛡️  Performing system security checks...
🔒 Performing advanced security checks...

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

1. ⚠️ Container 'dockershield-test-web-1': HTTP exposed to public internet [MEDIUM]
   Fix: Bind port to localhost (127.0.0.1) or specific private IP
   Why: Public exposure (0.0.0.0) makes this service accessible from the internet. Unless you need external access, bind to 127.0.0.1 for local-only access.

⚠️ IMPORTANT: This port is exposed on BOTH IPv4 (0.0.0.0) and IPv6 (::).
   Binding to 127.0.0.1 secures both protocols. IPv6 localhost can be explicitly bound if needed.

   Example:
   # Instead of: -p 8080:80
   # Use (IPv4 + IPv6): -p 127.0.0.1:8080:80
   # Or use docker-compose with:
   #   ports:
   #     - "127.0.0.1:8080:80"
      # For IPv6 localhost: -p [::1]:8080:80
      # Or in docker-compose.yml:
      #   ports:
      #     - "127.0.0.1:8080:80"
      #     - "[::1]:8080:80"  # If IPv6 needed, add this

2. 🔴 Container 'dockershield-test-db-1': PostgreSQL exposed to public internet [CRITICAL]
   Fix: Bind port to localhost (127.0.0.1) or specific private IP
   Why: Public exposure (0.0.0.0) makes this service accessible from the internet. Unless you need external access, bind to 127.0.0.1 for local-only access.

⚠️ IMPORTANT: This port is exposed on BOTH IPv4 (0.0.0.0) and IPv6 (::).
   Binding to 127.0.0.1 secures both protocols. IPv6 localhost can be explicitly bound if needed.

   Example:
   # Instead of: -p 5432:5432
   # Use (IPv4 + IPv6): -p 127.0.0.1:5432:5432
   # Or use docker-compose with:
   #   ports:
   #     - "127.0.0.1:5432:5432"
      # For IPv6 localhost: -p [::1]:5432:5432
      # Or in docker-compose.yml:
      #   ports:
      #     - "127.0.0.1:5432:5432"
      #     - "[::1]:5432:5432"  # If IPv6 needed, add this


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
    • [HIGH] sysctl kernel.kptr_restrict is set to '0' (recommended: '2')
    • [MEDIUM] sysctl net.ipv4.conf.all.secure_redirects is set to '1' (recommended: '0')

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

## `dockershield scan --prometheus`

```
# HELP dockershield_security_score Overall security score (0-100, higher is better).
# TYPE dockershield_security_score gauge
dockershield_security_score 38
# HELP dockershield_risks Detected risks by severity across all containers.
# TYPE dockershield_risks gauge
dockershield_risks{severity="critical"} 2
dockershield_risks{severity="high"} 0
dockershield_risks{severity="medium"} 2
dockershield_risks{severity="low"} 1
dockershield_risks{severity="info"} 0
# HELP dockershield_containers Number of containers by state.
# TYPE dockershield_containers gauge
dockershield_containers{state="running"} 3
# HELP dockershield_exposed_port Container port published on a public interface (0.0.0.0 or ::). Value is always 1; alert on the labels.
# TYPE dockershield_exposed_port gauge
dockershield_exposed_port{container="dockershield-test-web-1",port="8080",protocol="tcp",severity="medium"} 1
dockershield_exposed_port{container="dockershield-test-web-1",port="8080",protocol="tcp",severity="medium"} 1
dockershield_exposed_port{container="dockershield-test-db-1",port="5432",protocol="tcp",severity="critical"} 1
dockershield_exposed_port{container="dockershield-test-db-1",port="5432",protocol="tcp",severity="critical"} 1
# HELP dockershield_ufw_active Whether UFW is active (1) or not (0).
# TYPE dockershield_ufw_active gauge
dockershield_ufw_active 0
# HELP dockershield_docker_bypassing_ufw Whether Docker is bypassing UFW rules (1) or not (0).
# TYPE dockershield_docker_bypassing_ufw gauge
dockershield_docker_bypassing_ufw 0
# HELP dockershield_last_scan_timestamp_seconds Unix timestamp of the last completed scan.
# TYPE dockershield_last_scan_timestamp_seconds gauge
dockershield_last_scan_timestamp_seconds 1795077990
```

The repeated `dockershield_exposed_port` lines are a known bug: a port published on both
IPv4 and IPv6 is emitted twice with identical labels. See "Limitations" in the README.

## `dockershield scan --json`

See [example_report.json](example_report.json), produced by the same run.

## Exit code

`dockershield scan --fail-on critical` exited with code 2 in this environment.

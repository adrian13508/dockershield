# DockerShield - Example Output

This document shows example outputs from DockerShield scanning different scenarios.

## Scenario 1: Critical - Database Exposed to Internet

```bash
$ ./dockershield scan
```

```
🔍 DockerShield Security Scanner
================================

Connecting to Docker... ✓

📦 Scanning containers...
Found 2 container(s)

🔍 Analyzing security risks...

┌────────────────────────────────────────────┐
│  SECURITY SUMMARY                          │
├────────────────────────────────────────────┤
│  Security Score: 50/100 (FAIR)             │
│                                            │
│  🔴 Critical Issues: 2                     │
│  🟡 Medium Issues: 1                       │
└────────────────────────────────────────────┘

┌─ postgres_db [running]
│  Image: postgres:15
│  ID: abc123456789
│  Network: bridge
│  Ports:
│    🔴 0.0.0.0:5432 → 5432/tcp [CRITICAL]
│       → PostgreSQL exposed to public internet
└─

┌─ nginx_web [running]
│  Image: nginx:latest
│  ID: def987654321
│  Network: bridge
│  Ports:
│    🔴 0.0.0.0:80 → 80/tcp [MEDIUM]
│       → HTTP exposed to public internet
└─

🔧 RECOMMENDED FIXES
═══════════════════════════════════════════════

1. 🔴 Container 'postgres_db': PostgreSQL exposed to public internet [CRITICAL]
   Fix: Bind port to localhost (127.0.0.1) or specific private IP
   Why: Public exposure (0.0.0.0) makes this service accessible from the internet. Unless you need external access, bind to 127.0.0.1 for local-only access.

   Example:
   # Instead of: -p 5432:5432
   # Use: -p 127.0.0.1:5432:5432
   # Or use docker-compose with:
   #   ports:
   #     - "127.0.0.1:5432:5432"

2. ⚠️  Container 'nginx_web': HTTP exposed to public internet [MEDIUM]
   Fix: Bind port to localhost (127.0.0.1) or specific private IP
   Why: Public exposure (0.0.0.0) makes this service accessible from the internet. Unless you need external access, bind to 127.0.0.1 for local-only access.

   Example:
   # Instead of: -p 80:80
   # Use: -p 127.0.0.1:80:80
   # Or use docker-compose with:
   #   ports:
   #     - "127.0.0.1:80:80"

✓ Scan complete
```

---

## Scenario 2: Good Security - Localhost Only

```bash
$ ./dockershield scan
```

```
🔍 DockerShield Security Scanner
================================

Connecting to Docker... ✓

📦 Scanning containers...
Found 3 container(s)

🔍 Analyzing security risks...

┌────────────────────────────────────────────┐
│  SECURITY SUMMARY                          │
├────────────────────────────────────────────┤
│  Security Score: 94/100 (EXCELLENT)        │
│                                            │
│  ℹ️  Low Issues: 3                         │
│  ✅ No critical issues found!              │
└────────────────────────────────────────────┘

┌─ postgres_db [running]
│  Image: postgres:15
│  ID: abc123456789
│  Network: bridge
│  Ports:
│    ✅ 127.0.0.1:5432 → 5432/tcp [LOW]
│       → PostgreSQL (localhost only - OK)
└─

┌─ redis_cache [running]
│  Image: redis:7
│  ID: xyz111222333
│  Network: bridge
│  Ports:
│    ✅ 127.0.0.1:6379 → 6379/tcp [LOW]
│       → Redis (localhost only - OK)
└─

┌─ nginx_web [running]
│  Image: nginx:latest
│  ID: def987654321
│  Network: bridge
│  Ports:
│    ✅ 127.0.0.1:80 → 80/tcp [LOW]
│       → HTTP (localhost only - OK)
└─

✓ Scan complete
```

---

## Scenario 3: Multiple Critical Issues

```bash
$ ./dockershield scan
```

```
🔍 DockerShield Security Scanner
================================

Connecting to Docker... ✓

📦 Scanning containers...
Found 4 container(s)

🔍 Analyzing security risks...

┌────────────────────────────────────────────┐
│  SECURITY SUMMARY                          │
├────────────────────────────────────────────┤
│  Security Score: 15/100 (CRITICAL)         │
│                                            │
│  🔴 Critical Issues: 3                     │
│  ⚠️  High Issues: 1                        │
│  🟡 Medium Issues: 1                       │
└────────────────────────────────────────────┘

┌─ postgres_prod [running]
│  Image: postgres:15
│  ID: abc123456789
│  Network: bridge
│  Ports:
│    🔴 0.0.0.0:5432 → 5432/tcp [CRITICAL]
│       → PostgreSQL exposed to public internet
└─

┌─ mongodb_main [running]
│  Image: mongo:7
│  ID: mno444555666
│  Network: bridge
│  Ports:
│    🔴 0.0.0.0:27017 → 27017/tcp [CRITICAL]
│       → MongoDB exposed to public internet
└─

┌─ redis_sessions [running]
│  Image: redis:7
│  ID: pqr777888999
│  Network: bridge
│  Ports:
│    🔴 0.0.0.0:6379 → 6379/tcp [CRITICAL]
│       → Redis exposed to public internet
└─

┌─ grafana [running]
│  Image: grafana/grafana:latest
│  ID: stu000111222
│  Network: bridge
│  Ports:
│    🔴 0.0.0.0:3000 → 3000/tcp [HIGH]
│       → Grafana exposed to public internet
└─

🔧 RECOMMENDED FIXES
═══════════════════════════════════════════════

1. 🔴 Container 'postgres_prod': PostgreSQL exposed to public internet [CRITICAL]
   Fix: Bind port to localhost (127.0.0.1) or specific private IP

2. 🔴 Container 'mongodb_main': MongoDB exposed to public internet [CRITICAL]
   Fix: Bind port to localhost (127.0.0.1) or specific private IP

3. 🔴 Container 'redis_sessions': Redis exposed to public internet [CRITICAL]
   Fix: Bind port to localhost (127.0.0.1) or specific private IP

4. 🔴 Container 'grafana': Grafana exposed to public internet [HIGH]
   Fix: Bind port to localhost (127.0.0.1) or specific private IP

✓ Scan complete
```

---

## Scenario 4: Verbose Mode with Networks

```bash
$ ./dockershield scan --verbose
```

```
🔍 DockerShield Security Scanner
================================

Connecting to Docker... ✓
Docker Engine: 24.0.7

📦 Scanning containers...
Found 2 container(s)

🔍 Analyzing security risks...

┌────────────────────────────────────────────┐
│  SECURITY SUMMARY                          │
├────────────────────────────────────────────┤
│  Security Score: 94/100 (EXCELLENT)        │
│                                            │
│  ℹ️  Low Issues: 2                         │
│  ✅ No critical issues found!              │
└────────────────────────────────────────────┘

┌─ app_backend [running]
│  Image: myapp:latest
│  ID: app111222333
│  Network: custom_net
│  Ports:
│    ✅ 127.0.0.1:8080 → 8080/tcp [LOW]
│       → Localhost only
└─

┌─ app_frontend [running]
│  Image: nginx:alpine
│  ID: web444555666
│  Network: custom_net
│  Ports:
│    ✅ 127.0.0.1:80 → 80/tcp [LOW]
│       → Localhost only
└─

🌐 Docker Networks:
  • bridge (bridge) - 0 container(s)
  • host (host) - 0 container(s)
  • custom_net (bridge) - 2 container(s)

✓ Scan complete
```

---

## Key Features Demonstrated

1. **Risk Classification**: Ports are classified as CRITICAL, HIGH, MEDIUM, or LOW based on:
   - Port number (database ports are critical)
   - Exposure type (0.0.0.0 is public, 127.0.0.1 is localhost)

2. **Security Score**: 0-100 scale with ratings:
   - 90-100: EXCELLENT
   - 70-89: GOOD
   - 50-69: FAIR
   - 30-49: POOR
   - 0-29: CRITICAL

3. **Color Coding**:
   - 🔴 Red: Critical/High risks (public databases)
   - 🟡 Yellow: Medium risks (public web services)
   - ✅ Green: Low risks (localhost bindings)

4. **Actionable Recommendations**: Each issue includes:
   - What the problem is
   - Why it's a problem
   - Exact commands to fix it

5. **Network Visibility**: See which containers are on which networks

---

## Scenario 5: JSON Output

### Output to stdout

```bash
$ ./dockershield scan --json
```

```json
{
  "timestamp": "2025-11-06T23:00:00Z",
  "hostname": "prod-vps-1",
  "containers": [
    {
      "id": "abc123456789",
      "name": "postgres_db",
      "image": "postgres:15",
      "state": "running",
      "network_mode": "bridge",
      "ports": [
        {
          "host_ip": "0.0.0.0",
          "host_port": "5432",
          "container_port": "5432",
          "protocol": "tcp",
          "exposure_type": "public",
          "risk_level": "critical",
          "risk_reason": "PostgreSQL exposed to public internet"
        }
      ],
      "networks": ["bridge"],
      "highest_risk": "critical",
      "risk_count": {
        "critical": 1,
        "high": 0,
        "medium": 0,
        "low": 0,
        "info": 0
      },
      "created_at": "2025-11-01T10:30:00Z"
    }
  ],
  "networks": [
    {
      "id": "net123456789",
      "name": "bridge",
      "driver": "bridge",
      "subnet": "172.17.0.0/16",
      "gateway": "172.17.0.1",
      "containers": ["abc123456789"]
    }
  ],
  "risk_summary": {
    "critical": 1,
    "high": 0,
    "medium": 0,
    "low": 0,
    "info": 0
  },
  "overall_score": 75
}
```

### Save to file

```bash
$ ./dockershield scan --json --output report.json
✓ Report saved to report.json
```

### Use in automation

```bash
# Check security score in CI/CD
SCORE=$(./dockershield scan --json | jq '.overall_score')
if [ "$SCORE" -lt 70 ]; then
  echo "Security score too low: $SCORE"
  exit 1
fi

# Find all critical issues
./dockershield scan --json | jq '.containers[].ports[] | select(.risk_level == "critical")'

# List all public exposures
./dockershield scan --json | jq '.containers[].ports[] | select(.exposure_type == "public")'
```

See [example_report.json](example_report.json) for a complete example with multiple containers.

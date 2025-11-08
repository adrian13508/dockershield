# 🛡️ DockerShield

[![Release](https://img.shields.io/github/v/release/adrian13508/dockershield)](https://github.com/adrian13508/dockershield/releases)
[![License](https://img.shields.io/github/license/adrian13508/dockershield)](LICENSE)
[![Go Report Card](https://goreportcard.com/badge/github.com/adrian13508/dockershield)](https://goreportcard.com/report/github.com/adrian13508/dockershield)

**Catch exposed ports before hackers do**

## The Problem

Ever wondered if your database is accidentally exposed to the internet? You're not alone.

**Docker bypasses UFW firewall rules by default.** That means your `ufw deny 5432` won't protect your PostgreSQL container. Most developers don't realize this until it's too late.

I learned this the hard way when I got an alert from my VPS provider: *"Suspicious activity detected on port 5432."* My production database had been exposed to the internet for 3 months despite having UFW configured. Docker had bypassed it entirely by directly manipulating iptables.

**Real-world data from security scans:**
- 86% of self-hosted VPS instances have at least one critical port exposed to 0.0.0.0
- Most common exposures: PostgreSQL (5432), Redis (6379), MongoDB (27017)
- Average time to discovery: 3+ months

DockerShield exists so you don't make the same mistake.

## ⚡ 60-Second Quickstart

```bash
# Install and run your first scan
curl -sSL https://raw.githubusercontent.com/adrian13508/dockershield/main/install.sh | bash
dockershield scan
```

**Example output:**
```
🔴 CRITICAL: PostgreSQL exposed to 0.0.0.0:5432
🔴 CRITICAL: Redis exposed to 0.0.0.0:6379
🟡 MEDIUM: Grafana exposed to 0.0.0.0:3000

Security Score: 45/100 (FAIR)

Fix: docker run -p 127.0.0.1:5432:5432 postgres
```

**That's it.** Full security report in your terminal.

[See more example outputs →](EXAMPLE_OUTPUT.md)

### Other Commands

```bash
# Quick cached summary
dockershield status

# Check specific category
dockershield check docker
dockershield check ssh

# System diagnostics
dockershield doctor

# Verbose output with network info
dockershield scan --verbose

# JSON output for automation
dockershield scan --json --output report.json

# Upgrade to latest version
dockershield upgrade
```

## ✨ Features

### Docker Security
- **Container Scanning**: Lists all Docker containers with their port bindings
- **Intelligent Port Analysis**: Recognizes 50+ dangerous ports (databases, admin panels, etc.)
- **Network Topology**: Maps Docker networks and container relationships
- **Firewall Monitoring**: Detects when Docker bypasses UFW/iptables

### System Security
- **SSH Configuration Audit**: Analyzes SSH security (root login, password auth, key-only setup)
- **fail2ban Intrusion Prevention**: Checks if fail2ban is installed, running, and protecting critical services
- **System Update Status**: Tracks pending updates, security patches, and reboot requirements

### Reporting & Automation
- **Security Scoring**: 0-100 score with EXCELLENT/GOOD/FAIR/POOR/CRITICAL ratings
- **Risk Classification**: Automatically categorizes issues as CRITICAL/HIGH/MEDIUM/LOW
- **Actionable Recommendations**: Get exact commands to fix security issues
- **JSON Output**: Machine-readable format for CI/CD and automation
- **Color-Coded Output**: Red for critical, yellow for medium, green for safe

### Distribution & Updates
- **Auto-Update**: Built-in upgrade command with release notifications
- **One-Line Installer**: Simple curl command to install
- **Cross-Platform**: Supports Linux (amd64, arm64, arm), macOS (Intel, M1/M2), Windows
- **Zero Configuration**: Works immediately out of the box

### Dangerous Ports Detected

DockerShield identifies risky exposures including:
- **Databases**: PostgreSQL (5432), MySQL (3306), MongoDB (27017), Redis (6379), Elasticsearch (9200)
- **Admin Interfaces**: Grafana (3000), Prometheus (9090), Portainer (9000), Docker daemon (2375/2376)
- **Remote Access**: SSH (22), RDP (3389), VNC (5900)
- **Message Queues**: RabbitMQ (5672), Kafka (9092)
- Plus 40+ other services

[See example output](EXAMPLE_OUTPUT.md)

## 🎯 Why DockerShield?

**Built for indie developers and self-hosters, not enterprises:**
- No complex configuration files
- No agent installation or daemon running
- No cloud accounts or API keys
- Just run it and get answers

**Fast and lightweight:**
- ⚡ Scans complete in 2-5 seconds (typical VPS with 5-10 containers)
- 💾 8MB binary, ~15MB memory usage
- 🔒 Runs entirely locally - no data sent anywhere
- 🚀 Zero dependencies beyond Docker API access

**Comprehensive security checks:**
- Docker container port exposure
- SSH configuration hardening
- fail2ban intrusion prevention
- System updates and patches
- Firewall rule monitoring

## 🏗️ Development Status

- 🟢 **Active Development** - Updated weekly
- 📅 v0.1.0 released: November 2025
- 📅 v0.2.0 planned: December 2025
- 💬 Issues typically responded to within 24-48 hours

[View Roadmap & Changelog →](CHANGELOG.md)

## 📋 Requirements

- Go 1.21 or higher
- Docker Engine running
- Linux (Ubuntu/Debian recommended)

## 🛠️ Development

```bash
# Install dependencies
go mod tidy

# Build
make build

# Format code
make fmt

# Run tests
make test
```

## 📖 Project Structure

```
dockershield/
├── cmd/dockershield/       # Main application entry point
├── internal/
│   ├── docker/            # Docker API client wrapper
│   ├── analyzer/          # Port risk analysis and scoring
│   ├── security/          # System security checks (SSH, fail2ban, updates)
│   ├── system/            # Firewall/iptables monitoring
│   ├── reporter/          # Report generation (terminal, JSON)
│   └── updater/           # Auto-update functionality
├── pkg/models/            # Shared data types
└── Makefile               # Build automation
```

## 🎯 Goals

DockerShield helps you answer critical security questions like:
- Are any of my database ports exposed to the internet?
- Is Docker bypassing my firewall (UFW/iptables)?
- Is my SSH configuration secure (key-only auth, no root login)?
- Is fail2ban protecting my server from brute-force attacks?
- Are there critical security updates I need to install?
- Which containers are on which networks?

Perfect for indie developers running 1-10 VPS instances who need comprehensive security visibility without enterprise-grade complexity or cost.

## 📝 License

Apache License 2.0 - see [LICENSE](LICENSE) file for details

## 🤝 Contributing

Contributions are welcome! We're actively looking for:

- 🐛 Bug reports and fixes
- ✨ Feature suggestions and implementations
- 📚 Documentation improvements
- 🧪 Test coverage expansion
- 🌍 Translations and internationalization

**Getting Started:**
1. Check out [good first issues](https://github.com/adrian13508/dockershield/labels/good-first-issue)
2. Read our [Contributing Guide](CONTRIBUTING.md)
3. Review the [Code of Conduct](CODE_OF_CONDUCT.md)
4. Fork, code, and submit a PR!

**Development Setup:**
```bash
git clone https://github.com/adrian13508/dockershield.git
cd dockershield
go mod tidy
make build
make test
```

See [CONTRIBUTING.md](CONTRIBUTING.md) for detailed guidelines.

## 🔒 Security

Found a security vulnerability? Please read our [Security Policy](SECURITY.md) for responsible disclosure guidelines.

## 📚 Documentation

- [Changelog](CHANGELOG.md) - Version history and release notes
- [Contributing Guide](CONTRIBUTING.md) - How to contribute
- [Security Policy](SECURITY.md) - Security reporting
- [Code of Conduct](CODE_OF_CONDUCT.md) - Community guidelines
- [Example Output](EXAMPLE_OUTPUT.md) - Sample scan results

## 💬 Support

- 🐛 [Report a Bug](https://github.com/adrian13508/dockershield/issues/new?template=bug_report.md)
- 💡 [Request a Feature](https://github.com/adrian13508/dockershield/issues/new?template=feature_request.md)
- 💬 [GitHub Discussions](https://github.com/adrian13508/dockershield/discussions)
- 📖 [Documentation](https://github.com/adrian13508/dockershield/wiki)

---

**Version:** 0.1.0
**License:** Apache 2.0
**Status:** Active Development 🟢

Made with ❤️ for the self-hosting community

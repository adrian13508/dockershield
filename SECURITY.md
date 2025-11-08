# Security Policy

## Supported Versions

We release patches for security vulnerabilities. Currently supported versions:

| Version | Supported          |
| ------- | ------------------ |
| 0.1.x   | :white_check_mark: |
| < 0.1   | :x:                |

## Reporting a Vulnerability

**Please do not report security vulnerabilities through public GitHub issues.**

We take the security of DockerShield seriously. If you believe you have found a security vulnerability, please report it to us as described below.

### How to Report

**Email:** security@dockershield.dev (or create a [GitHub Security Advisory](https://github.com/adrian13508/dockershield/security/advisories/new))

Please include the following information:

- **Type of vulnerability** (e.g., privilege escalation, information disclosure, code injection)
- **Full path of source file(s)** related to the vulnerability
- **Location of affected code** (tag/branch/commit or direct URL)
- **Step-by-step instructions** to reproduce the issue
- **Proof-of-concept or exploit code** (if possible)
- **Impact** of the issue, including how an attacker might exploit it

### What to Expect

- **Acknowledgment:** We will acknowledge receipt of your vulnerability report within 48 hours
- **Communication:** We will keep you informed about the progress of the fix
- **Credit:** With your permission, we will credit you in the security advisory
- **Timeline:** We aim to patch critical vulnerabilities within 7 days, and other vulnerabilities within 30 days

### Disclosure Policy

- **Coordinated Disclosure:** Please give us reasonable time to fix the issue before public disclosure
- **We will:**
  - Confirm the vulnerability and determine its impact
  - Develop and test a fix
  - Prepare a security advisory
  - Release a patched version
  - Publish the security advisory (with credit to you, if desired)

### Security Update Process

When we release a security fix:

1. **Patch Release:** We'll release a new patch version (e.g., v0.1.1)
2. **Security Advisory:** We'll publish a GitHub Security Advisory
3. **CHANGELOG Update:** The vulnerability and fix will be documented
4. **User Notification:** Users will be notified via the auto-updater
5. **Disclosure:** Full details published after users have had time to update (typically 7-14 days)

## Security Best Practices for Users

### Running DockerShield Securely

1. **Keep Updated**
   ```bash
   # Check for updates regularly
   dockershield upgrade
   ```

2. **Run with Minimum Privileges**
   - DockerShield requires Docker API access (typically requires root/sudo)
   - Consider using Docker socket proxy with restricted permissions
   - Never run as root if you can avoid it

3. **Verify Downloads**
   ```bash
   # Verify checksums after download
   sha256sum dockershield-linux-amd64
   # Compare with checksums.txt from release
   ```

4. **Review JSON Output**
   - When using JSON output in automation, sanitize sensitive data
   - Don't expose full reports publicly (may contain internal network info)

5. **Secure Your Reports**
   ```bash
   # Set proper permissions on report files
   dockershield scan --json --output report.json
   chmod 600 report.json
   ```

### Common Security Concerns

#### "Does DockerShield collect data?"

**No.** DockerShield:
- Runs entirely locally on your system
- Does not send data anywhere (except when checking for updates via GitHub API)
- Does not phone home or transmit scan results
- Is fully open source - you can audit the code

#### "Can DockerShield be used maliciously?"

DockerShield is a **defensive security tool** designed to help you:
- Find vulnerabilities in your own systems
- Secure your Docker containers
- Monitor your own infrastructure

**Prohibited uses:**
- ❌ Scanning systems you don't own or have permission to scan
- ❌ Using scan data for unauthorized access
- ❌ Any activity that violates applicable laws or regulations

#### "Does DockerShield modify my system?"

DockerShield operates in **read-only mode**:
- ✅ Reads Docker container information
- ✅ Reads system configuration files (SSH, fail2ban)
- ✅ Reads iptables rules
- ❌ Does NOT modify containers
- ❌ Does NOT change firewall rules
- ❌ Does NOT install packages

The only exception is the `upgrade` command, which updates DockerShield itself.

## Known Security Considerations

### Docker Socket Access

DockerShield requires access to the Docker socket (`/var/run/docker.sock`) to function. This is equivalent to root access on the host system.

**Risks:**
- Anyone with Docker socket access can escape containers
- Be cautious about running DockerShield in shared environments
- Consider using Docker socket proxy with access controls

**Mitigations:**
- Run DockerShield on systems you control
- Review the source code before running
- Use Docker contexts for remote scanning
- Consider running in a container with limited permissions

### SSH Configuration Parsing

DockerShield reads `/etc/ssh/sshd_config` and other system files.

**Risks:**
- Low risk - read-only access to configuration files
- May expose information about SSH hardening status

**Mitigations:**
- Secure report output (don't share publicly)
- Set proper file permissions on generated reports

### Update Mechanism

DockerShield can auto-update itself via the `upgrade` command.

**Risks:**
- Downloads binaries from GitHub releases
- Potential for supply chain attacks if GitHub account compromised

**Mitigations:**
- Verify checksums (automatic in upgrade process)
- Review release notes before upgrading
- Pin to specific versions in production
- Build from source for maximum security

## Security Audits

This project has not yet undergone a formal security audit. We welcome security researchers to review the code and report findings.

## Bug Bounty

We currently do not have a bug bounty program. However, we deeply appreciate security researchers who responsibly disclose vulnerabilities and will:

- Publicly credit you (with your permission)
- Respond promptly to your reports
- Keep you informed throughout the fix process

## Contact

- **Security Issues:** security@dockershield.dev or [GitHub Security Advisory](https://github.com/adrian13508/dockershield/security/advisories/new)
- **General Questions:** [GitHub Discussions](https://github.com/adrian13508/dockershield/discussions)

Thank you for helping keep DockerShield and its users safe! 🛡️

---
name: Wrong result
about: A false alarm, or an exposure the scanner missed
labels: bug
---

**What the scanner reported**

**What is actually the case, and how you know**

**Evidence** (remove anything private)

- `ports` section of `dockershield scan --json` for the affected container:
- `docker inspect <container> --format '{{json .NetworkSettings.Ports}}'`:
- For firewall findings, `sudo iptables-save` and `sudo ufw status`:

**Environment**
- `dockershield version`:
- OS and version:
- `docker version` (server):

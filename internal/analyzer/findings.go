package analyzer

import (
	"fmt"
	"net"
	"net/url"
	"sort"
	"strings"

	"github.com/adrian13508/skobel/pkg/models"
)

// Finding IDs. Part of the JSON output: do not rename.
const (
	FindingPortExposed   = "port_exposed"
	FindingHostNetwork   = "host_network"
	FindingSocketMounted = "docker_socket_mounted"
	FindingDockerAPITCP  = "docker_api_tcp"
	FindingUFWBypassed   = "ufw_bypassed"
	FindingIPv6Open      = "ipv6_unfiltered"
)

var severityRank = map[models.RiskLevel]int{
	models.RiskInfo: 0, models.RiskLow: 1, models.RiskMedium: 2, models.RiskHigh: 3, models.RiskCritical: 4,
}

// DaemonListener is one tcp:// address a Docker daemon listens on
type DaemonListener struct {
	Host      string
	TLSVerify bool
}

// BuildFindings turns analyzed containers, firewall state and daemon
// configuration into a sorted list of findings, each with a concrete fix.
// Containers must already have been through AnalyzeContainers.
func BuildFindings(containers []models.Container, fw *models.FirewallInfo, daemon []DaemonListener) []models.Finding {
	findings := []models.Finding{}
	published, publishedV6 := false, false

	for _, c := range containers {
		findings = append(findings, portFindings(c)...)

		for _, p := range c.Ports {
			if p.AddressScope == models.ScopeAllInterfaces || p.AddressScope == models.ScopePublicAddress {
				published = true
				if strings.Contains(p.HostIP, ":") {
					publishedV6 = true
				}
			}
		}

		if c.State != "running" {
			continue
		}
		if c.NetworkMode == "host" {
			findings = append(findings, models.Finding{
				ID:        FindingHostNetwork,
				Severity:  models.RiskHigh,
				Container: c.Name,
				Title:     "Container uses host networking",
				Detail: "Every port the container listens on is open on the host directly. " +
					"Docker does not report these ports, so they are not listed in this scan.",
				Fix: fmt.Sprintf("List what it listens on:\n"+
					"  sudo ss -tlnp\n"+
					"Then remove `network_mode: host` from '%s' and publish only what is needed:\n"+
					"  ports:\n"+
					"    - \"127.0.0.1:PORT:PORT\"", c.Name),
			})
		}
		if c.DockerSocketMounted {
			findings = append(findings, models.Finding{
				ID:        FindingSocketMounted,
				Severity:  models.RiskMedium,
				Container: c.Name,
				Title:     "Docker socket is mounted into the container",
				Detail: "A process in this container can control the Docker daemon, which is equivalent to root on the host. " +
					"A read-only mount does not change that.",
				Fix: "If the container needs the Docker API, put a filtering proxy in between and mount the socket only there, for example:\n" +
					"  https://github.com/Tecnativa/docker-socket-proxy\n" +
					"Otherwise remove the volume:\n" +
					"  - /var/run/docker.sock:/var/run/docker.sock",
			})
		}
	}

	for _, listener := range daemon {
		host := listener.Host
		if isLoopbackListener(host) {
			continue
		}
		f := models.Finding{
			ID:        FindingDockerAPITCP,
			Severity:  models.RiskCritical,
			Addresses: []string{host},
			Title:     "Docker daemon listens on TCP without TLS client verification",
			Detail:    "Anyone who can reach " + host + " can start containers and take over the host.",
			Fix: "Remove the tcp:// entry from \"hosts\" in /etc/docker/daemon.json (or the -H flag of dockerd) and restart Docker:\n" +
				"  sudo systemctl restart docker\n" +
				"For remote access use a Docker context over SSH instead:\n" +
				"  https://docs.docker.com/engine/security/protect-access/",
		}
		if listener.TLSVerify {
			f.Severity = models.RiskMedium
			f.Title = "Docker daemon listens on TCP (TLS client verification is on)"
			f.Detail = "Access to " + host + " depends on the client certificates staying private."
		}
		findings = append(findings, f)
	}

	if fw != nil && fw.Checked && published {
		if fw.DockerBypassingUFW {
			findings = append(findings, models.Finding{
				ID:       FindingUFWBypassed,
				Severity: models.RiskHigh,
				Title:    "UFW is active but does not filter published container ports",
				Detail: "Docker adds its own iptables rules ahead of UFW, and the DOCKER-USER chain has no filtering rules. " +
					"`ufw deny` has no effect on the published ports.",
				Fix: "Bind each port to 127.0.0.1 as shown for the individual findings, or filter in the DOCKER-USER chain:\n" +
					"  https://docs.docker.com/engine/network/packet-filtering-firewalls/#docker-and-ufw\n" +
					"  https://github.com/chaifeng/ufw-docker",
			})
		}
		if publishedV6 && fw.DockerUserFiltered && fw.IPv6Checked && !fw.IPv6DockerUserFiltered {
			findings = append(findings, models.Finding{
				ID:       FindingIPv6Open,
				Severity: models.RiskHigh,
				Title:    "IPv4 is filtered in DOCKER-USER, IPv6 is not",
				Detail: "The IPv4 DOCKER-USER chain has filtering rules, the IPv6 one has none, and at least one port is published on an IPv6 address. " +
					"Those ports may be reachable over IPv6 even though IPv4 is blocked.",
				Fix: "Compare the two chains and mirror the rules for IPv6:\n" +
					"  sudo iptables -S DOCKER-USER\n" +
					"  sudo ip6tables -S DOCKER-USER\n" +
					"or publish on IPv4 only by giving an explicit address:\n" +
					"  ports:\n" +
					"    - \"127.0.0.1:PORT:PORT\"",
			})
		}
	}

	sort.SliceStable(findings, func(i, j int) bool {
		a, b := findings[i], findings[j]
		if severityRank[a.Severity] != severityRank[b.Severity] {
			return severityRank[a.Severity] > severityRank[b.Severity]
		}
		if a.Container != b.Container {
			return a.Container < b.Container
		}
		return a.Port < b.Port
	})
	return findings
}

// portFindings reports bindings rated medium or above, one finding per
// published port (IPv4 and IPv6 bindings of the same port are merged).
func portFindings(c models.Container) []models.Finding {
	var out []models.Finding
	index := map[string]int{}
	for _, p := range c.Ports {
		if severityRank[p.RiskLevel] < severityRank[models.RiskMedium] {
			continue
		}
		key := p.HostPort + "/" + p.ContainerPort + "/" + p.Protocol + "/" + string(p.RiskLevel)
		if i, ok := index[key]; ok {
			out[i].Addresses = append(out[i].Addresses, p.HostIP)
			continue
		}
		index[key] = len(out)
		mapping := fmt.Sprintf("%s:%s", p.HostPort, p.ContainerPort)
		if p.Protocol != "tcp" {
			mapping += "/" + p.Protocol
		}
		out = append(out, models.Finding{
			ID:        FindingPortExposed,
			Severity:  p.RiskLevel,
			Container: c.Name,
			Port:      p.HostPort + "/" + p.Protocol,
			Addresses: []string{p.HostIP},
			Title:     p.RiskReason,
			Detail: "Other machines can connect to this port unless a firewall outside Docker blocks it. " +
				"UFW rules do not apply to published container ports by default.",
			Fix: fmt.Sprintf("In compose, bind the port to localhost:\n"+
				"  ports:\n"+
				"    - \"127.0.0.1:%s\"\n"+
				"With docker run:\n"+
				"  -p 127.0.0.1:%s\n"+
				"If only other containers use it, remove the `ports:` entry; containers on the same compose network reach it by service name on port %s.",
				mapping, mapping, p.ContainerPort),
		})
	}
	return out
}

// AddToSummary counts findings that are not port bindings. Port bindings are
// already counted by AnalyzeContainers.
func AddToSummary(summary *models.RiskSummary, findings []models.Finding) {
	for _, f := range findings {
		if f.ID != FindingPortExposed {
			countRisk(summary, f.Severity)
		}
	}
}

func isLoopbackListener(host string) bool {
	u, err := url.Parse(host)
	if err != nil {
		return false
	}
	ip := net.ParseIP(u.Hostname())
	return u.Hostname() == "localhost" || (ip != nil && ip.IsLoopback())
}

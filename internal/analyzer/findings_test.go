package analyzer

import (
	"strings"
	"testing"

	"github.com/adrian13508/skobel/pkg/models"
)

func binding(hostIP, hostPort, containerPort string) models.PortBinding {
	exposure, scope := ClassifyHostIP(hostIP)
	return models.PortBinding{HostIP: hostIP, HostPort: hostPort, ContainerPort: containerPort,
		Protocol: "tcp", ExposureType: exposure, AddressScope: scope}
}

func findingIDs(findings []models.Finding) []string {
	var ids []string
	for _, f := range findings {
		ids = append(ids, f.ID)
	}
	return ids
}

func has(findings []models.Finding, id string) bool {
	for _, f := range findings {
		if f.ID == id {
			return true
		}
	}
	return false
}

func TestDualStackBindingCountsOnce(t *testing.T) {
	containers := []models.Container{{
		Name:  "db",
		State: "running",
		Ports: []models.PortBinding{binding("0.0.0.0", "5432", "5432"), binding("::", "5432", "5432")},
	}}

	summary := AnalyzeContainers(containers)
	if summary.Critical != 1 {
		t.Errorf("critical = %d, want 1 (one published port, two address families)", summary.Critical)
	}
	if got := CalculateSecurityScore(summary); got != 75 {
		t.Errorf("score = %d, want 75", got)
	}

	findings := BuildFindings(containers, nil, nil)
	if len(findings) != 1 {
		t.Fatalf("findings = %v, want one", findingIDs(findings))
	}
	f := findings[0]
	if len(f.Addresses) != 2 || f.Port != "5432/tcp" || f.Severity != models.RiskCritical {
		t.Errorf("unexpected finding: %+v", f)
	}
	if !strings.Contains(f.Fix, `- "127.0.0.1:5432:5432"`) {
		t.Errorf("fix must contain a compose snippet bound to localhost:\n%s", f.Fix)
	}
}

func TestAddressScopeDrivesRisk(t *testing.T) {
	cases := []struct {
		hostIP string
		want   models.RiskLevel
	}{
		{"0.0.0.0", models.RiskCritical},
		{"203.0.113.7", models.RiskCritical}, // a specific public address is just as reachable
		{"10.0.0.5", models.RiskMedium},
		{"100.101.79.8", models.RiskMedium}, // VPN range
		{"127.0.0.1", models.RiskLow},
		{"", models.RiskCritical}, // Podman: empty means all interfaces
	}
	for _, c := range cases {
		b := binding(c.hostIP, "5432", "5432")
		AnalyzePortRisk(&b)
		if b.RiskLevel != c.want {
			t.Errorf("PostgreSQL on %q: risk = %s, want %s", c.hostIP, b.RiskLevel, c.want)
		}
	}
}

func TestWebPortsOnAllInterfacesAreLow(t *testing.T) {
	for _, port := range []string{"80", "443"} {
		b := binding("0.0.0.0", port, port)
		AnalyzePortRisk(&b)
		if b.RiskLevel != models.RiskLow {
			t.Errorf("port %s: risk = %s, want low", port, b.RiskLevel)
		}
	}
}

func TestContainerSettingFindings(t *testing.T) {
	containers := []models.Container{
		{Name: "proxy", State: "running", NetworkMode: "host"},
		{Name: "watcher", State: "running", DockerSocketMounted: true},
		{Name: "old", State: "exited", NetworkMode: "host", DockerSocketMounted: true},
	}
	summary := AnalyzeContainers(containers)
	findings := BuildFindings(containers, nil, nil)
	AddToSummary(&summary, findings)

	if len(findings) != 2 || findings[0].ID != FindingHostNetwork || findings[1].ID != FindingSocketMounted {
		t.Fatalf("findings = %v, want host_network then docker_socket_mounted (stopped container ignored)", findingIDs(findings))
	}
	if summary.High != 1 || summary.Medium != 1 {
		t.Errorf("summary = %+v, want 1 high and 1 medium", summary)
	}
}

func TestDockerAPITCP(t *testing.T) {
	findings := BuildFindings(nil, nil, []DaemonListener{{Host: "tcp://0.0.0.0:2375"}, {Host: "tcp://127.0.0.1:2375"}})
	if len(findings) != 1 || findings[0].Severity != models.RiskCritical {
		t.Fatalf("want one critical finding for the non-loopback listener, got %+v", findings)
	}

	// TLS on one daemon must not downgrade another daemon's plain listener
	findings = BuildFindings(nil, nil, []DaemonListener{
		{Host: "tcp://0.0.0.0:2376", TLSVerify: true},
		{Host: "tcp://0.0.0.0:2375"},
	})
	if len(findings) != 2 || findings[0].Severity != models.RiskCritical || findings[1].Severity != models.RiskMedium {
		t.Fatalf("want critical (plain) then medium (tlsverify), got %+v", findings)
	}
}

func TestFirewallFindings(t *testing.T) {
	published := []models.Container{{Name: "db", State: "running",
		Ports: []models.PortBinding{binding("0.0.0.0", "5432", "5432"), binding("::", "5432", "5432")}}}
	localOnly := []models.Container{{Name: "db", State: "running",
		Ports: []models.PortBinding{binding("127.0.0.1", "5432", "5432")}}}
	AnalyzeContainers(published)
	AnalyzeContainers(localOnly)

	cases := []struct {
		name       string
		containers []models.Container
		fw         models.FirewallInfo
		wantBypass bool
		wantIPv6   bool
	}{
		{"ufw active, nothing in DOCKER-USER", published,
			models.FirewallInfo{Checked: true, UFWActive: true, DockerBypassingUFW: true}, true, false},
		{"bypass but nothing published", localOnly,
			models.FirewallInfo{Checked: true, UFWActive: true, DockerBypassingUFW: true}, false, false},
		{"not checked", published,
			models.FirewallInfo{Checked: false, DockerBypassingUFW: true}, false, false},
		{"IPv4 filtered, IPv6 open", published,
			models.FirewallInfo{Checked: true, UFWActive: true, DockerUserFiltered: true, IPv6Checked: true}, false, true},
		{"both filtered", published,
			models.FirewallInfo{Checked: true, UFWActive: true, DockerUserFiltered: true, IPv6Checked: true, IPv6DockerUserFiltered: true}, false, false},
		{"IPv6 rules unreadable", published,
			models.FirewallInfo{Checked: true, DockerUserFiltered: true, IPv6Checked: false}, false, false},
	}
	for _, c := range cases {
		findings := BuildFindings(c.containers, &c.fw, nil)
		if got := has(findings, FindingUFWBypassed); got != c.wantBypass {
			t.Errorf("%s: ufw_bypassed = %v, want %v", c.name, got, c.wantBypass)
		}
		if got := has(findings, FindingIPv6Open); got != c.wantIPv6 {
			t.Errorf("%s: ipv6_unfiltered = %v, want %v", c.name, got, c.wantIPv6)
		}
	}
}

func TestFindingsSortedBySeverity(t *testing.T) {
	containers := []models.Container{
		{Name: "web", State: "running", Ports: []models.PortBinding{binding("0.0.0.0", "8080", "8000")}},
		{Name: "db", State: "running", Ports: []models.PortBinding{binding("0.0.0.0", "5432", "5432")}},
	}
	AnalyzeContainers(containers)
	findings := BuildFindings(containers, nil, nil)
	if len(findings) != 2 || findings[0].Container != "db" {
		t.Errorf("critical finding must come first: %+v", findings)
	}
}

func TestLowFindingsDoNotAffectScore(t *testing.T) {
	if got := CalculateSecurityScore(models.RiskSummary{Low: 7, Info: 3}); got != 100 {
		t.Errorf("score = %d, want 100: localhost bindings must not cost points", got)
	}
}

// One port on two public addresses is one finding and one count
func TestSummaryCountsWhatFindingsList(t *testing.T) {
	containers := []models.Container{{Name: "db", State: "running", Ports: []models.PortBinding{
		{HostIP: "203.0.113.1", HostPort: "5432", ContainerPort: "5432", Protocol: "tcp"},
		{HostIP: "203.0.113.2", HostPort: "5432", ContainerPort: "5432", Protocol: "tcp"},
		{HostIP: "127.0.0.1", HostPort: "6379", ContainerPort: "6379", Protocol: "tcp"},
		{HostIP: "::1", HostPort: "6379", ContainerPort: "6379", Protocol: "tcp"},
	}}}
	for i := range containers[0].Ports {
		p := &containers[0].Ports[i]
		p.ExposureType, p.AddressScope = ClassifyHostIP(p.HostIP)
	}
	summary := AnalyzeContainers(containers)
	findings := BuildFindings(containers, nil, nil)
	if summary.Critical != 1 || len(findings) != 1 || len(findings[0].Addresses) != 2 {
		t.Errorf("critical = %d, findings = %+v; want one of each with two addresses", summary.Critical, findings)
	}
	if summary.Low != 1 {
		t.Errorf("low = %d, want 1 for the localhost port on IPv4 and IPv6", summary.Low)
	}
}

package reporter

import (
	"strings"
	"testing"
	"time"

	"github.com/adrian13508/dockershield/pkg/models"
)

func TestGenerateHTML(t *testing.T) {
	result := models.ScanResult{
		Timestamp:    time.Date(2026, 11, 19, 10, 30, 0, 0, time.UTC),
		Hostname:     "vps-1",
		OverallScore: 65,
		RiskSummary:  models.RiskSummary{Critical: 1, High: 1},
		Findings: []models.Finding{
			{ID: "port_exposed", Severity: models.RiskCritical, Container: `db<script>alert(1)</script>`, Port: "5432/tcp",
				Addresses: []string{"0.0.0.0", "::"}, Title: "PostgreSQL published on all interfaces",
				Detail: "Other machines can connect.", Fix: "ports:\n  - \"127.0.0.1:5432:5432\""},
			{ID: "ufw_bypassed", Severity: models.RiskHigh, Title: "UFW is active but does not filter published container ports",
				Detail: "d", Fix: "see https://docs.docker.com/engine/network/packet-filtering-firewalls/"},
		},
		Containers: []models.Container{
			{Name: "db", State: "running", Ports: []models.PortBinding{
				{HostIP: "0.0.0.0", HostPort: "5432", ContainerPort: "5432", Protocol: "tcp",
					AddressScope: models.ScopeAllInterfaces, RiskLevel: models.RiskCritical}}},
			{Name: "stopped", State: "exited", Ports: []models.PortBinding{{HostPort: "9999"}}},
		},
		Firewall: &models.FirewallInfo{Checked: true, UFWActive: true, DockerDetected: true},
	}

	out, err := GenerateHTML(result, "1.2.3")
	if err != nil {
		t.Fatal(err)
	}
	html := string(out)

	for _, want := range []string{
		"vps-1", "2026-11-19 10:30 UTC", "65/100", "FAIR",
		"1. <span class=\"sev critical\">CRITICAL</span>",
		"2. <span class=\"sev high\">HIGH</span>",
		"PostgreSQL published on all interfaces",
		"127.0.0.1:5432:5432",
		"DockerShield 1.2.3",
		"@media print",
	} {
		if !strings.Contains(html, want) {
			t.Errorf("report lacks %q", want)
		}
	}

	if strings.Contains(html, "<script>alert(1)</script>") {
		t.Error("container name was not escaped")
	}
	if strings.Contains(html, "9999") {
		t.Error("ports of stopped containers must not be listed")
	}

	// One file, nothing loaded from elsewhere
	for _, forbidden := range []string{"<script", "<link", "<img", "<iframe", "src=", "@import", "url(", `href=`} {
		if strings.Contains(html, forbidden) {
			t.Errorf("report must be self-contained, found %q", forbidden)
		}
	}
}

func TestGenerateHTMLWithoutFindingsOrFirewall(t *testing.T) {
	out, err := GenerateHTML(models.ScanResult{Hostname: "h", OverallScore: 100,
		Firewall: &models.FirewallInfo{Checked: false, Warning: "Could not analyze firewall: insufficient permissions."}}, "dev")
	if err != nil {
		t.Fatal(err)
	}
	html := string(out)
	for _, want := range []string{"No findings rated medium or above.", "No running container publishes a port.", "could not be checked", "insufficient permissions"} {
		if !strings.Contains(html, want) {
			t.Errorf("report lacks %q", want)
		}
	}
}

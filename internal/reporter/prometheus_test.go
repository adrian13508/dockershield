package reporter

import (
	"strings"
	"testing"

	"github.com/adrian13508/dockershield/pkg/models"
)

func TestPrometheusGenerate(t *testing.T) {
	containers := []models.Container{
		{
			Name:  "db",
			State: "running",
			Ports: []models.PortBinding{
				{HostIP: "0.0.0.0", HostPort: "5432", Protocol: "tcp", ExposureType: models.ExposurePublic, RiskLevel: models.RiskCritical},
				{HostIP: "127.0.0.1", HostPort: "6379", Protocol: "tcp", ExposureType: models.ExposureLocalhost, RiskLevel: models.RiskLow},
			},
		},
		{
			Name:  `we"ird\name`,
			State: "exited",
			Ports: []models.PortBinding{
				{HostIP: "0.0.0.0", HostPort: "8080", Protocol: "tcp", ExposureType: models.ExposurePublic, RiskLevel: models.RiskMedium},
			},
		},
	}
	firewall := &models.FirewallInfo{UFWActive: true, DockerBypassingUFW: true}
	summary := models.RiskSummary{Critical: 1, Medium: 1, Low: 1}

	out := string(NewPrometheusReporter().Generate(containers, firewall, summary, 42))

	for _, want := range []string{
		"dockershield_security_score 42\n",
		`dockershield_risks{severity="critical"} 1` + "\n",
		`dockershield_risks{severity="high"} 0` + "\n",
		`dockershield_containers{state="running"} 1` + "\n",
		`dockershield_containers{state="exited"} 1` + "\n",
		`dockershield_exposed_port{container="db",port="5432",protocol="tcp",severity="critical"} 1` + "\n",
		`dockershield_exposed_port{container="we\"ird\\name",port="8080",protocol="tcp",severity="medium"} 1` + "\n",
		"dockershield_ufw_active 1\n",
		"dockershield_docker_bypassing_ufw 1\n",
		"dockershield_last_scan_timestamp_seconds ",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("output missing %q\n--- full output:\n%s", want, out)
		}
	}

	if strings.Contains(out, `port="6379"`) {
		t.Errorf("localhost-bound port must not be reported as exposed:\n%s", out)
	}
	if !strings.HasSuffix(out, "\n") {
		t.Error("output must end with a newline")
	}
}

func TestPrometheusGenerateNoFirewall(t *testing.T) {
	out := string(NewPrometheusReporter().Generate(nil, nil, models.RiskSummary{}, 100))

	if strings.Contains(out, "dockershield_ufw_active") {
		t.Error("firewall metrics must be absent when firewall info is nil")
	}
	if !strings.Contains(out, "dockershield_security_score 100\n") {
		t.Errorf("missing score metric:\n%s", out)
	}
}

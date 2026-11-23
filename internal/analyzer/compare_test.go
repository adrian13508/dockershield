package analyzer

import (
	"testing"

	"github.com/adrian13508/skobel/pkg/models"
)

func TestCompare(t *testing.T) {
	db := models.Finding{ID: FindingPortExposed, Container: "db", Port: "5432/tcp", Severity: models.RiskCritical}
	admin := models.Finding{ID: FindingPortExposed, Container: "admin", Port: "9000/tcp", Severity: models.RiskHigh}
	host := models.Finding{ID: FindingHostNetwork, Container: "proxy", Severity: models.RiskHigh}
	plain := models.Finding{ID: FindingDockerAPITCP, Addresses: []string{"tcp://0.0.0.0:2375"}, Severity: models.RiskCritical}
	tls := models.Finding{ID: FindingDockerAPITCP, Addresses: []string{"tcp://0.0.0.0:2376"}, Severity: models.RiskMedium}

	d := Compare(
		models.ScanResult{OverallScore: 30, Findings: []models.Finding{db, admin, plain}},
		models.ScanResult{OverallScore: 70, Findings: []models.Finding{admin, host, tls}},
	)

	if d.OldScore != 30 || d.NewScore != 70 || d.Recomputed {
		t.Errorf("scores = %d -> %d, recomputed = %v", d.OldScore, d.NewScore, d.Recomputed)
	}
	if len(d.Resolved) != 2 || d.Resolved[0].Container != "db" || d.Resolved[1].Addresses[0] != "tcp://0.0.0.0:2375" {
		t.Errorf("resolved = %+v, want db and the plain daemon listener", d.Resolved)
	}
	if len(d.New) != 2 || d.New[0].ID != FindingHostNetwork {
		t.Errorf("new = %+v, want host_network and the TLS listener", d.New)
	}
	if len(d.Remaining) != 1 || d.Remaining[0].Container != "admin" {
		t.Errorf("remaining = %+v, want admin", d.Remaining)
	}
}

// Reports from v0.1.3 have no findings list and count IPv4+IPv6 twice
func TestCompareOldReportIsRatedWithCurrentRules(t *testing.T) {
	old := models.ScanResult{
		OverallScore: 50, // as v0.1.3 computed it: two criticals
		Containers: []models.Container{{Name: "db", State: "running", Ports: []models.PortBinding{
			{HostIP: "0.0.0.0", HostPort: "5432", ContainerPort: "5432", Protocol: "tcp", ExposureType: models.ExposurePublic},
			{HostIP: "::", HostPort: "5432", ContainerPort: "5432", Protocol: "tcp", ExposureType: models.ExposurePublic},
		}}},
	}
	fixed := models.ScanResult{OverallScore: 100, Findings: []models.Finding{}}

	d := Compare(old, fixed)
	if !d.Recomputed {
		t.Error("Recomputed must be set for a report without findings")
	}
	if d.OldScore != 75 {
		t.Errorf("old score = %d, want 75 (one critical under current rules)", d.OldScore)
	}
	if len(d.Resolved) != 1 || len(d.New) != 0 {
		t.Errorf("resolved = %+v, new = %+v", d.Resolved, d.New)
	}
}

// A v0.1.3 report against a current one: the firewall finding of the new
// report must not show up as new, because the old report cannot have it.
func TestCompareMixedVersionsRatesBothSides(t *testing.T) {
	db := models.Container{Name: "db", State: "running", Ports: []models.PortBinding{
		{HostIP: "0.0.0.0", HostPort: "5432", ContainerPort: "5432", Protocol: "tcp"},
	}}
	old := models.ScanResult{OverallScore: 75, Containers: []models.Container{db}}
	current := models.ScanResult{OverallScore: 65, Containers: []models.Container{db}, Findings: []models.Finding{
		{ID: FindingPortExposed, Container: "db", Port: "5432/tcp", Severity: models.RiskCritical},
		{ID: FindingUFWBypassed, Severity: models.RiskHigh},
	}}
	d := Compare(old, current)
	if !d.Recomputed || len(d.New) != 0 || len(d.Resolved) != 0 || len(d.Remaining) != 1 {
		t.Errorf("new = %+v, resolved = %+v, remaining = %+v; want one remaining", d.New, d.Resolved, d.Remaining)
	}
	if d.OldScore != d.NewScore {
		t.Errorf("scores = %d -> %d, want equal for the same containers", d.OldScore, d.NewScore)
	}
}

// Two findings can share a key; resolving one of them must show
func TestCompareCountsFindingsWithTheSameKey(t *testing.T) {
	public := models.Finding{ID: FindingPortExposed, Container: "db", Port: "5432/tcp", Severity: models.RiskCritical}
	private := models.Finding{ID: FindingPortExposed, Container: "db", Port: "5432/tcp", Severity: models.RiskMedium}
	d := Compare(
		models.ScanResult{Findings: []models.Finding{public, private}},
		models.ScanResult{Findings: []models.Finding{private}},
	)
	if len(d.Resolved) != 1 || len(d.Remaining) != 1 || len(d.New) != 0 {
		t.Errorf("resolved = %d, remaining = %d, new = %d; want 1, 1, 0", len(d.Resolved), len(d.Remaining), len(d.New))
	}
}

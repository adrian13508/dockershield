//go:build integration

// Integration tests: start the compose projects in test/exposed against a
// real Docker daemon and check what the built scanner reports.
//
//	go build -o dockershield ./cmd/dockershield
//	DOCKERSHIELD_BIN=$PWD/dockershield go test -tags integration ./test/
//
// DOCKERSHIELD_TEST_DIR overrides the directory holding the compose files.
package test

import (
	"encoding/json"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/adrian13508/dockershield/pkg/models"
)

const project = "dockershield-test-"

func bin(t *testing.T) string {
	t.Helper()
	b := os.Getenv("DOCKERSHIELD_BIN")
	if b == "" {
		t.Fatal("set DOCKERSHIELD_BIN to the built dockershield binary")
	}
	return b
}

func up(t *testing.T, file string) {
	t.Helper()
	dir := os.Getenv("DOCKERSHIELD_TEST_DIR")
	if dir == "" {
		dir = "exposed"
	}
	path := filepath.Join(dir, file)
	down := func() {
		_ = exec.Command("docker", "compose", "-f", path, "down", "--remove-orphans", "-t", "1").Run()
	}
	down()
	if out, err := exec.Command("docker", "compose", "-f", path, "up", "-d").CombinedOutput(); err != nil {
		t.Fatalf("compose up failed: %v\n%s", err, out)
	}
	t.Cleanup(down)
}

func scan(t *testing.T) models.ScanResult {
	t.Helper()
	cmd := exec.Command(bin(t), "scan", "--json")
	cmd.Stderr = os.Stderr
	out, err := cmd.Output()
	if err != nil {
		t.Fatalf("scan failed: %v", err)
	}
	var result models.ScanResult
	if err := json.Unmarshal(out, &result); err != nil {
		t.Fatalf("scan --json is not valid JSON: %v\n%s", err, out)
	}
	return result
}

func exitCode(t *testing.T, args ...string) int {
	t.Helper()
	err := exec.Command(bin(t), args...).Run()
	var exit *exec.ExitError
	if errors.As(err, &exit) {
		return exit.ExitCode()
	}
	if err != nil {
		t.Fatalf("%v: %v", args, err)
	}
	return 0
}

func find(findings []models.Finding, id, service string) *models.Finding {
	for i, f := range findings {
		if f.ID == id && f.Container == project+service+"-1" {
			return &findings[i]
		}
	}
	return nil
}

func TestExposedServices(t *testing.T) {
	up(t, "compose.yml")
	result := scan(t)

	db := find(result.Findings, "port_exposed", "db")
	if db == nil {
		t.Fatalf("no port_exposed finding for db; findings: %+v", result.Findings)
	}
	if db.Severity != models.RiskCritical || db.Port != "5432/tcp" {
		t.Errorf("db finding = %+v, want critical on 5432/tcp", db)
	}
	if !strings.Contains(db.Fix, `- "127.0.0.1:5432:5432"`) {
		t.Errorf("db fix lacks the compose snippet:\n%s", db.Fix)
	}

	if admin := find(result.Findings, "port_exposed", "admin"); admin == nil || admin.Severity != models.RiskHigh {
		t.Errorf("admin finding = %+v, want high", admin)
	}
	if f := find(result.Findings, "host_network", "hostnet"); f == nil || f.Severity != models.RiskHigh {
		t.Errorf("hostnet finding = %+v, want high host_network", f)
	}
	if f := find(result.Findings, "docker_socket_mounted", "watcher"); f == nil {
		t.Error("no docker_socket_mounted finding for watcher")
	}
	for _, service := range []string{"cache", "web"} {
		if f := find(result.Findings, "port_exposed", service); f != nil {
			t.Errorf("unexpected finding for %s: %+v", service, f)
		}
	}

	// One published port is one critical finding, also on a dual-stack host
	// where Docker reports it on both 0.0.0.0 and ::
	if result.RiskSummary.Critical != 1 {
		t.Errorf("risk_summary.critical = %d, want 1", result.RiskSummary.Critical)
	}
	// db critical (25) + admin high (10) + hostnet high (10) + watcher medium (5) = 50.
	// Findings about the host itself (UFW bypass, daemon TCP listener) may lower it further.
	if result.OverallScore > 50 {
		t.Errorf("overall_score = %d, want at most 50", result.OverallScore)
	}

	for _, c := range result.Containers {
		if c.CreatedAt.IsZero() {
			t.Errorf("container %s has no created_at", c.Name)
		}
	}

	if code := exitCode(t, "scan", "--json", "--fail-on", "critical"); code != 2 {
		t.Errorf("scan --fail-on critical exit code = %d, want 2", code)
	}

	// `check ports` must rate ports too (it used to report everything as info)
	out, err := exec.Command(bin(t), "check", "ports", "--json", "--severity", "critical").Output()
	if err != nil {
		t.Fatalf("check ports failed: %v", err)
	}
	var check struct {
		Results struct {
			Critical int `json:"critical"`
		} `json:"results"`
	}
	if err := json.Unmarshal(out, &check); err != nil {
		t.Fatalf("check ports --json: %v\n%s", err, out)
	}
	if check.Results.Critical == 0 {
		t.Errorf("check ports --severity critical found nothing:\n%s", out)
	}
}

func TestFixedServices(t *testing.T) {
	up(t, "compose.fixed.yml")
	result := scan(t)

	for _, f := range result.Findings {
		if strings.HasPrefix(f.Container, project) {
			t.Errorf("unexpected finding after applying the fixes: %+v", f)
		}
	}
	if result.RiskSummary.Critical != 0 || result.RiskSummary.High != 0 {
		t.Errorf("risk_summary = %+v, want no critical or high", result.RiskSummary)
	}
	// "high", not "medium": the host itself may have medium findings
	// (a Docker-in-Docker daemon listens on TCP with TLS)
	if code := exitCode(t, "scan", "--json", "--fail-on", "high"); code != 0 {
		t.Errorf("scan --fail-on high exit code = %d, want 0", code)
	}
}

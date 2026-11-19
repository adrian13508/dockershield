package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/adrian13508/dockershield/internal/analyzer"
	"github.com/adrian13508/dockershield/pkg/models"
)

func TestFormatDiff(t *testing.T) {
	db := models.Finding{ID: analyzer.FindingPortExposed, Severity: models.RiskCritical, Container: "db", Port: "5432/tcp", Title: "PostgreSQL published on all interfaces"}
	admin := models.Finding{ID: analyzer.FindingPortExposed, Severity: models.RiskHigh, Container: "admin", Port: "9000/tcp", Title: "Portainer published on all interfaces"}
	before := models.ScanResult{Hostname: "vps-1", Timestamp: time.Date(2026, 11, 1, 9, 0, 0, 0, time.UTC), OverallScore: 65, Findings: []models.Finding{db, admin}}
	after := models.ScanResult{Hostname: "vps-1", Timestamp: time.Date(2026, 11, 2, 9, 0, 0, 0, time.UTC), OverallScore: 90, Findings: []models.Finding{admin}}

	out := formatDiff(before, after, analyzer.Compare(before, after))
	for _, want := range []string{
		"Host:   vps-1", "score 65", "score 90 (+25)",
		"Resolved (1)", "db 5432/tcp: PostgreSQL published on all interfaces",
		"New (0)", "Still present (1)", "admin 9000/tcp",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("diff lacks %q:\n%s", want, out)
		}
	}
	if strings.Contains(out, "different host") || strings.Contains(out, "v0.1.3") {
		t.Errorf("unexpected note:\n%s", out)
	}

	after.Hostname = "vps-2"
	if out := formatDiff(before, after, analyzer.Compare(before, after)); !strings.Contains(out, "different host (vps-1)") {
		t.Errorf("no warning about different hosts:\n%s", out)
	}
}

func TestLoadReportRejectsOtherFiles(t *testing.T) {
	dir := t.TempDir()
	for name, content := range map[string]string{"empty.json": "{}", "text.json": "not json", "probe.json": `{"host":"x","results":[]}`} {
		path := filepath.Join(dir, name)
		if err := os.WriteFile(path, []byte(content), 0600); err != nil {
			t.Fatal(err)
		}
		if _, err := loadReport(path); err == nil {
			t.Errorf("loadReport accepted %s", name)
		}
	}
	if _, err := loadReport(filepath.Join(dir, "missing.json")); err == nil {
		t.Error("loadReport accepted a missing file")
	}
}

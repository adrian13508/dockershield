package main

import (
	"testing"

	"github.com/adrian13508/dockershield/pkg/models"
)

func TestFindingsAtOrAbove(t *testing.T) {
	summary := models.RiskSummary{Critical: 1, High: 2, Medium: 3, Low: 4, Info: 5}

	cases := []struct {
		severity string
		want     int
	}{
		{"critical", 1},
		{"high", 3},
		{"medium", 6},
		{"low", 10},
		{"", 0},
	}
	for _, c := range cases {
		if got := findingsAtOrAbove(summary, c.severity); got != c.want {
			t.Errorf("findingsAtOrAbove(%q) = %d, want %d", c.severity, got, c.want)
		}
	}
}

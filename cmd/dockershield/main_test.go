package main

import (
	"strings"
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

// The scanner must not touch the network unless asked: the release lookup
// is opt-in via `version --check`.
func TestVersionCheckIsOptIn(t *testing.T) {
	f := versionCmd.Flags().Lookup("check")
	if f == nil {
		t.Fatal("version --check flag missing")
	}
	if f.DefValue != "false" {
		t.Errorf("version --check default = %s, want false", f.DefValue)
	}
}

func TestWaitlistNotice(t *testing.T) {
	notice := waitlistNotice(false, "")
	if !strings.Contains(notice, waitlistURL) || strings.Contains(notice, "\n") {
		t.Errorf("notice must be one line with the waitlist link: %q", notice)
	}
	if !strings.Contains(waitlistURL, "ref=cli") {
		t.Error("the CLI link must carry its own source parameter")
	}
	for _, off := range []struct {
		quiet bool
		env   string
	}{{true, ""}, {false, "1"}, {false, "true"}, {false, "yes"}} {
		if got := waitlistNotice(off.quiet, off.env); got != "" {
			t.Errorf("notice shown with quiet=%v env=%q", off.quiet, off.env)
		}
	}
	for _, on := range []string{"0", "false"} {
		if waitlistNotice(false, on) == "" {
			t.Errorf("DOCKERSHIELD_QUIET=%s must not hide the notice", on)
		}
	}
}

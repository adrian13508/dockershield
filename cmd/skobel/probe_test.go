package main

import (
	"context"
	"path/filepath"
	"testing"

	"github.com/adrian13508/skobel/internal/probe"
)

func TestOwnershipConfirmationIsRememberedPerHost(t *testing.T) {
	file := filepath.Join(t.TempDir(), "sub", "probe_hosts")

	if isConfirmed(file, "my-server.example.com") {
		t.Fatal("a host must not be confirmed before the user said so")
	}
	if err := confirmHost(file, "my-server.example.com"); err != nil {
		t.Fatal(err)
	}
	if !isConfirmed(file, "my-server.example.com") || !isConfirmed(file, "MY-SERVER.example.com") {
		t.Error("confirmed host not remembered")
	}
	if isConfirmed(file, "other.example.com") || isConfirmed(file, "server.example.com") {
		t.Error("confirmation must not carry over to another host")
	}
}

func TestProbeRefusesWithoutConfirmation(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	probeConfirm, probePorts, probeFromReport = false, "22", ""
	probeTimeout, probeConcurrency = probe.MaxTimeout, 1

	err := runProbe(probeCmd, []string{"192.0.2.1"}) // TEST-NET-1, never contacted: refusal comes first
	if err == nil {
		t.Fatal("probe ran without --i-own-this-host")
	}
	file, _ := probeConfirmedFile()
	if isConfirmed(file, "192.0.2.1") {
		t.Error("a refused run must not record a confirmation")
	}
}

func TestProbeRejectsRanges(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	probeConfirm, probePorts, probeFromReport = true, "22", ""
	probeTimeout, probeConcurrency = probe.MaxTimeout, 1
	defer func() { probeConfirm = false }()

	for _, host := range []string{"10.0.0.0/24", "a.example.com,b.example.com", "a b"} {
		if err := runProbe(probeCmd, []string{host}); err == nil {
			t.Errorf("probe accepted %q", host)
		}
	}
}

func TestParsePorts(t *testing.T) {
	ports, err := parsePorts("22, 5432,6379")
	if err != nil || len(ports) != 3 || ports[1] != 5432 {
		t.Errorf("parsePorts = %v, %v", ports, err)
	}
	for _, bad := range []string{"0", "70000", "1-1024", "abc", ""} {
		if _, err := parsePorts(bad); err == nil {
			t.Errorf("parsePorts(%q) must fail", bad)
		}
	}
}

func TestVerdict(t *testing.T) {
	cases := []struct {
		state      string
		fromReport bool
		want       string
	}{
		{probe.StateOpen, true, "published and confirmed from outside"},
		{probe.StateFiltered, true, "published but blocked on the way (no answer)"},
		{probe.StateClosed, true, "published but refused from here"},
		{probe.StateUnreachable, true, "not tested: no route from this machine"},
		{probe.StateOpen, false, "open"},
		{probe.StateFiltered, false, "filtered"},
	}
	for _, c := range cases {
		if got := verdict(probe.Result{State: c.state}, c.fromReport); got != c.want {
			t.Errorf("verdict(%s, fromReport=%v) = %q, want %q", c.state, c.fromReport, got, c.want)
		}
	}
}

func TestResolveLiteralAndFamilyFilter(t *testing.T) {
	addrs, err := resolve(context.Background(), "::ffff:192.0.2.1", false, false)
	if err != nil || len(addrs) != 1 || addrs[0].String() != "192.0.2.1" {
		t.Errorf("resolve = %v, %v; want the unmapped IPv4 address", addrs, err)
	}
	if _, err := resolve(context.Background(), "192.0.2.1", false, true); err == nil {
		t.Error("an IPv4 literal with --ipv6 must fail")
	}
	if _, err := resolve(context.Background(), "2001:db8::1", true, false); err == nil {
		t.Error("an IPv6 literal with --ipv4 must fail")
	}
}

func TestVerdictUsesTheBoundFamily(t *testing.T) {
	v4only := probe.Target{Port: 5432, Bound: []string{"0.0.0.0"}}
	cases := []struct {
		family, state, want string
	}{
		{"ipv4", probe.StateOpen, "published and confirmed from outside"},
		{"ipv6", probe.StateClosed, "not published on IPv6 according to the report"},
		{"ipv6", probe.StateFiltered, "not published on IPv6 according to the report"},
		{"ipv6", probe.StateOpen, "open, although the report shows no IPv6 binding"},
	}
	for _, c := range cases {
		r := probe.Result{Target: v4only, Family: c.family, State: c.state}
		if got := verdict(r, true); got != c.want {
			t.Errorf("verdict(%s, %s) = %q, want %q", c.family, c.state, got, c.want)
		}
	}
}

package system

import (
	"reflect"
	"testing"
)

const dockerDefault = `*filter
:INPUT DROP [0:0]
:DOCKER - [0:0]
:DOCKER-USER - [0:0]
:ufw-user-forward - [0:0]
-A FORWARD -j DOCKER-USER
-A DOCKER-USER -j RETURN
COMMIT
`

// What ufw-docker appends to /etc/ufw/after.rules
const ufwDocker = `*filter
:DOCKER - [0:0]
:DOCKER-USER - [0:0]
-A DOCKER-USER -j ufw-user-forward
-A DOCKER-USER -m conntrack --ctstate RELATED,ESTABLISHED -j RETURN
-A DOCKER-USER -m conntrack --ctstate INVALID -j DROP
COMMIT
`

const manualDrop = `*filter
:DOCKER - [0:0]
:DOCKER-USER - [0:0]
-A DOCKER-USER -i eth0 ! -s 10.0.0.0/8 -j DROP
COMMIT
`

const noDocker = `*filter
:INPUT ACCEPT [0:0]
COMMIT
`

func TestAnalyze(t *testing.T) {
	cases := []struct {
		name         string
		v4, v6       string
		v6ok, ufw    bool
		wantBypass   bool
		wantFiltered bool
		wantV6       bool
	}{
		{"ufw + default docker rules", dockerDefault, dockerDefault, true, true, true, false, false},
		{"ufw inactive", dockerDefault, dockerDefault, true, false, false, false, false},
		{"ufw-docker installed", ufwDocker, ufwDocker, true, true, false, true, true},
		{"manual DROP, IPv4 only", manualDrop, dockerDefault, true, true, false, true, false},
		{"no docker chains", noDocker, noDocker, true, true, false, false, false},
		{"ip6tables unreadable", manualDrop, "", false, true, false, true, false},
	}
	for _, c := range cases {
		a := analyze(c.v4, c.v6, c.v6ok, c.ufw)
		if a.DockerBypassingUFW != c.wantBypass {
			t.Errorf("%s: DockerBypassingUFW = %v, want %v", c.name, a.DockerBypassingUFW, c.wantBypass)
		}
		if a.DockerUserFiltered != c.wantFiltered {
			t.Errorf("%s: DockerUserFiltered = %v, want %v", c.name, a.DockerUserFiltered, c.wantFiltered)
		}
		if a.IPv6DockerUserFiltered != c.wantV6 {
			t.Errorf("%s: IPv6DockerUserFiltered = %v, want %v", c.name, a.IPv6DockerUserFiltered, c.wantV6)
		}
		if a.IPv6Checked != c.v6ok {
			t.Errorf("%s: IPv6Checked = %v, want %v", c.name, a.IPv6Checked, c.v6ok)
		}
	}
}

func TestParseRulesChains(t *testing.T) {
	chains, byChain := parseRules(dockerDefault)
	if !reflect.DeepEqual(chains, []string{"DOCKER", "DOCKER-USER"}) {
		t.Errorf("chains = %v", chains)
	}
	if rules := byChain[dockerUserChain]; len(rules) != 1 {
		t.Errorf("DOCKER-USER rules = %v", rules)
	}
}

func TestUFWEnabledInConf(t *testing.T) {
	cases := map[string]bool{
		"# comment\nENABLED=yes\nLOGLEVEL=low\n": true,
		"ENABLED=no\n":                           false,
		`ENABLED="yes"`:                          true,
		"LOGLEVEL=low\n":                         false,
		"":                                       false,
	}
	for conf, want := range cases {
		if got := ufwEnabledInConf(conf); got != want {
			t.Errorf("ufwEnabledInConf(%q) = %v, want %v", conf, got, want)
		}
	}
}

func TestParseDaemonJSON(t *testing.T) {
	hosts, tls := parseDaemonJSON([]byte(`{"hosts": ["unix:///var/run/docker.sock", "tcp://0.0.0.0:2375"], "tlsverify": false}`))
	if !reflect.DeepEqual(hosts, []string{"tcp://0.0.0.0:2375"}) || tls {
		t.Errorf("hosts = %v, tls = %v", hosts, tls)
	}
	if hosts, _ := parseDaemonJSON([]byte(`{"hosts": ["0.0.0.0:2375", "fd://"]}`)); !reflect.DeepEqual(hosts, []string{"tcp://0.0.0.0:2375"}) {
		t.Errorf("a host without a scheme is TCP, got %v", hosts)
	}
	if hosts, _ := parseDaemonJSON([]byte(`not json`)); hosts != nil {
		t.Errorf("invalid JSON must yield no hosts, got %v", hosts)
	}
}

func TestParseDockerdArgs(t *testing.T) {
	cases := []struct {
		args  []string
		hosts []string
		tls   bool
	}{
		{[]string{"-H", "fd://", "--containerd=/run/containerd/containerd.sock"}, nil, false},
		{[]string{"-H", "unix:///var/run/docker.sock", "-H", "tcp://0.0.0.0:2375"}, []string{"tcp://0.0.0.0:2375"}, false},
		{[]string{"--host=tcp://0.0.0.0:2376", "--tlsverify"}, []string{"tcp://0.0.0.0:2376"}, true},
		{[]string{"-H=tcp://10.0.0.1:2375"}, []string{"tcp://10.0.0.1:2375"}, false},
		{[]string{"-H", "0.0.0.0:2375"}, []string{"tcp://0.0.0.0:2375"}, false},
		{[]string{"--host", "tcp://0.0.0.0:2375", "--log-level", "tcp://not-a-host"}, []string{"tcp://0.0.0.0:2375"}, false},
	}
	for _, c := range cases {
		hosts, tls := parseDockerdArgs(c.args)
		if !reflect.DeepEqual(hosts, c.hosts) || tls != c.tls {
			t.Errorf("parseDockerdArgs(%v) = %v, %v; want %v, %v", c.args, hosts, tls, c.hosts, c.tls)
		}
	}
}

func TestMergeListeners(t *testing.T) {
	// tlsverify in daemon.json, listener on the command line, and the reverse
	got := mergeListeners(nil, true, []daemonArgs{{[]string{"tcp://0.0.0.0:2376"}, false}})
	if len(got) != 1 || !got[0].TLSVerify {
		t.Errorf("tlsverify from daemon.json must cover a command line host: %+v", got)
	}
	got = mergeListeners([]string{"tcp://0.0.0.0:2376"}, false, []daemonArgs{{nil, true}})
	if len(got) != 1 || !got[0].TLSVerify {
		t.Errorf("--tlsverify must cover a daemon.json host: %+v", got)
	}
	got = mergeListeners([]string{"tcp://0.0.0.0:2375"}, false, []daemonArgs{{[]string{"tcp://10.0.0.1:2375"}, false}})
	if len(got) != 2 || got[0].TLSVerify || got[1].TLSVerify {
		t.Errorf("no tlsverify anywhere: %+v", got)
	}
}

func TestFiltersFollowsUserChains(t *testing.T) {
	const viaChain = `*filter
:DOCKER-USER - [0:0]
:DOCKER-USER-EXTRA - [0:0]
:MY-FILTER - [0:0]
-A DOCKER-USER -j MY-FILTER
-A DOCKER-USER-EXTRA -j DROP
-A MY-FILTER -s 203.0.113.0/24 -j DROP
COMMIT
`
	if a := analyze(viaChain, "", false, true); !a.DockerUserFiltered || len(a.DockerUserRules) != 1 {
		t.Errorf("a DROP in a chain DOCKER-USER jumps to counts as filtering: %+v", a)
	}
	const otherChainOnly = `*filter
:DOCKER-USER - [0:0]
:DOCKER-USER-EXTRA - [0:0]
-A DOCKER-USER -j RETURN
-A DOCKER-USER-EXTRA -j DROP
COMMIT
`
	if a := analyze(otherChainOnly, "", false, true); a.DockerUserFiltered {
		t.Error("rules of DOCKER-USER-EXTRA must not be read as DOCKER-USER rules")
	}
	const loop = `*filter
:DOCKER-USER - [0:0]
:A - [0:0]
-A DOCKER-USER -j A
-A A -j DOCKER-USER
COMMIT
`
	if a := analyze(loop, "", false, true); a.DockerUserFiltered {
		t.Error("a jump loop without DROP is not filtering")
	}
}

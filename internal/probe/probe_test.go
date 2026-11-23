package probe

import (
	"context"
	"encoding/json"
	"net"
	"net/netip"
	"sync/atomic"
	"testing"
	"time"

	"github.com/adrian13508/skobel/pkg/models"
)

func TestMain(m *testing.M) {
	bannerWait = 150 * time.Millisecond
	m.Run()
}

var loopback = []netip.Addr{netip.MustParseAddr("127.0.0.1")}

// serve starts a TCP server on a random loopback port and returns the port
func serve(t *testing.T, handle func(net.Conn)) int {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				defer func() { _ = conn.Close() }()
				handle(conn)
			}()
		}
	}()
	return ln.Addr().(*net.TCPAddr).Port
}

// reply waits for the client's request, then answers
func reply(response string) func(net.Conn) {
	return func(conn net.Conn) {
		buf := make([]byte, 64)
		if _, err := conn.Read(buf); err != nil {
			return
		}
		_, _ = conn.Write([]byte(response))
	}
}

func probeLocal(port int, expected string) Result {
	return Run(context.Background(), loopback, []Target{{Port: port, Service: expected}},
		Options{Timeout: time.Second, Concurrency: 1})[0]
}

func TestIdentify(t *testing.T) {
	mysqlHandshake := "\x4a\x00\x00\x00\x0a8.0.36\x00rest-of-packet"
	cases := []struct {
		name     string
		handler  func(net.Conn)
		expected string // service the caller expects on that port
		service  string
		note     string
	}{
		{"SSH banner", func(c net.Conn) { _, _ = c.Write([]byte("SSH-2.0-OpenSSH_9.6\r\n")) }, "", "SSH", ""},
		{"MySQL handshake", func(c net.Conn) { _, _ = c.Write([]byte(mysqlHandshake)) }, "MySQL", "MySQL", ""},
		{"SMTP greeting", func(c net.Conn) { _, _ = c.Write([]byte("220 mail.example ESMTP Postfix\r\n")) }, "", "SMTP", ""},
		{"PostgreSQL", reply("N"), "PostgreSQL", "PostgreSQL", "answered the SSL negotiation request"},
		{"Redis without password", reply("+PONG\r\n"), "Redis", "Redis", "answers PING without authentication"},
		{"Redis with password", reply("-NOAUTH Authentication required.\r\n"), "Redis", "Redis", "requires authentication or is in protected mode"},
		{"HTTP", reply("HTTP/1.1 200 OK\r\nServer: nginx/1.27.0\r\n\r\n"), "HTTP", "HTTP", ""},
		{"Docker API", reply("HTTP/1.1 404 Not Found\r\nServer: Docker/27.0 (linux)\r\n\r\n"), "Docker", "Docker API", "unencrypted Docker API"},
		{"TLS port", reply("HTTP/1.0 400 Bad Request\r\n\r\nClient sent an HTTP request to an HTTPS server.\n"), "Docker", "HTTPS", "TLS port, answered a plaintext request with an error"},
		{"silent, nothing expected", reply("ignored"), "", "", "open, service not identified"},
		{"wrong service behind the port", reply("garbage"), "PostgreSQL", "", "open, service not identified"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			r := probeLocal(serve(t, c.handler), c.expected)
			if r.State != StateOpen || r.Service != c.service || r.Note != c.note {
				t.Errorf("got state=%s service=%q note=%q banner=%q; want open, %q, %q",
					r.State, r.Service, r.Note, r.Banner, c.service, c.note)
			}
			if r.Family != "ipv4" || r.Address != "127.0.0.1" {
				t.Errorf("address = %s (%s)", r.Address, r.Family)
			}
		})
	}
}

func TestNothingIsSentWhenServiceIsUnknown(t *testing.T) {
	received := make(chan int, 1)
	port := serve(t, func(c net.Conn) {
		_ = c.SetReadDeadline(time.Now().Add(500 * time.Millisecond))
		n, _ := c.Read(make([]byte, 64))
		received <- n
	})
	probeLocal(port, "")
	if n := <-received; n != 0 {
		t.Errorf("probe sent %d bytes to a service it knows nothing about", n)
	}
}

func TestBannerIsSanitised(t *testing.T) {
	port := serve(t, func(c net.Conn) { _, _ = c.Write([]byte("SSH-2.0-x\x1b[31mred\x07\r\nsecond line")) })
	r := probeLocal(port, "")
	if r.Banner != "SSH-2.0-x.[31mred." {
		t.Errorf("banner = %q, want control characters replaced and only the first line", r.Banner)
	}
}

func TestClosedPort(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := ln.Addr().(*net.TCPAddr).Port
	_ = ln.Close()

	if r := probeLocal(port, ""); r.State != StateClosed {
		t.Errorf("state = %s (%s), want closed", r.State, r.Note)
	}
}

func TestClassifyDialError(t *testing.T) {
	if state, _ := classifyDialError(context.DeadlineExceeded); state != StateFiltered {
		t.Errorf("timeout: state = %s, want filtered", state)
	}
	if state, _ := classifyDialError(&net.OpError{Op: "dial", Err: net.UnknownNetworkError("x")}); state != StateError {
		t.Errorf("unknown error: state = %s, want error", state)
	}
}

func TestConcurrencyLimit(t *testing.T) {
	var active, peak int32
	handler := func(c net.Conn) {
		n := atomic.AddInt32(&active, 1)
		for {
			old := atomic.LoadInt32(&peak)
			if n <= old || atomic.CompareAndSwapInt32(&peak, old, n) {
				break
			}
		}
		time.Sleep(60 * time.Millisecond)
		atomic.AddInt32(&active, -1)
		_, _ = c.Write([]byte("SSH-2.0-test\r\n"))
	}

	var targets []Target
	for i := 0; i < 12; i++ {
		targets = append(targets, Target{Port: serve(t, handler)})
	}
	results := Run(context.Background(), loopback, targets, Options{Timeout: 2 * time.Second, Concurrency: 3})

	if len(results) != 12 {
		t.Fatalf("got %d results, want 12", len(results))
	}
	if p := atomic.LoadInt32(&peak); p > 3 {
		t.Errorf("%d connections were open at once, limit is 3", p)
	}
}

// Zero and oversized options must be clamped: a zero concurrency would
// otherwise block forever on the connection slots.
func TestRunClampsOptions(t *testing.T) {
	port := serve(t, func(net.Conn) {})
	for _, opts := range []Options{{}, {Concurrency: 10000, Timeout: time.Hour}} {
		got := Run(context.Background(), loopback, []Target{{Port: port}}, opts)
		if len(got) != 1 || got[0].State != StateOpen {
			t.Errorf("Run with %+v = %+v, want one open result", opts, got)
		}
	}
}

func TestTargetsFromReport(t *testing.T) {
	report := `{"containers": [
	  {"name": "db", "ports": [
	    {"host_ip": "0.0.0.0", "host_port": "15432", "container_port": "5432", "protocol": "tcp", "exposure_type": "public", "address_scope": "all_interfaces"},
	    {"host_ip": "::", "host_port": "15432", "container_port": "5432", "protocol": "tcp", "exposure_type": "public", "address_scope": "all_interfaces"}]},
	  {"name": "cache", "ports": [
	    {"host_ip": "127.0.0.1", "host_port": "6379", "container_port": "6379", "protocol": "tcp", "exposure_type": "localhost", "address_scope": "localhost"}]},
	  {"name": "vpn-only", "ports": [
	    {"host_ip": "100.101.79.8", "host_port": "9090", "container_port": "9090", "protocol": "tcp", "exposure_type": "specific_ip", "address_scope": "private_or_vpn"}]},
	  {"name": "dns", "ports": [
	    {"host_ip": "0.0.0.0", "host_port": "53", "container_port": "53", "protocol": "udp", "exposure_type": "public", "address_scope": "all_interfaces"}]},
	  {"name": "old-report", "ports": [
	    {"host_ip": "0.0.0.0", "host_port": "8080", "container_port": "80", "protocol": "tcp", "exposure_type": "public"}]}
	]}`
	var scan models.ScanResult
	if err := json.Unmarshal([]byte(report), &scan); err != nil {
		t.Fatal(err)
	}

	targets := TargetsFromReport(scan)
	if len(targets) != 2 {
		t.Fatalf("targets = %+v, want 8080 and 15432 only", targets)
	}
	if targets[0].Port != 8080 || targets[0].Service != "HTTP" || targets[0].Container != "old-report" {
		t.Errorf("first target = %+v", targets[0])
	}
	db := targets[1]
	if db.Port != 15432 || db.Service != "PostgreSQL" || db.Container != "db" || len(db.Bound) != 2 {
		t.Errorf("db target = %+v, want host port 15432, service from container port, both addresses", db)
	}
}

func TestDefaultTargetsMatchPortTable(t *testing.T) {
	targets := DefaultTargets()
	if len(targets) != 38 {
		t.Errorf("default targets = %d, want the 38 ports of the scanner's table", len(targets))
	}
}

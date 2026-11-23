// Package probe checks from the outside which TCP ports of a host accept
// connections. It is meant to be run from a different machine than the one
// being checked, against hosts the user owns.
//
// It never attempts to log in. After connecting it reads what the server
// sends on its own; for a few protocols where the server waits for the
// client it sends one minimal, unauthenticated handshake message.
package probe

import (
	"bytes"
	"context"
	"errors"
	"net"
	"net/netip"
	"sort"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/adrian13508/skobel/internal/analyzer"
	"github.com/adrian13508/skobel/pkg/models"
)

// Hard limits. probe checks a handful of ports on one host; it is not a
// general-purpose scanner.
const (
	MaxPorts       = 200
	MaxAddresses   = 8 // addresses of the one host; ports x addresses connections are made
	MaxConcurrency = 32
	MaxTimeout     = 30 * time.Second
)

// bannerWait is how long to wait for a server-first banner (a var so tests can shorten it)
var bannerWait = 1500 * time.Millisecond

// Port states
const (
	StateOpen        = "open"        // TCP connection established
	StateClosed      = "closed"      // connection refused
	StateFiltered    = "filtered"    // no answer within the timeout
	StateUnreachable = "unreachable" // no route from this machine (for example no IPv6 connectivity)
	StateError       = "error"
)

// Target is one port to check
type Target struct {
	Port      int      `json:"port"`
	Service   string   `json:"expected_service,omitempty"` // from the port table or the scan report
	Container string   `json:"container,omitempty"`        // from the scan report
	Bound     []string `json:"bound,omitempty"`            // host addresses the local scan saw it bound to
}

// Result is the outcome for one address and port
type Result struct {
	Target
	Address string `json:"address"`
	Family  string `json:"family"` // ipv4 or ipv6
	State   string `json:"state"`
	Service string `json:"service,omitempty"` // identified from the server's response
	Banner  string `json:"banner,omitempty"`
	Note    string `json:"note,omitempty"`
}

// Options control pacing
type Options struct {
	Timeout     time.Duration
	Concurrency int
}

// DefaultTargets is the scanner's port table
func DefaultTargets() []Target {
	var targets []Target
	for _, port := range analyzer.KnownPorts() {
		info, _ := analyzer.GetPortInfo(port)
		targets = append(targets, Target{Port: port, Service: info.Service})
	}
	return targets
}

// TargetsFromPorts builds targets from a list of port numbers
func TargetsFromPorts(ports []int) []Target {
	var targets []Target
	seen := map[int]bool{}
	for _, port := range ports {
		if seen[port] {
			continue
		}
		seen[port] = true
		info, _ := analyzer.GetPortInfo(port)
		targets = append(targets, Target{Port: port, Service: info.Service})
	}
	return targets
}

// TargetsFromReport returns the TCP ports a scan report lists as published
// on all interfaces or on a public address: the ones the scan considers
// exposed. Ports bound to localhost or a private address are left out.
func TargetsFromReport(report models.ScanResult) []Target {
	index := map[int]int{}
	var targets []Target
	for _, c := range report.Containers {
		for _, p := range c.Ports {
			if p.Protocol != "tcp" {
				continue
			}
			// address_scope is missing in reports from v0.1.3 and older
			published := p.AddressScope == models.ScopeAllInterfaces || p.AddressScope == models.ScopePublicAddress ||
				(p.AddressScope == "" && p.ExposureType == models.ExposurePublic)
			if !published {
				continue
			}
			port, err := strconv.Atoi(p.HostPort)
			if err != nil || port < 1 || port > 65535 {
				continue
			}
			if i, ok := index[port]; ok {
				targets[i].Bound = append(targets[i].Bound, p.HostIP)
				continue
			}
			service := ""
			if containerPort, err := strconv.Atoi(p.ContainerPort); err == nil {
				if info, ok := analyzer.GetPortInfo(containerPort); ok {
					service = info.Service
				}
			}
			index[port] = len(targets)
			targets = append(targets, Target{Port: port, Service: service, Container: c.Name, Bound: []string{p.HostIP}})
		}
	}
	sort.Slice(targets, func(i, j int) bool { return targets[i].Port < targets[j].Port })
	return targets
}

// Run probes every target on every address, at most opts.Concurrency
// connections at a time. Results are sorted by port, then address.
func Run(ctx context.Context, addrs []netip.Addr, targets []Target, opts Options) []Result {
	if opts.Concurrency < 1 {
		opts.Concurrency = 1
	}
	if opts.Concurrency > MaxConcurrency {
		opts.Concurrency = MaxConcurrency
	}
	if opts.Timeout <= 0 || opts.Timeout > MaxTimeout {
		opts.Timeout = MaxTimeout
	}

	results := make([]Result, 0, len(addrs)*len(targets))
	var mu sync.Mutex
	var wg sync.WaitGroup
	slots := make(chan struct{}, opts.Concurrency)

	for _, target := range targets {
		for _, addr := range addrs {
			wg.Add(1)
			slots <- struct{}{}
			go func(addr netip.Addr, target Target) {
				defer wg.Done()
				defer func() { <-slots }()
				r := probeOne(ctx, addr, target, opts.Timeout)
				mu.Lock()
				results = append(results, r)
				mu.Unlock()
			}(addr, target)
		}
	}
	wg.Wait()

	sort.Slice(results, func(i, j int) bool {
		if results[i].Port != results[j].Port {
			return results[i].Port < results[j].Port
		}
		return results[i].Address < results[j].Address
	})
	return results
}

func probeOne(ctx context.Context, addr netip.Addr, target Target, timeout time.Duration) Result {
	result := Result{Target: target, Address: addr.String(), Family: "ipv4"}
	if addr.Is6() && !addr.Is4In6() {
		result.Family = "ipv6"
	}

	dialer := net.Dialer{Timeout: timeout}
	conn, err := dialer.DialContext(ctx, "tcp", netip.AddrPortFrom(addr, uint16(target.Port)).String())
	if err != nil {
		result.State, result.Note = classifyDialError(err)
		return result
	}
	defer func() { _ = conn.Close() }()

	result.State = StateOpen
	result.Service, result.Banner, result.Note = identify(conn, target.Service, timeout)
	return result
}

func classifyDialError(err error) (state, note string) {
	var netErr net.Error
	switch {
	// 10061 is WSAECONNREFUSED: on Windows a refusal does not match
	// syscall.ECONNREFUSED. Not tested on Windows.
	case errors.Is(err, syscall.ECONNREFUSED), errors.Is(err, syscall.Errno(10061)):
		return StateClosed, "connection refused"
	case errors.Is(err, syscall.ENETUNREACH), errors.Is(err, syscall.EHOSTUNREACH), errors.Is(err, syscall.EADDRNOTAVAIL):
		return StateUnreachable, "no route from this machine"
	case errors.As(err, &netErr) && netErr.Timeout(), errors.Is(err, context.DeadlineExceeded):
		return StateFiltered, "no answer"
	default:
		return StateError, err.Error()
	}
}

// identify recognises the service on an open connection. It first waits for
// a banner the server sends unprompted. If there is none and the expected
// service is one that waits for the client, it sends that protocol's
// smallest unauthenticated message. It never sends credentials.
func identify(conn net.Conn, expected string, timeout time.Duration) (service, banner, note string) {
	wait := bannerWait
	if timeout < wait {
		wait = timeout
	}

	if data := read(conn, wait); len(data) > 0 {
		service = fromBanner(data)
		if service == "MySQL" && data[4] == 0x0a {
			// The handshake packet carries the server version as a NUL-terminated string
			version, _, _ := bytes.Cut(data[5:], []byte{0})
			return service, printable(version), ""
		}
		if service == "MySQL" && data[4] == 0xff && len(data) > 7 {
			// Error packet (for example "Host ... is not allowed to connect"):
			// the message follows the marker and a two-byte error code
			return service, printable(data[7:]), ""
		}
		return service, printable(data), ""
	}

	switch handshakeFor(expected) {
	case "postgres":
		// SSLRequest: length 8, code 80877103. The server answers with one byte.
		data := exchange(conn, []byte{0, 0, 0, 8, 0x04, 0xd2, 0x16, 0x2f}, wait)
		if len(data) == 1 && (data[0] == 'S' || data[0] == 'N') {
			return "PostgreSQL", "", "answered the SSL negotiation request"
		}
	case "redis":
		data := exchange(conn, []byte("PING\r\n"), wait)
		switch {
		case bytes.HasPrefix(data, []byte("+PONG")):
			return "Redis", printable(data), "answers PING without authentication"
		case bytes.HasPrefix(data, []byte("-NOAUTH")), bytes.HasPrefix(data, []byte("-ERR")), bytes.HasPrefix(data, []byte("-DENIED")):
			return "Redis", printable(data), "requires authentication or is in protected mode"
		}
	case "http":
		data := exchange(conn, []byte("HEAD / HTTP/1.0\r\n\r\n"), wait)
		if bytes.HasPrefix(data, []byte("HTTP/")) {
			if bytes.Contains(data, []byte("HTTPS server")) {
				// Go's TLS listeners answer a plaintext request with
				// "400 Client sent an HTTP request to an HTTPS server"
				return "HTTPS", "", "TLS port, answered a plaintext request with an error"
			}
			server := header(data, "Server")
			if strings.HasPrefix(server, "Docker/") {
				return "Docker API", printable([]byte(server)), "unencrypted Docker API"
			}
			return "HTTP", printable([]byte(firstLine(data) + " " + server)), ""
		}
	}
	return "", "", "open, service not identified"
}

// handshakeFor picks the client-first handshake for an expected service.
// Services that normally speak TLS (HTTPS, Kubernetes API) get none: a
// plaintext request would tell us nothing. Docker gets the HTTP request on
// both 2375 and 2376, because an answer on either means an open API.
func handshakeFor(expected string) string {
	switch expected {
	case "PostgreSQL":
		return "postgres"
	case "Redis":
		return "redis"
	case "HTTP", "HTTP Alt", "Grafana", "Prometheus", "Portainer", "Admin Panel", "Node.js", "Flask",
		"Elasticsearch", "CouchDB", "InfluxDB", "Docker":
		return "http"
	}
	return ""
}

// fromBanner recognises protocols where the server speaks first
func fromBanner(data []byte) string {
	switch {
	case bytes.HasPrefix(data, []byte("SSH-")):
		return "SSH"
	case bytes.HasPrefix(data, []byte("RFB ")):
		return "VNC"
	case bytes.HasPrefix(data, []byte("220")) && bytes.Contains(bytes.ToUpper(data), []byte("SMTP")):
		return "SMTP"
	case bytes.HasPrefix(data, []byte("220")):
		return "FTP or SMTP"
	case len(data) > 5 && data[3] == 0 && (data[4] == 0x0a || data[4] == 0xff):
		// MySQL packet: 3-byte length, sequence 0, then protocol 10 or an error
		return "MySQL"
	case bytes.HasPrefix(data, []byte("HTTP/")):
		return "HTTP"
	}
	return ""
}

func exchange(conn net.Conn, request []byte, wait time.Duration) []byte {
	_ = conn.SetWriteDeadline(time.Now().Add(wait))
	if _, err := conn.Write(request); err != nil {
		return nil
	}
	return read(conn, wait)
}

func read(conn net.Conn, wait time.Duration) []byte {
	_ = conn.SetReadDeadline(time.Now().Add(wait))
	buf := make([]byte, 512)
	n, _ := conn.Read(buf)
	return buf[:n]
}

func firstLine(data []byte) string {
	line, _, _ := bytes.Cut(data, []byte("\n"))
	return strings.TrimSpace(string(line))
}

func header(data []byte, name string) string {
	for _, line := range strings.Split(string(data), "\n") {
		key, value, ok := strings.Cut(line, ":")
		if ok && strings.EqualFold(strings.TrimSpace(key), name) {
			return strings.TrimSpace(value)
		}
	}
	return ""
}

// printable keeps the first line of a banner, with non-printable bytes
// replaced, capped at 80 characters. Banners come from an untrusted server
// and are shown in a terminal.
func printable(data []byte) string {
	var b strings.Builder
	for _, c := range data {
		if c == '\n' || c == '\r' || b.Len() >= 80 {
			break
		}
		if c < 0x20 || c > 0x7e {
			c = '.'
		}
		b.WriteByte(c)
	}
	return strings.TrimSpace(b.String())
}

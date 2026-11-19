package main

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/adrian13508/dockershield/internal/probe"
	"github.com/adrian13508/dockershield/pkg/models"
	"github.com/spf13/cobra"
)

var probeCmd = &cobra.Command{
	Use:   "probe <host>",
	Short: "Check from another machine which ports of your server accept connections",
	Long: `Connects to TCP ports of one host and reports which ones answer.

Run it from a DIFFERENT machine than the server you are checking. A scan on
the server shows what is published; probe shows what an outside client can
actually reach, after every firewall on the way.

Only probe servers you own or are authorized to test. Connecting to ports of
other people's systems may be illegal where you live. The first time you
probe a host you must pass --i-own-this-host.

What probe does: one TCP connection per port and address, a short wait for a
banner, and for PostgreSQL, Redis and HTTP one minimal unauthenticated
handshake message. It never tries to log in.

Ports: the scanner's built-in list by default, the ports a scan found
published with --from-report, or an explicit list with --ports.

Example:
  # on the server
  sudo dockershield scan --json > report.json
  # on your laptop
  dockershield probe my-server.example.com --from-report report.json --i-own-this-host`,
	Args: cobra.ExactArgs(1),
	RunE: runProbe,
}

var (
	probeFromReport  string
	probePorts       string
	probeTimeout     time.Duration
	probeConcurrency int
	probeJSON        bool
	probeConfirm     bool
	probeFailOnOpen  bool
	probeShowAll     bool
	probeIPv4Only    bool
	probeIPv6Only    bool
)

func init() {
	rootCmd.AddCommand(probeCmd)
	f := probeCmd.Flags()
	f.StringVar(&probeFromReport, "from-report", "", "Probe the ports that this scan report (scan --json) lists as published")
	f.StringVar(&probePorts, "ports", "", "Comma-separated list of TCP ports to probe")
	f.DurationVar(&probeTimeout, "timeout", 3*time.Second, "Connection timeout per port (max 30s)")
	f.IntVar(&probeConcurrency, "concurrency", 10, fmt.Sprintf("Connections open at the same time (max %d)", probe.MaxConcurrency))
	f.BoolVar(&probeJSON, "json", false, "Output results in JSON format")
	f.BoolVar(&probeConfirm, "i-own-this-host", false, "Confirm that you own the host or are authorized to test it (required once per host)")
	f.BoolVar(&probeFailOnOpen, "fail-on-open", false, "Exit with code 2 when at least one probed port is open")
	f.BoolVar(&probeShowAll, "all", false, "Also list closed and filtered ports (always listed with --from-report)")
	f.BoolVarP(&probeIPv4Only, "ipv4", "4", false, "Probe IPv4 addresses only")
	f.BoolVarP(&probeIPv6Only, "ipv6", "6", false, "Probe IPv6 addresses only")
	probeCmd.MarkFlagsMutuallyExclusive("from-report", "ports")
	probeCmd.MarkFlagsMutuallyExclusive("ipv4", "ipv6")
}

// probeLine is one result plus the verdict that combines it with the local scan
type probeLine struct {
	probe.Result
	Verdict string `json:"verdict"`
}

type probeOutput struct {
	Host       string      `json:"host"`
	Addresses  []string    `json:"addresses"`
	Timestamp  time.Time   `json:"timestamp"`
	FromReport bool        `json:"from_report"`
	Results    []probeLine `json:"results"`
}

func runProbe(cmd *cobra.Command, args []string) error {
	host := args[0]
	if strings.ContainsAny(host, "/ ,") {
		return fmt.Errorf("probe takes exactly one host name or IP address, not a range or list")
	}
	if probeTimeout <= 0 || probeTimeout > probe.MaxTimeout {
		return fmt.Errorf("--timeout must be between 1ms and %s", probe.MaxTimeout)
	}
	if probeConcurrency < 1 || probeConcurrency > probe.MaxConcurrency {
		return fmt.Errorf("--concurrency must be between 1 and %d", probe.MaxConcurrency)
	}

	targets, err := probeTargets()
	if err != nil {
		return err
	}
	if len(targets) == 0 {
		return fmt.Errorf("nothing to probe: the report lists no TCP port published on all interfaces or a public address")
	}
	if len(targets) > probe.MaxPorts {
		return fmt.Errorf("%d ports requested, the limit is %d per run", len(targets), probe.MaxPorts)
	}

	// Ownership confirmation, remembered per host
	confirmedFile, err := probeConfirmedFile()
	if err != nil {
		return err
	}
	if !isConfirmed(confirmedFile, host) {
		if !probeConfirm {
			return fmt.Errorf(`refusing to probe %s without confirmation.

probe opens connections to ports on that host. Only do this for servers you
own or are authorized to test; probing other people's systems may be illegal.

If %s is yours, run the command again with --i-own-this-host.
This is asked once per host and remembered in %s`, host, host, confirmedFile)
		}
		if err := confirmHost(confirmedFile, host); err != nil {
			fmt.Fprintf(os.Stderr, "Warning: could not remember the confirmation: %v\n", err)
		}
	}

	ctx := context.Background()
	addrs, err := resolve(ctx, host, probeIPv4Only, probeIPv6Only)
	if err != nil {
		return err
	}

	if !probeJSON {
		fmt.Printf("Probing %s (%s) from this machine\n", host, joinAddrs(addrs))
		fmt.Printf("%d port(s), timeout %s, up to %d connections at a time\n\n", len(targets), probeTimeout, probeConcurrency)
	}

	results := probe.Run(ctx, addrs, targets, probe.Options{Timeout: probeTimeout, Concurrency: probeConcurrency})

	fromReport := probeFromReport != ""
	out := probeOutput{Host: host, Timestamp: time.Now(), FromReport: fromReport}
	for _, a := range addrs {
		out.Addresses = append(out.Addresses, a.String())
	}
	open := 0
	for _, r := range results {
		if r.State == probe.StateOpen {
			open++
		}
		out.Results = append(out.Results, probeLine{Result: r, Verdict: verdict(r, fromReport)})
	}

	if probeJSON {
		data, err := json.MarshalIndent(out, "", "  ")
		if err != nil {
			return err
		}
		fmt.Println(string(data))
	} else {
		printProbe(out, probeShowAll || fromReport)
	}

	if probeFailOnOpen && open > 0 {
		os.Exit(2)
	}
	return nil
}

func probeTargets() ([]probe.Target, error) {
	switch {
	case probeFromReport != "":
		data, err := os.ReadFile(probeFromReport)
		if err != nil {
			return nil, fmt.Errorf("cannot read report: %w", err)
		}
		var report models.ScanResult
		if err := json.Unmarshal(data, &report); err != nil {
			return nil, fmt.Errorf("%s is not a scan report (expected the output of `dockershield scan --json`): %w", probeFromReport, err)
		}
		return probe.TargetsFromReport(report), nil
	case probePorts != "":
		ports, err := parsePorts(probePorts)
		if err != nil {
			return nil, err
		}
		return probe.TargetsFromPorts(ports), nil
	default:
		return probe.DefaultTargets(), nil
	}
}

func parsePorts(list string) ([]int, error) {
	var ports []int
	for _, field := range strings.Split(list, ",") {
		port, err := strconv.Atoi(strings.TrimSpace(field))
		if err != nil || port < 1 || port > 65535 {
			return nil, fmt.Errorf("invalid port %q in --ports (ranges are not supported)", field)
		}
		ports = append(ports, port)
	}
	return ports, nil
}

// resolve returns the addresses to probe for a host name or IP literal
func resolve(ctx context.Context, host string, v4Only, v6Only bool) ([]netip.Addr, error) {
	var addrs []netip.Addr
	if addr, err := netip.ParseAddr(host); err == nil {
		addrs = []netip.Addr{addr}
	} else {
		ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
		defer cancel()
		addrs, err = net.DefaultResolver.LookupNetIP(ctx, "ip", host)
		if err != nil {
			return nil, fmt.Errorf("cannot resolve %s: %w", host, err)
		}
	}

	var kept []netip.Addr
	seen := map[netip.Addr]bool{}
	for _, a := range addrs {
		a = a.Unmap()
		if seen[a] || (v4Only && !a.Is4()) || (v6Only && a.Is4()) {
			continue
		}
		seen[a] = true
		kept = append(kept, a)
	}
	if len(kept) == 0 {
		return nil, fmt.Errorf("%s has no address of the requested family", host)
	}
	return kept, nil
}

// verdict combines what the scan saw on the server (when a report was given)
// with what this machine could reach.
func verdict(r probe.Result, fromReport bool) string {
	if !fromReport {
		return r.State
	}
	switch r.State {
	case probe.StateOpen:
		return "published and confirmed from outside"
	case probe.StateFiltered:
		return "published but blocked on the way (no answer)"
	case probe.StateClosed:
		return "published but refused from here"
	case probe.StateUnreachable:
		return "not tested: no route from this machine"
	default:
		return "not tested: " + r.Note
	}
}

func printProbe(out probeOutput, showAll bool) {
	counts := map[string]int{}
	lastPort := 0
	for _, line := range out.Results {
		counts[line.State]++
		if !showAll && line.State != probe.StateOpen {
			continue
		}
		if line.Port != lastPort {
			lastPort = line.Port
			fmt.Printf("%d/tcp%s\n", line.Port, describeTarget(line.Target))
		}
		detail := line.Verdict
		if line.State == probe.StateOpen {
			var parts []string
			if line.Service != "" {
				parts = append(parts, line.Service)
			}
			if line.Banner != "" {
				parts = append(parts, strconv.Quote(line.Banner))
			}
			if line.Note != "" {
				parts = append(parts, line.Note)
			}
			if len(parts) > 0 {
				detail += ": " + strings.Join(parts, ", ")
			}
		}
		fmt.Printf("  %-39s %s\n", line.Address, detail)
	}

	fmt.Printf("\n%d open, %d closed, %d filtered", counts[probe.StateOpen], counts[probe.StateClosed], counts[probe.StateFiltered])
	if n := counts[probe.StateUnreachable] + counts[probe.StateError]; n > 0 {
		fmt.Printf(", %d not tested", n)
	}
	fmt.Println()
	if !showAll && counts[probe.StateOpen] < len(out.Results) {
		fmt.Println("Closed and filtered ports are not listed. Use --all to see them.")
	}
	fmt.Println("\nThis is the view from this machine only. Another network may be treated differently by a firewall.")
}

func describeTarget(t probe.Target) string {
	var parts []string
	if t.Container != "" {
		parts = append(parts, "container "+t.Container)
	}
	if t.Service != "" {
		parts = append(parts, "expected "+t.Service)
	}
	if len(t.Bound) > 0 {
		parts = append(parts, "bound on "+strings.Join(t.Bound, ", "))
	}
	if len(parts) == 0 {
		return ""
	}
	return "  (" + strings.Join(parts, "; ") + ")"
}

func joinAddrs(addrs []netip.Addr) string {
	var s []string
	for _, a := range addrs {
		s = append(s, a.String())
	}
	return strings.Join(s, ", ")
}

func probeConfirmedFile() (string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", fmt.Errorf("cannot find the home directory: %w", err)
	}
	return filepath.Join(home, ".dockershield", "probe_hosts"), nil
}

// isConfirmed reports whether the user has confirmed ownership of host before
func isConfirmed(file, host string) bool {
	f, err := os.Open(file)
	if err != nil {
		return false
	}
	defer f.Close()
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		if strings.EqualFold(strings.TrimSpace(scanner.Text()), host) {
			return true
		}
	}
	return false
}

// confirmHost records that the user confirmed ownership of host
func confirmHost(file, host string) error {
	if err := os.MkdirAll(filepath.Dir(file), 0700); err != nil {
		return err
	}
	f, err := os.OpenFile(file, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0600)
	if err != nil {
		return err
	}
	if _, err := fmt.Fprintln(f, host); err != nil {
		_ = f.Close()
		return err
	}
	return f.Close()
}

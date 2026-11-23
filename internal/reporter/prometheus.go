package reporter

import (
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/adrian13508/skobel/pkg/models"
)

// PrometheusReporter renders scan results in the Prometheus text exposition
// format, for use with the node_exporter textfile collector:
//
//	skobel scan --prometheus > /var/lib/node_exporter/textfile/skobel.prom
type PrometheusReporter struct{}

// NewPrometheusReporter creates a new Prometheus reporter
func NewPrometheusReporter() *PrometheusReporter {
	return &PrometheusReporter{}
}

// labelEscaper escapes label values per the Prometheus text format
// (backslash, double quote, and newline).
var labelEscaper = strings.NewReplacer(`\`, `\\`, `"`, `\"`, "\n", `\n`)

// Generate creates a Prometheus textfile report from scan results.
// All metrics are gauges; hostname is intentionally omitted as a label
// because node_exporter already attaches instance identity.
func (r *PrometheusReporter) Generate(
	containers []models.Container,
	firewall *models.FirewallInfo,
	riskSummary models.RiskSummary,
	score int,
) []byte {
	var b strings.Builder

	header(&b, "skobel_security_score", "Overall security score (0-100, higher is better).")
	fmt.Fprintf(&b, "skobel_security_score %d\n", score)

	header(&b, "skobel_risks", "Detected risks by severity: published ports, container settings, firewall and daemon findings.")
	for _, s := range []struct {
		severity string
		count    int
	}{
		{"critical", riskSummary.Critical},
		{"high", riskSummary.High},
		{"medium", riskSummary.Medium},
		{"low", riskSummary.Low},
		{"info", riskSummary.Info},
	} {
		fmt.Fprintf(&b, "skobel_risks{severity=\"%s\"} %d\n", s.severity, s.count)
	}

	header(&b, "skobel_containers", "Number of containers by state.")
	states := map[string]int{}
	for _, c := range containers {
		states[c.State]++
	}
	stateNames := make([]string, 0, len(states))
	for s := range states {
		stateNames = append(stateNames, s)
	}
	sort.Strings(stateNames)
	for _, s := range stateNames {
		fmt.Fprintf(&b, "skobel_containers{state=\"%s\"} %d\n", labelEscaper.Replace(s), states[s])
	}

	header(&b, "skobel_exposed_port", "Container port published on all interfaces or on a public address. Value is always 1; alert on the labels.")
	// A port published on IPv4 and IPv6 yields two bindings with the same
	// labels; a duplicate series makes the textfile collector reject the file.
	seen := map[string]bool{}
	for _, c := range containers {
		for _, p := range c.Ports {
			if p.ExposureType != models.ExposurePublic && p.AddressScope != models.ScopePublicAddress {
				continue
			}
			line := fmt.Sprintf("skobel_exposed_port{container=\"%s\",port=\"%s\",protocol=\"%s\",severity=\"%s\"} 1\n",
				labelEscaper.Replace(c.Name), labelEscaper.Replace(p.HostPort),
				labelEscaper.Replace(p.Protocol), labelEscaper.Replace(string(p.RiskLevel)))
			if !seen[line] {
				seen[line] = true
				b.WriteString(line)
			}
		}
	}

	if firewall != nil {
		header(&b, "skobel_firewall_checked", "Whether iptables could be read (1) or not (0). When 0, the UFW metrics are omitted.")
		fmt.Fprintf(&b, "skobel_firewall_checked %d\n", boolToInt(firewall.Checked))
	}

	if firewall != nil && firewall.Checked {
		header(&b, "skobel_ufw_active", "Whether UFW is active (1) or not (0).")
		fmt.Fprintf(&b, "skobel_ufw_active %d\n", boolToInt(firewall.UFWActive))

		header(&b, "skobel_docker_bypassing_ufw", "Whether Docker is bypassing UFW rules (1) or not (0).")
		fmt.Fprintf(&b, "skobel_docker_bypassing_ufw %d\n", boolToInt(firewall.DockerBypassingUFW))
	}

	header(&b, "skobel_last_scan_timestamp_seconds", "Unix timestamp of the last completed scan.")
	fmt.Fprintf(&b, "skobel_last_scan_timestamp_seconds %d\n", time.Now().Unix())

	return []byte(b.String())
}

// WriteToFile writes Prometheus output to a file
func (r *PrometheusReporter) WriteToFile(data []byte, path string) error {
	return writeReportFile(data, path)
}

// Print outputs metrics to stdout
func (r *PrometheusReporter) Print(data []byte) {
	fmt.Print(string(data))
}

// header writes the HELP and TYPE lines for a gauge metric
func header(b *strings.Builder, name, help string) {
	fmt.Fprintf(b, "# HELP %s %s\n# TYPE %s gauge\n", name, help, name)
}

func boolToInt(v bool) int {
	if v {
		return 1
	}
	return 0
}

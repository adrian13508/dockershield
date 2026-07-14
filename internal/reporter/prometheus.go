package reporter

import (
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/adrian13508/dockershield/pkg/models"
)

// PrometheusReporter renders scan results in the Prometheus text exposition
// format, for use with the node_exporter textfile collector:
//
//	dockershield scan --prometheus > /var/lib/node_exporter/textfile/dockershield.prom
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

	header(&b, "dockershield_security_score", "Overall security score (0-100, higher is better).")
	fmt.Fprintf(&b, "dockershield_security_score %d\n", score)

	header(&b, "dockershield_risks", "Detected risks by severity across all containers.")
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
		fmt.Fprintf(&b, "dockershield_risks{severity=\"%s\"} %d\n", s.severity, s.count)
	}

	header(&b, "dockershield_containers", "Number of containers by state.")
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
		fmt.Fprintf(&b, "dockershield_containers{state=\"%s\"} %d\n", labelEscaper.Replace(s), states[s])
	}

	header(&b, "dockershield_exposed_port", "Container port published on a public interface (0.0.0.0 or ::). Value is always 1; alert on the labels.")
	for _, c := range containers {
		for _, p := range c.Ports {
			if p.ExposureType != models.ExposurePublic {
				continue
			}
			fmt.Fprintf(&b, "dockershield_exposed_port{container=\"%s\",port=\"%s\",protocol=\"%s\",severity=\"%s\"} 1\n",
				labelEscaper.Replace(c.Name), labelEscaper.Replace(p.HostPort),
				labelEscaper.Replace(p.Protocol), labelEscaper.Replace(string(p.RiskLevel)))
		}
	}

	if firewall != nil {
		header(&b, "dockershield_ufw_active", "Whether UFW is active (1) or not (0).")
		fmt.Fprintf(&b, "dockershield_ufw_active %d\n", boolToInt(firewall.UFWActive))

		header(&b, "dockershield_docker_bypassing_ufw", "Whether Docker is bypassing UFW rules (1) or not (0).")
		fmt.Fprintf(&b, "dockershield_docker_bypassing_ufw %d\n", boolToInt(firewall.DockerBypassingUFW))
	}

	header(&b, "dockershield_last_scan_timestamp_seconds", "Unix timestamp of the last completed scan.")
	fmt.Fprintf(&b, "dockershield_last_scan_timestamp_seconds %d\n", time.Now().Unix())

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

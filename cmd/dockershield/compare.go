package main

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"

	"github.com/adrian13508/dockershield/internal/analyzer"
	"github.com/adrian13508/dockershield/pkg/models"
	"github.com/spf13/cobra"
)

var compareFailOnNew bool

var compareCmd = &cobra.Command{
	Use:   "compare <before.json> <after.json>",
	Short: "Compare two scan reports (before and after a change)",
	Long: `Compares two reports written by 'dockershield scan --json' and lists which
findings were resolved, which are new and which remain.

Example:
  sudo dockershield scan --json > before.json
  # apply fixes
  sudo dockershield scan --json > after.json
  dockershield compare before.json after.json`,
	Args: cobra.ExactArgs(2),
	RunE: func(cmd *cobra.Command, args []string) error {
		before, err := loadReport(args[0])
		if err != nil {
			return err
		}
		after, err := loadReport(args[1])
		if err != nil {
			return err
		}
		diff := analyzer.Compare(before, after)
		fmt.Print(formatDiff(before, after, diff))
		if compareFailOnNew && len(diff.New) > 0 {
			os.Exit(2)
		}
		return nil
	},
}

func init() {
	rootCmd.AddCommand(compareCmd)
	compareCmd.Flags().BoolVar(&compareFailOnNew, "fail-on-new", false, "Exit with code 2 when the second report has findings the first one did not")
}

func loadReport(path string) (models.ScanResult, error) {
	var report models.ScanResult
	data, err := os.ReadFile(path)
	if err != nil {
		return report, fmt.Errorf("cannot read report: %w", err)
	}
	if err := json.Unmarshal(data, &report); err != nil {
		return report, fmt.Errorf("%s is not a scan report (expected the output of `dockershield scan --json`): %w", path, err)
	}
	if report.Timestamp.IsZero() {
		return report, fmt.Errorf("%s is not a scan report (expected the output of `dockershield scan --json`)", path)
	}
	return report, nil
}

func formatDiff(before, after models.ScanResult, d analyzer.Diff) string {
	w := &strings.Builder{}
	const layout = "2006-01-02 15:04"
	fmt.Fprintf(w, "Host:   %s\n", after.Hostname)
	if before.Hostname != after.Hostname {
		fmt.Fprintf(w, "        note: the first report is from a different host (%s)\n", before.Hostname)
	}
	fmt.Fprintf(w, "Before: %s   score %d\n", before.Timestamp.Format(layout), d.OldScore)
	fmt.Fprintf(w, "After:  %s   score %d (%+d)\n", after.Timestamp.Format(layout), d.NewScore, d.NewScore-d.OldScore)
	if d.Recomputed {
		fmt.Fprintln(w, "\nA report from v0.1.3 or older has no findings list. Its container ports were rated")
		fmt.Fprintln(w, "again with the current rules; firewall and daemon findings are not available for it.")
	}

	section := func(title string, findings []models.Finding) {
		fmt.Fprintf(w, "\n%s (%d)\n", title, len(findings))
		for _, f := range findings {
			subject := f.Container
			if f.Port != "" {
				subject = strings.TrimSpace(subject + " " + f.Port)
			}
			if subject != "" {
				subject += ": "
			}
			fmt.Fprintf(w, "  %-10s %s%s\n", getRiskIcon(f.Severity), subject, f.Title)
		}
	}
	section("Resolved", d.Resolved)
	section("New", d.New)
	section("Still present", d.Remaining)
	return w.String()
}

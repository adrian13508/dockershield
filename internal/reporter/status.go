package reporter

import (
	"encoding/json"
	"fmt"
	"time"

	"github.com/adrian13508/dockershield/pkg/models"
	"github.com/fatih/color"
)

// StatusSummary represents a quick status summary
type StatusSummary struct {
	LastScan      time.Time `json:"last_scan"`
	AgeMinutes    int       `json:"age_minutes"`
	AgeHuman      string    `json:"age_human"`
	Containers    int       `json:"containers"`
	Critical      int       `json:"critical"`
	High          int       `json:"high"`
	Medium        int       `json:"medium"`
	Low           int       `json:"low"`
	OverallScore  int       `json:"overall_score"`
	NewContainers int       `json:"new_containers,omitempty"`
}

// FormatStatusTerminal displays status summary in terminal
func FormatStatusTerminal(result *models.ScanResult) {
	// Color functions
	green := color.New(color.FgGreen).SprintFunc()
	yellow := color.New(color.FgYellow).SprintFunc()
	red := color.New(color.FgRed).SprintFunc()
	cyan := color.New(color.FgCyan, color.Bold).SprintFunc()
	white := color.New(color.FgWhite, color.Bold).SprintFunc()

	// Calculate age
	age := time.Since(result.Timestamp)
	ageStr := formatDuration(age)

	fmt.Println("┌────────────────────────────────────────────┐")
	fmt.Printf("│  %s                 │\n", cyan("DockerShield Status"))
	fmt.Println("├────────────────────────────────────────────┤")
	fmt.Printf("│  Last Scan: %s                     │\n", white(ageStr))
	fmt.Printf("│  Containers: %s running                   │\n", white(fmt.Sprintf("%d", len(result.Containers))))
	fmt.Println("│                                            │")

	// Risk summary
	summary := result.RiskSummary
	if summary.Critical > 0 {
		fmt.Printf("│  %s Critical: %s                           │\n", red("🔴"), white(fmt.Sprintf("%d", summary.Critical)))
	}
	if summary.High > 0 {
		fmt.Printf("│  %s High: %s                              │\n", yellow("⚠️ "), white(fmt.Sprintf("%d", summary.High)))
	}
	if summary.Medium > 0 {
		fmt.Printf("│  %s Medium: %s                            │\n", yellow("🟡"), white(fmt.Sprintf("%d", summary.Medium)))
	}
	if summary.Low > 0 {
		fmt.Printf("│  %s Low: %s                               │\n", green("ℹ️ "), white(fmt.Sprintf("%d", summary.Low)))
	}

	// If no issues
	if summary.Critical == 0 && summary.High == 0 && summary.Medium == 0 {
		fmt.Printf("│  %s                      │\n", green("✅ No critical issues found!"))
	}

	// Security score
	fmt.Println("│                                            │")
	scoreColor := green
	if result.OverallScore < 50 {
		scoreColor = red
	} else if result.OverallScore < 70 {
		scoreColor = yellow
	}
	fmt.Printf("│  Security Score: %s                  │\n", scoreColor(fmt.Sprintf("%d/100", result.OverallScore)))

	fmt.Println("└────────────────────────────────────────────┘")
	fmt.Println()

	// Show if stale
	if age > 24*time.Hour {
		fmt.Printf("%s\n", yellow("⚠️  Last scan was more than 24 hours ago (stale)."))
		fmt.Println("Run 'dockershield scan' for fresh data.")
		fmt.Println()
	} else {
		fmt.Println("Run 'dockershield scan' for detailed analysis.")
	}
}

// FormatStatusJSON outputs status summary as JSON
func FormatStatusJSON(result *models.ScanResult) error {
	age := time.Since(result.Timestamp)

	summary := StatusSummary{
		LastScan:     result.Timestamp,
		AgeMinutes:   int(age.Minutes()),
		AgeHuman:     formatDuration(age),
		Containers:   len(result.Containers),
		Critical:     result.RiskSummary.Critical,
		High:         result.RiskSummary.High,
		Medium:       result.RiskSummary.Medium,
		Low:          result.RiskSummary.Low,
		OverallScore: result.OverallScore,
	}

	data, err := json.MarshalIndent(summary, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal JSON: %w", err)
	}

	fmt.Println(string(data))
	return nil
}

// formatDuration formats a duration into a human-readable string
func formatDuration(d time.Duration) string {
	if d < time.Minute {
		return "just now"
	}
	if d < time.Hour {
		minutes := int(d.Minutes())
		if minutes == 1 {
			return "1 minute ago"
		}
		return fmt.Sprintf("%d minutes ago", minutes)
	}
	if d < 24*time.Hour {
		hours := int(d.Hours())
		if hours == 1 {
			return "1 hour ago"
		}
		return fmt.Sprintf("%d hours ago", hours)
	}
	days := int(d.Hours() / 24)
	if days == 1 {
		return "1 day ago"
	}
	return fmt.Sprintf("%d days ago", days)
}

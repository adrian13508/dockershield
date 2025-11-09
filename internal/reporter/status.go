package reporter

import (
	"encoding/json"
	"fmt"
	"regexp"
	"strings"
	"time"

	"github.com/adrian13508/dockershield/pkg/models"
	"github.com/fatih/color"
)

// stripAnsi removes ANSI color codes to get actual text length
func stripAnsi(str string) string {
	re := regexp.MustCompile(`\x1b\[[0-9;]*m`)
	return re.ReplaceAllString(str, "")
}

// padTableLine pads a line to fit within a box of given width
func padTableLine(content string, width int) string {
	plainText := stripAnsi(content)
	runes := []rune(plainText)

	// Count emojis - they typically display as 2 characters wide
	emojiCount := 0
	for _, r := range runes {
		if (r >= 0x1F300 && r <= 0x1F9FF) || (r >= 0x2600 && r <= 0x26FF) {
			emojiCount++
		}
	}

	visualWidth := len(runes) + emojiCount
	paddingNeeded := width - visualWidth
	if paddingNeeded < 0 {
		paddingNeeded = 0
	}

	return content + strings.Repeat(" ", paddingNeeded)
}

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

	const boxWidth = 42

	fmt.Println("┌────────────────────────────────────────────┐")
	fmt.Printf("│  %s  │\n", padTableLine(cyan("DockerShield Status"), boxWidth-2))
	fmt.Println("├────────────────────────────────────────────┤")
	fmt.Printf("│  %s  │\n", padTableLine(fmt.Sprintf("Last Scan: %s", white(ageStr)), boxWidth-2))
	fmt.Printf("│  %s  │\n", padTableLine(fmt.Sprintf("Containers: %s running", white(fmt.Sprintf("%d", len(result.Containers)))), boxWidth-2))
	fmt.Printf("│  %s  │\n", padTableLine("", boxWidth-2))

	// Risk summary
	summary := result.RiskSummary
	if summary.Critical > 0 {
		line := fmt.Sprintf("%s Critical: %s", red("🔴"), white(fmt.Sprintf("%d", summary.Critical)))
		fmt.Printf("│  %s  │\n", padTableLine(line, boxWidth-2))
	}
	if summary.High > 0 {
		line := fmt.Sprintf("%s High: %s", yellow("⚠️"), white(fmt.Sprintf("%d", summary.High)))
		fmt.Printf("│  %s  │\n", padTableLine(line, boxWidth-2))
	}
	if summary.Medium > 0 {
		line := fmt.Sprintf("%s Medium: %s", yellow("🟡"), white(fmt.Sprintf("%d", summary.Medium)))
		fmt.Printf("│  %s  │\n", padTableLine(line, boxWidth-2))
	}
	if summary.Low > 0 {
		line := fmt.Sprintf("%s Low: %s", green("ℹ️"), white(fmt.Sprintf("%d", summary.Low)))
		fmt.Printf("│  %s  │\n", padTableLine(line, boxWidth-2))
	}

	// If no issues
	if summary.Critical == 0 && summary.High == 0 && summary.Medium == 0 {
		line := green("✅ No critical issues found!")
		fmt.Printf("│  %s  │\n", padTableLine(line, boxWidth-2))
	}

	// Security score
	fmt.Printf("│  %s  │\n", padTableLine("", boxWidth-2))
	scoreColor := green
	if result.OverallScore < 50 {
		scoreColor = red
	} else if result.OverallScore < 70 {
		scoreColor = yellow
	}
	fmt.Printf("│  %s  │\n", padTableLine(fmt.Sprintf("Security Score: %s", scoreColor(fmt.Sprintf("%d/100", result.OverallScore))), boxWidth-2))

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

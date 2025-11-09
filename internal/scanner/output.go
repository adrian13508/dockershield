package scanner

import (
	"encoding/json"
	"fmt"
	"regexp"
	"strings"

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

// FormatTerminal outputs category results to terminal
func (r *CategoryResult) FormatTerminal() {
	// Color functions
	green := color.New(color.FgGreen).SprintFunc()
	yellow := color.New(color.FgYellow).SprintFunc()
	red := color.New(color.FgRed).SprintFunc()
	cyan := color.New(color.FgCyan, color.Bold).SprintFunc()
	white := color.New(color.FgWhite, color.Bold).SprintFunc()

	const boxWidth = 42

	fmt.Println()
	fmt.Println("┌────────────────────────────────────────────┐")
	fmt.Printf("│  %s  │\n", padTableLine(cyan(fmt.Sprintf("Category Check: %s", r.Category)), boxWidth-2))
	fmt.Printf("│  %s  │\n", padTableLine(fmt.Sprintf("Scan Time: %s", white(fmt.Sprintf("%dms", r.ScanTimeMs))), boxWidth-2))
	fmt.Println("└────────────────────────────────────────────┘")
	fmt.Println()

	// Results summary
	fmt.Printf("%s\n", white("RESULTS:"))
	fmt.Println("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")
	fmt.Println()

	// Show findings
	if len(r.Findings) == 0 {
		fmt.Println(green("✓ No findings for this category"))
		fmt.Println()
		return
	}

	for _, finding := range r.Findings {
		// Icon based on severity
		var icon string
		var colorFunc func(a ...interface{}) string

		switch finding.Severity {
		case "critical":
			icon = "🔴"
			colorFunc = red
		case "high":
			icon = "⚠️ "
			colorFunc = red
		case "medium":
			icon = "🟡"
			colorFunc = yellow
		case "low":
			icon = "ℹ️ "
			colorFunc = yellow
		case "ok":
			icon = "✅"
			colorFunc = green
		default:
			icon = "ℹ️ "
			colorFunc = white
		}

		// Format severity label
		severityLabel := fmt.Sprintf("[%s]", finding.Severity)

		// Print finding
		fmt.Printf("%s %s", icon, colorFunc(fmt.Sprintf("%-10s", severityLabel)))

		// Add container name if present
		if finding.Container != "" {
			fmt.Printf(" %s", white(finding.Container))
		}

		fmt.Println()

		// Message
		fmt.Printf("   %s\n", colorFunc(finding.Message))

		// Port/binding info
		if finding.Port != "" {
			fmt.Printf("   Port: %s", finding.Port)
			if finding.Binding != "" {
				fmt.Printf(" (%s)", finding.Binding)
			}
			fmt.Println()
		}

		// Network info
		if finding.Network != "" && finding.Container != "" {
			fmt.Printf("   Network: %s\n", finding.Network)
		}

		// Remediation
		if finding.Remediation != "" {
			fmt.Printf("   → Fix: %s\n", finding.Remediation)
		}

		fmt.Println()
	}

	// Summary line
	fmt.Println("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")
	fmt.Printf("Summary: ")

	parts := []string{}
	if r.Results.Critical > 0 {
		parts = append(parts, red(fmt.Sprintf("%d critical", r.Results.Critical)))
	}
	if r.Results.High > 0 {
		parts = append(parts, red(fmt.Sprintf("%d high", r.Results.High)))
	}
	if r.Results.Medium > 0 {
		parts = append(parts, yellow(fmt.Sprintf("%d medium", r.Results.Medium)))
	}
	if r.Results.Low > 0 {
		parts = append(parts, yellow(fmt.Sprintf("%d low", r.Results.Low)))
	}
	if r.Results.OK > 0 {
		parts = append(parts, green(fmt.Sprintf("%d ok", r.Results.OK)))
	}

	if len(parts) == 0 {
		fmt.Println(green("All clear"))
	} else {
		for i, part := range parts {
			if i > 0 {
				fmt.Print(", ")
			}
			fmt.Print(part)
		}
		fmt.Println()
	}

	fmt.Println()
	fmt.Println("Run 'dockershield scan' for full analysis.")
	fmt.Println()
}

// FormatJSON outputs category results as JSON
func (r *CategoryResult) FormatJSON() error {
	data, err := json.MarshalIndent(r, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal JSON: %w", err)
	}

	fmt.Println(string(data))
	return nil
}

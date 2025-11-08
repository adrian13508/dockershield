package diagnostics

import (
	"encoding/json"
	"fmt"

	"github.com/fatih/color"
)

// OutputTerminal prints diagnostic results to terminal
func (r *DiagnosticResults) OutputTerminal() {
	// Color functions
	green := color.New(color.FgGreen).SprintFunc()
	yellow := color.New(color.FgYellow).SprintFunc()
	red := color.New(color.FgRed).SprintFunc()
	cyan := color.New(color.FgCyan, color.Bold).SprintFunc()
	white := color.New(color.FgWhite, color.Bold).SprintFunc()

	fmt.Println("┌────────────────────────────────────────────┐")
	fmt.Printf("│  %s              │\n", cyan("DockerShield Doctor"))
	fmt.Printf("│  %s                   │\n", white("System Diagnostics"))
	fmt.Println("└────────────────────────────────────────────┘")
	fmt.Println()

	// System checks
	fmt.Printf("%s\n", white("SYSTEM:"))
	fmt.Println("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")
	r.printCheckResult("Operating System", r.System.OS, green, yellow, red)
	r.printCheckResult("Architecture", r.System.Architecture, green, yellow, red)
	r.printCheckResult("Kernel", r.System.Kernel, green, yellow, red)
	r.printCheckResult("Running as", r.System.IsRoot, green, yellow, red)
	fmt.Println()

	// Docker checks
	fmt.Printf("%s\n", white("DOCKER:"))
	fmt.Println("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")
	r.printCheckResult("Docker installed", r.Docker.Installed, green, yellow, red)
	r.printCheckResult("Docker daemon", r.Docker.DaemonRunning, green, yellow, red)
	r.printCheckResult("Docker socket", r.Docker.SocketAccessible, green, yellow, red)
	r.printCheckResult("API version", r.Docker.APIVersion, green, yellow, red)
	r.printCheckResult("Can list containers", r.Docker.CanListContainers, green, yellow, red)
	r.printCheckResult("Can list networks", r.Docker.CanListNetworks, green, yellow, red)
	fmt.Println()

	// Permissions checks
	fmt.Printf("%s\n", white("PERMISSIONS:"))
	fmt.Println("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")
	r.printCheckResult("Read iptables", r.Permissions.CanReadIptables, green, yellow, red)
	r.printCheckResult("Access Docker socket", r.Permissions.CanAccessDocker, green, yellow, red)
	r.printCheckResult("Write state files", r.Permissions.CanWriteState, green, yellow, red)
	r.printCheckResult("Read SSH config", r.Permissions.CanReadSSHConfig, green, yellow, red)
	fmt.Println()

	// Dependencies checks
	fmt.Printf("%s\n", white("DEPENDENCIES:"))
	fmt.Println("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")
	r.printCheckResult("iptables", r.Dependencies.IptablesInstalled, green, yellow, red)
	r.printCheckResult("iptables-save", r.Dependencies.IptablesSaveAccessible, green, yellow, red)
	r.printCheckResult("UFW", r.Dependencies.UFWInstalled, green, yellow, red)
	fmt.Println()

	// Configuration checks
	fmt.Printf("%s\n", white("CONFIGURATION:"))
	fmt.Println("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")
	r.printCheckResult("Config directory", r.Config.ConfigDirExists, green, yellow, red)
	r.printCheckResult("Config file", r.Config.ConfigFileExists, green, yellow, red)
	r.printCheckResult("State directory", r.Config.StateDirExists, green, yellow, red)
	r.printCheckResult("State writable", r.Config.StateDirWritable, green, yellow, red)
	r.printCheckResult("Previous scan", r.Config.StateFileExists, green, yellow, red)
	fmt.Println()

	// DockerShield info
	fmt.Printf("%s\n", white("DOCKERSHIELD:"))
	fmt.Println("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")
	r.printCheckResult("Version", r.DockerShield.Version, green, yellow, red)
	r.printCheckResult("Binary", r.DockerShield.BinaryLocation, green, yellow, red)
	r.printCheckResult("Build", r.DockerShield.BuildInfo, green, yellow, red)
	fmt.Println()

	// Summary
	fmt.Println("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")
	statusMsg := r.GetStatusMessage()
	if r.HasErrors() {
		fmt.Printf("DIAGNOSIS: %s\n", red(statusMsg))
	} else if r.HasWarnings() {
		fmt.Printf("DIAGNOSIS: %s ✅\n", yellow(statusMsg))
	} else {
		fmt.Printf("DIAGNOSIS: %s ✅\n", green(statusMsg))
	}
	fmt.Println()

	// Show issues if any
	issues := r.GetIssues()
	if len(issues) > 0 {
		fmt.Printf("%s\n", yellow("Issues found:"))
		for i, issue := range issues {
			fmt.Printf("%d. %s\n", i+1, issue.Message)
			if issue.Fix != "" {
				fmt.Printf("   → %s\n", issue.Fix)
			}
		}
		fmt.Println()
	}

	// Helpful message
	if !r.HasErrors() {
		fmt.Println("Run 'dockershield scan' to perform security analysis.")
	}
}

// printCheckResult prints a single check result with color
func (r *DiagnosticResults) printCheckResult(
	label string,
	result CheckResult,
	green, yellow, red func(a ...interface{}) string,
) {
	// Icon based on status
	var icon string
	switch result.Status {
	case StatusPass:
		icon = green("✅")
	case StatusWarning:
		icon = yellow("⚠️ ")
	case StatusFail:
		icon = red("❌")
	case StatusSkipped:
		icon = "⏭️ "
	}

	fmt.Printf("%s %s: %s\n", icon, label, result.Message)

	// Show fix if available and not passed
	if result.Fix != "" && result.Status != StatusPass {
		fmt.Printf("   → %s\n", result.Fix)
	}
}

// OutputJSON prints diagnostic results as JSON
func (r *DiagnosticResults) OutputJSON() error {
	// Convert to JSON
	data, err := json.MarshalIndent(r, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal JSON: %w", err)
	}

	fmt.Println(string(data))
	return nil
}

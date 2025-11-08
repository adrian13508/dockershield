package main

import (
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/adrian13508/dockershield/internal/analyzer"
	"github.com/adrian13508/dockershield/internal/diagnostics"
	"github.com/adrian13508/dockershield/internal/docker"
	"github.com/adrian13508/dockershield/internal/reporter"
	"github.com/adrian13508/dockershield/internal/scanner"
	"github.com/adrian13508/dockershield/internal/security"
	"github.com/adrian13508/dockershield/internal/state"
	"github.com/adrian13508/dockershield/internal/system"
	"github.com/adrian13508/dockershield/internal/updater"
	"github.com/adrian13508/dockershield/pkg/models"
	"github.com/fatih/color"
	"github.com/spf13/cobra"
)

var (
	// Version info - will be set during build
	version = "0.1.0-dev"
	commit  = "unknown"
)

func main() {
	// Execute starts the CLI application
	if err := rootCmd.Execute(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

// rootCmd is the base command when called without subcommands
var rootCmd = &cobra.Command{
	Use:   "dockershield",
	Short: "Complete VPS security scanning tool",
	Long: `DockerShield - A comprehensive VPS security scanner

DockerShield performs security audits of your VPS including:
  • Docker container port exposure analysis
  • Network topology mapping
  • Firewall/UFW configuration
  • SSH security configuration
  • fail2ban intrusion prevention
  • System updates and patches
  • System hardening baseline (sysctl, kernel parameters)
  • User/sudo security and password policies
  • Rootkit detection (rkhunter, chkrootkit)
  • File integrity monitoring (AIDE)
  • Log analysis (auth, sudo, system logs)

Perfect for indie developers and small teams running self-hosted applications.`,
	// Don't show usage on errors
	SilenceUsage: true,
}

func init() {
	// Add subcommands
	rootCmd.AddCommand(scanCmd)
	rootCmd.AddCommand(statusCmd)
	rootCmd.AddCommand(checkCmd)
	rootCmd.AddCommand(versionCmd)
	rootCmd.AddCommand(upgradeCmd)
	rootCmd.AddCommand(doctorCmd)
}

// scanCmd represents the scan command
var scanCmd = &cobra.Command{
	Use:   "scan",
	Short: "Scan Docker containers and system for security issues",
	Long: `Performs a comprehensive security scan of Docker containers and system.

Checks for:
  - Publicly exposed ports (0.0.0.0)
  - Database ports on public internet
  - Docker network topology
  - iptables/firewall status
  - SSH configuration security
  - fail2ban intrusion prevention
  - System updates and patches
  - System hardening (sysctl, SELinux/AppArmor)
  - User/sudo security and password policies
  - Rootkit detection (rkhunter, chkrootkit)
  - File integrity monitoring (AIDE)
  - Log analysis (failed logins, sudo usage)

Example:
  dockershield scan
  dockershield scan --json
  dockershield scan --output report.json`,
	RunE: runScan,
}

// versionCmd prints version information
var versionCmd = &cobra.Command{
	Use:   "version",
	Short: "Show version information",
	Run: func(cmd *cobra.Command, args []string) {
		fmt.Printf("DockerShield %s (commit: %s)\n", version, commit)

		// Check for updates (non-blocking)
		checkForUpdatesNotification()
	},
}

// upgradeCmd upgrades dockershield to the latest version
var upgradeCmd = &cobra.Command{
	Use:   "upgrade",
	Short: "Upgrade DockerShield to the latest version",
	Long: `Upgrades DockerShield to the latest version from GitHub releases.

This command will:
  - Check for the latest release on GitHub
  - Download and replace the current binary
  - Verify the update was successful

Example:
  dockershield upgrade`,
	RunE: runUpgrade,
}

// statusCmd shows quick summary from last scan
var statusCmd = &cobra.Command{
	Use:   "status",
	Short: "Show summary from last scan (cached)",
	Long: `Display a quick summary from the last security scan without running a new scan.

This command reads cached results from the previous scan and displays:
  - Time since last scan
  - Number of containers scanned
  - Risk summary (critical, high, medium, low issues)
  - Overall security score

This is useful for quick checks and integrations that need fast responses
without performing a full scan.

Example:
  dockershield status
  dockershield status --json
  dockershield status --fresh     # Run new scan if cache is old`,
	RunE: runStatus,
}

// checkCmd performs focused category scans
var checkCmd = &cobra.Command{
	Use:   "check <category>",
	Short: "Run focused scan on specific category",
	Long: `Run targeted security checks on a specific category.

Categories:
  ports      - Check port exposures only
  networks   - Check network configuration
  firewall   - Check iptables/UFW configuration
  containers - Check container security settings
  all        - Run all checks (same as 'scan')

This command is faster than a full scan and useful for CI/CD pipelines
or when you only need to check a specific aspect of security.

Example:
  dockershield check ports
  dockershield check ports --json
  dockershield check ports --container nginx
  dockershield check firewall --severity critical`,
	Args:      cobra.ExactArgs(1),
	ValidArgs: []string{"ports", "networks", "firewall", "containers", "all"},
	RunE:      runCheck,
}

// doctorCmd performs system diagnostics
var doctorCmd = &cobra.Command{
	Use:   "doctor",
	Short: "Run system diagnostics",
	Long: `Diagnose DockerShield and system requirements.

Checks:
  - System information (OS, kernel, architecture)
  - Docker installation and accessibility
  - Permissions (iptables, Docker socket, config files)
  - Dependencies (iptables, UFW)
  - Configuration files
  - DockerShield installation

This command is useful for troubleshooting issues and verifying that
DockerShield can run all security checks properly.

Example:
  dockershield doctor
  dockershield doctor --json
  dockershield doctor --verbose`,
	RunE: runDoctor,
}

var (
	// Flags for scan command
	jsonOutput  bool
	outputFile  string
	verboseMode bool
)

var (
	// Flags for status command
	statusJSON   bool
	statusFresh  bool
	statusMaxAge time.Duration
)

var (
	// Flags for check command
	checkJSON      bool
	checkContainer string
	checkSeverity  string
)

var (
	// Flags for doctor command
	doctorJSON    bool
	doctorVerbose bool
)

func init() {
	// Add flags to scan command
	scanCmd.Flags().BoolVar(&jsonOutput, "json", false, "Output results in JSON format")
	scanCmd.Flags().StringVarP(&outputFile, "output", "o", "", "Write output to file")
	scanCmd.Flags().BoolVarP(&verboseMode, "verbose", "v", false, "Enable verbose logging")

	// Add flags to status command
	statusCmd.Flags().BoolVar(&statusJSON, "json", false, "Output results in JSON format")
	statusCmd.Flags().BoolVar(&statusFresh, "fresh", false, "Force new scan if cache is old")
	statusCmd.Flags().DurationVar(&statusMaxAge, "max-age", 24*time.Hour, "Maximum cache age (e.g., 5m, 1h, 24h)")

	// Add flags to check command
	checkCmd.Flags().BoolVar(&checkJSON, "json", false, "Output results in JSON format")
	checkCmd.Flags().StringVar(&checkContainer, "container", "", "Filter by container name")
	checkCmd.Flags().StringVar(&checkSeverity, "severity", "all", "Filter by severity (critical, high, medium, low, all)")

	// Add flags to doctor command
	doctorCmd.Flags().BoolVar(&doctorJSON, "json", false, "Output results in JSON format")
	doctorCmd.Flags().BoolVarP(&doctorVerbose, "verbose", "v", false, "Enable verbose output")
}

// runScan executes the security scan
func runScan(cmd *cobra.Command, args []string) error {
	// In JSON mode, suppress progress messages
	quietMode := jsonOutput

	if !quietMode {
		fmt.Println("🔍 DockerShield Security Scanner")
		fmt.Println("================================")
		fmt.Println()
	}

	// Connect to Docker
	dockerClient, err := createDockerClient(quietMode)
	if err != nil {
		return err
	}
	defer dockerClient.Close()

	// Get Docker version (only in verbose mode)
	if verboseMode && !quietMode {
		version, err := dockerClient.GetServerVersion()
		if err != nil {
			return fmt.Errorf("failed to get Docker version: %w", err)
		}
		fmt.Printf("Docker Engine: %s\n\n", version)
	}

	// Scan containers
	if !quietMode {
		fmt.Println("📦 Scanning containers...")
	}
	containers, err := dockerClient.ListContainers()
	if err != nil {
		return fmt.Errorf("failed to list containers: %w", err)
	}

	if len(containers) == 0 && !quietMode {
		fmt.Println("No containers found.")
		return nil
	}

	// Scan networks (always needed for JSON output)
	networks, err := dockerClient.ListNetworks()
	if err != nil && !quietMode {
		fmt.Printf("Warning: failed to list networks: %v\n", err)
	}

	if !quietMode {
		fmt.Printf("Found %d container(s)\n\n", len(containers))
		fmt.Println("🔍 Analyzing security risks...")
	}

	// Analyze security risks
	riskSummary := analyzer.AnalyzeContainers(containers)
	score := analyzer.CalculateSecurityScore(riskSummary)

	// Analyze firewall (iptables/UFW)
	if !quietMode {
		fmt.Println("🔥 Checking firewall configuration...")
	}
	firewallAnalysis := system.AnalyzeIptables()
	firewallInfo := convertFirewallAnalysis(firewallAnalysis)

	// Perform system security checks
	if !quietMode {
		fmt.Println("🛡️  Performing system security checks...")
	}

	sshConfig := security.AnalyzeSSHConfig()
	fail2banStatus := security.AnalyzeFail2ban()
	systemStatus := security.AnalyzeSystemSecurity()

	// Perform advanced security checks
	if !quietMode {
		fmt.Println("🔒 Performing advanced security checks...")
	}

	hardeningStatus := security.AnalyzeSystemHardening()
	userStatus := security.AnalyzeUserSecurity()
	rootkitStatus := security.AnalyzeRootkit()
	integrityStatus := security.AnalyzeFileIntegrity()
	logStatus := security.AnalyzeLogs()

	// Save state for status command
	saveState(containers, networks, firewallInfo, sshConfig, fail2banStatus, systemStatus, riskSummary, score, quietMode)

	// Handle JSON output
	if jsonOutput {
		return outputJSON(containers, networks, firewallInfo, sshConfig, fail2banStatus, systemStatus,
			hardeningStatus, userStatus, rootkitStatus, integrityStatus, logStatus, riskSummary, score)
	}

	// Terminal output mode
	rating := analyzer.GetScoreRating(score)
	fmt.Println()

	// Display security summary
	displaySecuritySummary(score, rating, riskSummary)

	// Display each container
	if verboseMode {
		// Verbose mode: Show all containers with full details
		for _, container := range containers {
			displayContainer(container)
		}
	} else {
		// Compact mode (default): Show only running containers in one-line format
		fmt.Println("\n📦 RUNNING CONTAINERS")
		fmt.Println("═══════════════════════════════════════════════")
		runningCount := 0
		for _, container := range containers {
			if container.State == "running" {
				displayContainerCompact(container)
				runningCount++
			}
		}
		if runningCount == 0 {
			fmt.Println("No running containers found")
		}
		fmt.Println()
		totalContainers := len(containers)
		if totalContainers > runningCount {
			fmt.Printf("ℹ️  Showing %d running containers (%d stopped/created containers hidden)\n", runningCount, totalContainers-runningCount)
			fmt.Println("   Use --verbose to see all containers with full details")
			fmt.Println()
		}
	}

	// Show remediation recommendations
	displayRemediations(containers)

	// Show firewall warnings
	displayFirewallWarnings(firewallAnalysis)

	// Display system security checks
	displaySystemSecurityChecks(sshConfig, fail2banStatus, systemStatus)

	// Display advanced security checks
	displayAdvancedSecurityChecks(hardeningStatus, userStatus, rootkitStatus, integrityStatus, logStatus)

	// List networks if verbose
	if verboseMode {
		fmt.Println("\n🌐 Docker Networks:")
		for _, net := range networks {
			fmt.Printf("  • %s (%s) - %d container(s)\n",
				net.Name, net.Driver, len(net.Containers))
		}
	}

	fmt.Println("\n✓ Scan complete")

	// Check for updates notification
	checkForUpdatesNotification()

	return nil
}

// outputJSON generates and outputs JSON format
func outputJSON(
	containers []models.Container,
	networks []models.NetworkInfo,
	firewallInfo *models.FirewallInfo,
	sshConfig *security.SSHConfig,
	fail2banStatus *security.Fail2banStatus,
	systemStatus *security.SystemSecurityStatus,
	hardeningStatus *security.HardeningStatus,
	userStatus *security.UserHardeningStatus,
	rootkitStatus *security.RootkitStatus,
	integrityStatus *security.IntegrityStatus,
	logStatus *security.LogAnalysisStatus,
	riskSummary models.RiskSummary,
	score int,
) error {
	jsonReporter := reporter.NewJSONReporter()

	// Create security checks struct
	securityChecks := &models.SecurityChecks{
		SSH:       sshConfig,
		Fail2ban:  fail2banStatus,
		System:    systemStatus,
		Hardening: hardeningStatus,
		Users:     userStatus,
		Rootkit:   rootkitStatus,
		Integrity: integrityStatus,
		Logs:      logStatus,
	}

	// Generate JSON
	jsonData, err := jsonReporter.Generate(containers, networks, firewallInfo, securityChecks, riskSummary, score)
	if err != nil {
		return fmt.Errorf("failed to generate JSON: %w", err)
	}

	// Write to file or print to stdout
	if outputFile != "" {
		err = jsonReporter.WriteToFile(jsonData, outputFile)
		if err != nil {
			return err
		}
		fmt.Fprintf(os.Stderr, "✓ Report saved to %s\n", outputFile)
	} else {
		jsonReporter.Print(jsonData)
	}

	return nil
}

// createDockerClient creates and validates a Docker client connection
func createDockerClient(quiet bool) (*docker.Client, error) {
	if !quiet {
		fmt.Print("Connecting to Docker... ")
	}

	client, err := docker.NewClient()
	if err != nil {
		if !quiet {
			fmt.Println("✗")
		}
		return nil, fmt.Errorf("failed to connect to Docker: %w", err)
	}

	if !quiet {
		fmt.Println("✓")
	}
	return client, nil
}

// displayContainer prints container information in a readable format
func displayContainer(c models.Container) {
	// Color functions for visual output
	green := color.New(color.FgGreen).SprintFunc()
	yellow := color.New(color.FgYellow).SprintFunc()
	red := color.New(color.FgRed).SprintFunc()
	cyan := color.New(color.FgCyan).SprintFunc()

	// Container header
	statusColor := green
	if c.State != "running" {
		statusColor = yellow
	}

	fmt.Printf("┌─ %s %s\n", cyan(c.Name), statusColor("["+c.State+"]"))
	fmt.Printf("│  Image: %s\n", c.Image)
	fmt.Printf("│  ID: %s\n", c.ID)
	fmt.Printf("│  Network: %s\n", c.NetworkMode)

	// Port bindings
	if len(c.Ports) > 0 {
		fmt.Println("│  Ports:")
		for _, port := range c.Ports {
			exposureIcon := getExposureIcon(port.ExposureType)
			riskIcon := getRiskIcon(port.RiskLevel)
			portStr := fmt.Sprintf("%s:%s → %s/%s",
				port.HostIP, port.HostPort, port.ContainerPort, port.Protocol)

			// Color based on risk level
			var colorFunc func(a ...interface{}) string
			switch port.RiskLevel {
			case models.RiskCritical, models.RiskHigh:
				colorFunc = red
			case models.RiskMedium:
				colorFunc = yellow
			default:
				colorFunc = green
			}

			fmt.Printf("│    %s %s %s\n", exposureIcon, colorFunc(portStr), riskIcon)
			if port.RiskReason != "" {
				fmt.Printf("│       → %s\n", colorFunc(port.RiskReason))
			}
		}
	} else {
		fmt.Println("│  Ports: none")
	}

	fmt.Println("└─")
	fmt.Println()
}

// getExposureIcon returns an icon for the exposure type
func getExposureIcon(exposure models.ExposureType) string {
	switch exposure {
	case models.ExposurePublic:
		return "🔴"
	case models.ExposureLocalhost:
		return "✅"
	default:
		return "🟡"
	}
}

// displayContainerCompact shows container in compact one-line format
func displayContainerCompact(c models.Container) {
	green := color.New(color.FgGreen).SprintFunc()
	yellow := color.New(color.FgYellow).SprintFunc()
	red := color.New(color.FgRed).SprintFunc()
	white := color.New(color.FgWhite).SprintFunc()

	// Count issues by severity
	criticalCount := 0
	highCount := 0
	mediumCount := 0

	for _, port := range c.Ports {
		switch port.RiskLevel {
		case models.RiskCritical:
			criticalCount++
		case models.RiskHigh:
			highCount++
		case models.RiskMedium:
			mediumCount++
		}
	}

	// Determine overall status icon
	statusIcon := "✅"
	statusText := "OK"
	statusColor := green

	if criticalCount > 0 || highCount > 0 {
		statusIcon = "❌"
		statusText = "ISSUES"
		statusColor = red
	} else if mediumCount > 0 {
		statusIcon = "⚠️ "
		statusText = "WARN"
		statusColor = yellow
	}

	// Build issue summary
	var issues []string
	if criticalCount > 0 {
		issues = append(issues, red(fmt.Sprintf("CRITICAL×%d", criticalCount)))
	}
	if highCount > 0 {
		issues = append(issues, red(fmt.Sprintf("HIGH×%d", highCount)))
	}
	if mediumCount > 0 {
		issues = append(issues, yellow(fmt.Sprintf("MEDIUM×%d", mediumCount)))
	}

	issueText := ""
	if len(issues) > 0 {
		issueText = " - " + strings.Join(issues, ", ")
	}

	// Print compact line
	fmt.Printf("%s %s %s%s\n",
		statusIcon,
		statusColor(statusText),
		white(c.Name),
		issueText)
}

// getRiskIcon returns an icon for the risk level
func getRiskIcon(risk models.RiskLevel) string {
	switch risk {
	case models.RiskCritical:
		return "[CRITICAL]"
	case models.RiskHigh:
		return "[HIGH]"
	case models.RiskMedium:
		return "[MEDIUM]"
	case models.RiskLow:
		return "[LOW]"
	default:
		return ""
	}
}

// displaySecuritySummary shows the overall security score and risk breakdown
func displaySecuritySummary(score int, rating string, summary models.RiskSummary) {
	// Color functions
	green := color.New(color.FgGreen).SprintFunc()
	yellow := color.New(color.FgYellow).SprintFunc()
	red := color.New(color.FgRed).SprintFunc()
	cyan := color.New(color.FgCyan, color.Bold).SprintFunc()
	white := color.New(color.FgWhite, color.Bold).SprintFunc()

	// Choose color based on score
	var scoreColor func(a ...interface{}) string
	if score >= 70 {
		scoreColor = green
	} else if score >= 50 {
		scoreColor = yellow
	} else {
		scoreColor = red
	}

	fmt.Println("┌────────────────────────────────────────────┐")
	fmt.Printf("│  %s  │\n", cyan("SECURITY SUMMARY"))
	fmt.Println("├────────────────────────────────────────────┤")
	fmt.Printf("│  Security Score: %s  │\n", scoreColor(fmt.Sprintf("%d/100 (%s)", score, rating)))
	fmt.Println("│                                            │")

	// Risk breakdown
	if summary.Critical > 0 {
		fmt.Printf("│  %s Critical Issues: %s                    │\n", red("🔴"), white(fmt.Sprintf("%d", summary.Critical)))
	}
	if summary.High > 0 {
		fmt.Printf("│  %s High Issues: %s                        │\n", red("⚠️"), white(fmt.Sprintf("%d", summary.High)))
	}
	if summary.Medium > 0 {
		fmt.Printf("│  %s Medium Issues: %s                      │\n", yellow("🟡"), white(fmt.Sprintf("%d", summary.Medium)))
	}
	if summary.Low > 0 {
		fmt.Printf("│  %s Low Issues: %s                         │\n", green("ℹ️"), white(fmt.Sprintf("%d", summary.Low)))
	}

	// If no issues at all
	if summary.Critical == 0 && summary.High == 0 && summary.Medium == 0 {
		fmt.Printf("│  %s                              │\n", green("✅ No critical issues found!"))
	}

	fmt.Println("└────────────────────────────────────────────┘")
	fmt.Println()
}

// displayRemediations shows fix recommendations for security issues
func displayRemediations(containers []models.Container) {
	var allRemediations []analyzer.Remediation

	// Collect all remediations
	for _, container := range containers {
		remediations := analyzer.GenerateContainerRemediations(container)
		allRemediations = append(allRemediations, remediations...)
	}

	if len(allRemediations) == 0 {
		return
	}

	// Show remediation section
	cyan := color.New(color.FgCyan, color.Bold).SprintFunc()
	fmt.Printf("\n%s\n", cyan("🔧 RECOMMENDED FIXES"))
	fmt.Println("═══════════════════════════════════════════════")
	fmt.Println()

	// Display each remediation
	for i, r := range allRemediations {
		fmt.Printf("%d. %s\n", i+1, analyzer.FormatRemediation(r))
	}
}

// convertFirewallAnalysis converts system firewall analysis to model
func convertFirewallAnalysis(analysis *system.IptablesAnalysis) *models.FirewallInfo {
	if analysis == nil {
		return nil
	}

	return &models.FirewallInfo{
		UFWActive:          analysis.UFWActive,
		DockerDetected:     analysis.HasDocker,
		DockerBypassingUFW: analysis.DockerBypassingUFW,
		DockerChains:       analysis.DockerChains,
		Warning:            analysis.GetFirewallWarning(),
	}
}

// displayFirewallWarnings shows firewall-related security warnings
func displayFirewallWarnings(analysis *system.IptablesAnalysis) {
	if analysis == nil || analysis.ErrorMessage != "" {
		// Don't show warnings if we couldn't analyze
		if analysis != nil && analysis.RequiresSudo {
			yellow := color.New(color.FgYellow).SprintFunc()
			fmt.Printf("\n%s\n", yellow("ℹ️  Firewall analysis requires sudo privileges"))
		}
		return
	}

	warning := analysis.GetFirewallWarning()
	if warning == "" {
		return
	}

	// Show firewall warning section
	red := color.New(color.FgRed, color.Bold).SprintFunc()
	yellow := color.New(color.FgYellow).SprintFunc()

	fmt.Printf("\n%s\n", red("🔥 FIREWALL WARNING"))
	fmt.Println("═══════════════════════════════════════════════")
	fmt.Println()
	fmt.Println(yellow(warning))
	fmt.Println()

	// Show recommendation
	recommendation := analysis.GetRecommendation()
	if recommendation != "" {
		fmt.Println("How to fix this:")
		fmt.Println(recommendation)
	}
}

// runUpgrade executes the upgrade command
func runUpgrade(cmd *cobra.Command, args []string) error {
	cyan := color.New(color.FgCyan, color.Bold).SprintFunc()
	green := color.New(color.FgGreen).SprintFunc()
	yellow := color.New(color.FgYellow).SprintFunc()

	fmt.Printf("%s\n", cyan("🔄 DockerShield Upgrade"))
	fmt.Println("═══════════════════════════════════════════════")
	fmt.Println()

	// Clean version string (remove 'v' prefix if present)
	currentVer := strings.TrimPrefix(version, "v")

	// Check for updates first
	fmt.Print("Checking for updates... ")
	updateInfo, err := updater.CheckForUpdates(currentVer)
	if err != nil {
		fmt.Println("✗")
		return fmt.Errorf("failed to check for updates: %w", err)
	}
	fmt.Println("✓")

	if !updateInfo.Available {
		fmt.Printf("%s\n", green("✓ Already on the latest version: "+currentVer))
		return nil
	}

	fmt.Printf("\n%s\n", yellow("New version available!"))
	fmt.Printf("  Current: %s\n", currentVer)
	fmt.Printf("  Latest:  %s\n", updateInfo.LatestVersion)
	fmt.Println()

	if updateInfo.ReleaseNotes != "" {
		fmt.Println("Release notes:")
		fmt.Println(updateInfo.ReleaseNotes)
		fmt.Println()
	}

	// Perform update
	fmt.Print("Downloading and installing update... ")
	err = updater.DoSelfUpdate(currentVer)
	if err != nil {
		fmt.Println("✗")
		return fmt.Errorf("failed to update: %w", err)
	}
	fmt.Println("✓")

	fmt.Printf("\n%s\n", green("✓ Successfully upgraded to "+updateInfo.LatestVersion))
	fmt.Println("\nPlease restart dockershield to use the new version.")

	return nil
}

// checkForUpdatesNotification checks for updates and displays a notification
func checkForUpdatesNotification() {
	// Clean version string
	currentVer := strings.TrimPrefix(version, "v")

	// Skip if version is dev
	if strings.Contains(currentVer, "dev") {
		return
	}

	// Check for updates (with short timeout)
	updateInfo, err := updater.CheckForUpdates(currentVer)
	if err != nil {
		// Silently fail - don't bother user with update check errors
		return
	}

	if updateInfo.Available {
		yellow := color.New(color.FgYellow).SprintFunc()
		fmt.Printf("\n%s\n", yellow("💡 New version available: "+updateInfo.LatestVersion+" (run 'dockershield upgrade')"))
		fmt.Println()
	}
}

// displaySystemSecurityChecks shows system security audit results
func displaySystemSecurityChecks(sshConfig *security.SSHConfig, fail2ban *security.Fail2banStatus, system *security.SystemSecurityStatus) {
	// Color functions
	green := color.New(color.FgGreen).SprintFunc()
	yellow := color.New(color.FgYellow).SprintFunc()
	red := color.New(color.FgRed).SprintFunc()
	cyan := color.New(color.FgCyan, color.Bold).SprintFunc()
	white := color.New(color.FgWhite, color.Bold).SprintFunc()

	fmt.Printf("\n%s\n", cyan("🛡️  SYSTEM SECURITY AUDIT"))
	fmt.Println("═══════════════════════════════════════════════")
	fmt.Println()

	// SSH Configuration
	fmt.Printf("%s %s\n", white("SSH Configuration:"), getRiskLevelBadge(sshConfig.RiskLevel))
	fmt.Printf("  Port: %d\n", sshConfig.Port)
	fmt.Printf("  Root Login: %s\n", sshConfig.PermitRootLogin)
	fmt.Printf("  Password Auth: %s\n", sshConfig.PasswordAuth)
	fmt.Printf("  Security Score: %d/100\n", sshConfig.SecurityScore)

	if len(sshConfig.Issues) > 0 {
		fmt.Println("\n  Issues:")
		for _, issue := range sshConfig.Issues {
			issueColor := getIssueColor(issue.Severity)
			fmt.Printf("    %s [%s] %s\n", issueColor("•"), issue.Severity, issue.Issue)
			fmt.Printf("      → %s\n", issue.Recommendation)
		}
	}
	fmt.Println()

	// Fail2ban Status
	fmt.Printf("%s %s\n", white("Fail2ban (Intrusion Prevention):"), getRiskLevelBadge(fail2ban.RiskLevel))
	if !fail2ban.Installed {
		fmt.Printf("  Status: %s\n", red("NOT INSTALLED"))
	} else if !fail2ban.Running {
		fmt.Printf("  Status: %s\n", yellow("INSTALLED BUT NOT RUNNING"))
	} else {
		fmt.Printf("  Status: %s\n", green("RUNNING"))
		fmt.Printf("  Active Jails: %d\n", len(fail2ban.Jails))
		fmt.Printf("  Total Banned IPs: %d\n", fail2ban.TotalBanned)

		if len(fail2ban.Jails) > 0 {
			fmt.Println("\n  Protected Services:")
			for _, jail := range fail2ban.Jails {
				fmt.Printf("    • %s: %d currently banned, %d total banned\n",
					jail.Name, jail.BannedIPs, jail.TotalBanned)
			}
		}
	}

	if len(fail2ban.Recommendations) > 0 {
		fmt.Println("\n  Recommendations:")
		for _, rec := range fail2ban.Recommendations {
			fmt.Printf("    → %s\n", rec)
		}
	}
	fmt.Println()

	// System Update Status
	fmt.Printf("%s %s\n", white("System Updates:"), getRiskLevelBadge(system.RiskLevel))
	fmt.Printf("  OS: %s\n", system.OSVersion)
	fmt.Printf("  Kernel: %s\n", system.KernelVersion)

	if !system.LastUpdate.IsZero() {
		fmt.Printf("  Last Update: %s (%d days ago)\n",
			system.LastUpdate.Format("2006-01-02"), system.DaysSinceUpdate)
	}

	fmt.Printf("  Updates Available: %d", system.UpdatesAvailable)
	if system.SecurityUpdates > 0 {
		fmt.Printf(" (%s security updates)\n", red(fmt.Sprintf("%d", system.SecurityUpdates)))
	} else {
		fmt.Println()
	}

	if system.RebootRequired {
		fmt.Printf("  Reboot Required: %s\n", yellow("YES"))
	}

	if system.AutoUpdatesEnabled {
		fmt.Printf("  Automatic Updates: %s\n", green("ENABLED"))
	} else {
		fmt.Printf("  Automatic Updates: %s\n", red("DISABLED"))
	}

	if len(system.Issues) > 0 {
		fmt.Println("\n  Issues:")
		for _, issue := range system.Issues {
			if issue.Severity == "INFO" {
				fmt.Printf("    %s %s\n", green("✓"), issue.Issue)
			} else {
				issueColor := getIssueColor(issue.Severity)
				fmt.Printf("    %s [%s] %s\n", issueColor("•"), issue.Severity, issue.Issue)
				fmt.Printf("      → %s\n", issue.Recommendation)
			}
		}
	}
	fmt.Println()
}

// displayAdvancedSecurityChecks displays the advanced security audit results
func displayAdvancedSecurityChecks(
	hardening *security.HardeningStatus,
	users *security.UserHardeningStatus,
	rootkit *security.RootkitStatus,
	integrity *security.IntegrityStatus,
	logs *security.LogAnalysisStatus,
) {
	// Color functions
	green := color.New(color.FgGreen).SprintFunc()
	yellow := color.New(color.FgYellow).SprintFunc()
	red := color.New(color.FgRed).SprintFunc()
	cyan := color.New(color.FgCyan, color.Bold).SprintFunc()
	white := color.New(color.FgWhite, color.Bold).SprintFunc()

	fmt.Printf("\n%s\n", cyan("🔒 ADVANCED SECURITY AUDIT"))
	fmt.Println("═══════════════════════════════════════════════")
	fmt.Println()

	// System Hardening
	fmt.Printf("%s %s\n", white("System Hardening:"), getRiskLevelBadge(hardening.RiskLevel))
	fmt.Printf("  Security Score: %d/100\n", hardening.SecurityScore)

	// Show MAC status
	if hardening.SELinuxStatus.Enabled && hardening.SELinuxStatus.Mode == "enforcing" {
		fmt.Printf("  SELinux: %s\n", green("ENFORCING"))
	} else if hardening.SELinuxStatus.Installed {
		fmt.Printf("  SELinux: %s\n", yellow(hardening.SELinuxStatus.Mode))
	}

	if hardening.AppArmorStatus.Enabled {
		fmt.Printf("  AppArmor: %s (%d profiles)\n", green("ENABLED"), hardening.AppArmorStatus.Profiles)
	} else if hardening.AppArmorStatus.Installed {
		fmt.Printf("  AppArmor: %s\n", yellow("INSTALLED BUT DISABLED"))
	}

	// Show critical sysctl issues only
	criticalCount := 0
	for _, check := range hardening.SysctlChecks {
		if !check.Compliant && (check.Severity == "CRITICAL" || check.Severity == "HIGH") {
			criticalCount++
		}
	}
	if criticalCount > 0 {
		fmt.Printf("  Critical sysctl Issues: %s\n", red(fmt.Sprintf("%d", criticalCount)))
	}

	if len(hardening.Issues) > 0 && hardening.SecurityScore < 85 {
		fmt.Println("\n  Top Issues:")
		count := 0
		for _, issue := range hardening.Issues {
			if issue.Severity != "INFO" && count < 3 {
				issueColor := getIssueColor(issue.Severity)
				fmt.Printf("    %s [%s] %s\n", issueColor("•"), issue.Severity, issue.Issue)
				count++
			}
		}
	}
	fmt.Println()

	// User & Sudo Security
	fmt.Printf("%s %s\n", white("User & Sudo Security:"), getRiskLevelBadge(users.RiskLevel))
	fmt.Printf("  Security Score: %d/100\n", users.SecurityScore)
	fmt.Printf("  Sudo Users: %d\n", len(users.SudoConfig.SudoGroupMembers))

	if users.SudoConfig.PasswordlessCount > 0 {
		fmt.Printf("  NOPASSWD Entries: %s\n", red(fmt.Sprintf("%d", users.SudoConfig.PasswordlessCount)))
	}

	if users.PasswordPolicy.MinLength > 0 {
		policyColor := green
		if users.PasswordPolicy.MinLength < 12 {
			policyColor = yellow
		}
		fmt.Printf("  Password Min Length: %s\n", policyColor(fmt.Sprintf("%d", users.PasswordPolicy.MinLength)))
	}

	// Show critical user issues
	if len(users.Issues) > 0 && users.SecurityScore < 85 {
		fmt.Println("\n  Issues:")
		count := 0
		for _, issue := range users.Issues {
			if (issue.Severity == "CRITICAL" || issue.Severity == "HIGH") && count < 3 {
				issueColor := getIssueColor(issue.Severity)
				fmt.Printf("    %s [%s] %s\n", issueColor("•"), issue.Severity, issue.Issue)
				count++
			}
		}
	}
	fmt.Println()

	// Rootkit Detection
	fmt.Printf("%s %s\n", white("Rootkit Detection:"), getRiskLevelBadge(rootkit.RiskLevel))

	if rootkit.RkhunterStatus.Installed {
		status := green("Installed")
		if rootkit.RkhunterStatus.WarningsFound > 0 {
			status = red(fmt.Sprintf("%d warnings", rootkit.RkhunterStatus.WarningsFound))
		}
		fmt.Printf("  rkhunter: %s\n", status)
	} else {
		fmt.Printf("  rkhunter: %s\n", red("Not installed"))
	}

	if rootkit.ChkrootkitStatus.Installed {
		status := green("Installed")
		if rootkit.ChkrootkitStatus.InfectionsFound > 0 {
			status = red(fmt.Sprintf("%d infections", rootkit.ChkrootkitStatus.InfectionsFound))
		}
		fmt.Printf("  chkrootkit: %s\n", status)
	} else {
		fmt.Printf("  chkrootkit: %s\n", red("Not installed"))
	}

	if len(rootkit.Issues) > 0 {
		fmt.Println("\n  Issues:")
		for _, issue := range rootkit.Issues {
			if issue.Severity != "INFO" && issue.Severity != "LOW" {
				issueColor := getIssueColor(issue.Severity)
				fmt.Printf("    %s [%s] %s\n", issueColor("•"), issue.Severity, issue.Issue)
			}
		}
	}
	fmt.Println()

	// File Integrity Monitoring
	fmt.Printf("%s %s\n", white("File Integrity Monitoring:"), getRiskLevelBadge(integrity.RiskLevel))

	if integrity.AIDEStatus.Installed {
		if integrity.AIDEStatus.Initialized {
			status := green("Initialized")
			if integrity.AIDEStatus.ChangesFound > 0 {
				status = yellow(fmt.Sprintf("%d changes detected", integrity.AIDEStatus.ChangesFound))
			}
			fmt.Printf("  AIDE: %s\n", status)
			fmt.Printf("  Database Age: %d days\n", integrity.AIDEStatus.DatabaseAge)
		} else {
			fmt.Printf("  AIDE: %s\n", yellow("Not initialized"))
		}
	} else {
		fmt.Printf("  AIDE: %s\n", red("Not installed"))
	}

	if len(integrity.Issues) > 0 && integrity.SecurityScore < 80 {
		fmt.Println("\n  Issues:")
		count := 0
		for _, issue := range integrity.Issues {
			if issue.Severity != "INFO" && count < 2 {
				issueColor := getIssueColor(issue.Severity)
				fmt.Printf("    %s [%s] %s\n", issueColor("•"), issue.Severity, issue.Issue)
				count++
			}
		}
	}
	fmt.Println()

	// Log Analysis
	fmt.Printf("%s %s\n", white("Log Analysis:"), getRiskLevelBadge(logs.RiskLevel))

	if logs.AuthLog.LogAvailable {
		fmt.Printf("  Failed Logins: %s\n", getCountColor(logs.AuthLog.FailedLogins))
		if logs.AuthLog.RootLoginAttempts > 0 {
			fmt.Printf("  Root Login Attempts: %s\n", red(fmt.Sprintf("%d", logs.AuthLog.RootLoginAttempts)))
		}
		fmt.Printf("  Successful Logins: %d\n", logs.AuthLog.SuccessfulLogins)
	}

	if logs.SudoLog.LogAvailable {
		fmt.Printf("  Sudo Commands: %d\n", logs.SudoLog.SudoCommands)
		if len(logs.SudoLog.SuspiciousCommands) > 0 {
			fmt.Printf("  Suspicious Commands: %s\n", yellow(fmt.Sprintf("%d", len(logs.SudoLog.SuspiciousCommands))))
		}
	}

	if len(logs.SecurityEvents) > 0 {
		fmt.Println("\n  Recent Security Events:")
		count := 0
		for _, event := range logs.SecurityEvents {
			if count < 5 {
				eventColor := getIssueColor(event.Severity)
				fmt.Printf("    %s [%s] %s\n", eventColor("•"), event.Source, event.Description)
				count++
			}
		}
	}

	if len(logs.Issues) > 0 && logs.SecurityScore < 85 {
		fmt.Println("\n  Issues:")
		count := 0
		for _, issue := range logs.Issues {
			if issue.Severity != "INFO" && count < 3 {
				issueColor := getIssueColor(issue.Severity)
				fmt.Printf("    %s [%s] %s\n", issueColor("•"), issue.Severity, issue.Issue)
				count++
			}
		}
	}
	fmt.Println()
}

// getCountColor returns colored count based on value
func getCountColor(count int) string {
	green := color.New(color.FgGreen).SprintFunc()
	yellow := color.New(color.FgYellow).SprintFunc()
	red := color.New(color.FgRed).SprintFunc()

	if count == 0 {
		return green("0")
	} else if count < 20 {
		return yellow(fmt.Sprintf("%d", count))
	} else {
		return red(fmt.Sprintf("%d", count))
	}
}

// getRiskLevelBadge returns a colored badge for the risk level
func getRiskLevelBadge(riskLevel string) string {
	green := color.New(color.FgGreen, color.Bold).SprintFunc()
	yellow := color.New(color.FgYellow, color.Bold).SprintFunc()
	red := color.New(color.FgRed, color.Bold).SprintFunc()

	switch riskLevel {
	case "CRITICAL":
		return red("[CRITICAL]")
	case "HIGH":
		return red("[HIGH]")
	case "MEDIUM":
		return yellow("[MEDIUM]")
	case "LOW":
		return green("[LOW]")
	default:
		return "[UNKNOWN]"
	}
}

// getIssueColor returns the appropriate color function for an issue severity
func getIssueColor(severity string) func(a ...interface{}) string {
	red := color.New(color.FgRed).SprintFunc()
	yellow := color.New(color.FgYellow).SprintFunc()
	green := color.New(color.FgGreen).SprintFunc()

	switch severity {
	case "CRITICAL", "HIGH":
		return red
	case "MEDIUM":
		return yellow
	case "LOW", "INFO":
		return green
	default:
		return green
	}
}

// runDoctor executes the doctor command
func runDoctor(cmd *cobra.Command, args []string) error {
	// Run all diagnostics
	results := diagnostics.RunAll(version, commit, doctorVerbose)

	// Output based on format
	if doctorJSON {
		err := results.OutputJSON()
		if err != nil {
			return err
		}
	} else {
		results.OutputTerminal()
	}

	// Return appropriate exit code
	exitCode := results.GetExitCode()
	if exitCode != 0 {
		os.Exit(exitCode)
	}

	return nil
}

// saveState saves the scan results to state file
func saveState(
	containers []models.Container,
	networks []models.NetworkInfo,
	firewallInfo *models.FirewallInfo,
	sshConfig *security.SSHConfig,
	fail2banStatus *security.Fail2banStatus,
	systemStatus *security.SystemSecurityStatus,
	riskSummary models.RiskSummary,
	score int,
	quiet bool,
) {
	// Create state manager
	stateMgr, err := state.NewManager()
	if err != nil {
		if !quiet {
			fmt.Fprintf(os.Stderr, "Warning: failed to create state manager: %v\n", err)
		}
		return
	}

	// Get hostname
	hostname, _ := os.Hostname()
	if hostname == "" {
		hostname = "unknown"
	}

	// Create security checks struct
	securityChecks := &models.SecurityChecks{
		SSH:      sshConfig,
		Fail2ban: fail2banStatus,
		System:   systemStatus,
	}

	// Create scan result
	result := &models.ScanResult{
		Timestamp:      time.Now(),
		Hostname:       hostname,
		Containers:     containers,
		Networks:       networks,
		Firewall:       firewallInfo,
		SecurityChecks: securityChecks,
		RiskSummary:    riskSummary,
		OverallScore:   score,
	}

	// Save to file
	err = stateMgr.Save(result)
	if err != nil {
		if !quiet {
			fmt.Fprintf(os.Stderr, "Warning: failed to save state: %v\n", err)
		}
		return
	}

	if !quiet && verboseMode {
		fmt.Printf("\nState saved to %s\n", stateMgr.GetPath())
	}
}

// runStatus executes the status command
func runStatus(cmd *cobra.Command, args []string) error {
	// Create state manager
	stateMgr, err := state.NewManager()
	if err != nil {
		return fmt.Errorf("failed to create state manager: %w", err)
	}

	// Check if state exists
	if !stateMgr.Exists() {
		return fmt.Errorf("no previous scan found. Run 'dockershield scan' first")
	}

	// Check age if max-age is set
	age, err := stateMgr.GetAge()
	if err != nil {
		return fmt.Errorf("failed to check state age: %w", err)
	}

	// If stale and fresh flag is set, run new scan
	if age > statusMaxAge && statusFresh {
		fmt.Printf("⚠️  Last scan was %s ago (stale). Running new scan...\n\n", formatDuration(age))
		return runScan(cmd, args)
	}

	// Load state
	result, err := stateMgr.Load()
	if err != nil {
		return fmt.Errorf("failed to load state: %w", err)
	}

	// Output based on format
	if statusJSON {
		return reporter.FormatStatusJSON(result)
	}

	reporter.FormatStatusTerminal(result)
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
			return "1 minute"
		}
		return fmt.Sprintf("%d minutes", minutes)
	}
	if d < 24*time.Hour {
		hours := int(d.Hours())
		if hours == 1 {
			return "1 hour"
		}
		return fmt.Sprintf("%d hours", hours)
	}
	days := int(d.Hours() / 24)
	if days == 1 {
		return "1 day"
	}
	return fmt.Sprintf("%d days", days)
}

// runCheck executes a category-specific check
func runCheck(cmd *cobra.Command, args []string) error {
	category := args[0]

	// Create scanner options
	opts := scanner.CheckOptions{
		JSON:      checkJSON,
		Container: checkContainer,
		Severity:  checkSeverity,
		Quiet:     checkJSON, // Suppress progress in JSON mode
	}

	// If "all" category, delegate to scan command
	if category == "all" {
		return runScan(cmd, []string{})
	}

	// Run the appropriate category scanner
	var result *scanner.CategoryResult
	var err error

	switch category {
	case "ports":
		result, err = scanner.CheckPorts(opts)
	case "networks":
		result, err = scanner.CheckNetworks(opts)
	case "firewall":
		result, err = scanner.CheckFirewall(opts)
	case "containers":
		result, err = scanner.CheckContainers(opts)
	default:
		return fmt.Errorf("unknown category: %s (valid: ports, networks, firewall, containers, all)", category)
	}

	if err != nil {
		return err
	}

	// Output results
	if checkJSON {
		return result.FormatJSON()
	}

	result.FormatTerminal()
	return nil
}

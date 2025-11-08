package models

import "time"

// ExposureType represents how a port is exposed
type ExposureType string

const (
	ExposurePublic     ExposureType = "public"      // 0.0.0.0 or ::
	ExposureLocalhost  ExposureType = "localhost"   // 127.0.0.1
	ExposureSpecificIP ExposureType = "specific_ip" // Specific IP address
)

// RiskLevel represents the severity of a security finding
type RiskLevel string

const (
	RiskCritical RiskLevel = "critical" // Database ports on public internet
	RiskHigh     RiskLevel = "high"     // Admin interfaces exposed
	RiskMedium   RiskLevel = "medium"   // Standard services
	RiskLow      RiskLevel = "low"      // Localhost bindings
	RiskInfo     RiskLevel = "info"     // Informational
)

// PortBinding represents a container port binding
type PortBinding struct {
	HostIP        string       `json:"host_ip"`        // IP address (e.g., "0.0.0.0", "127.0.0.1")
	HostPort      string       `json:"host_port"`      // Host port number
	ContainerPort string       `json:"container_port"` // Container port number
	Protocol      string       `json:"protocol"`       // tcp or udp
	ExposureType  ExposureType `json:"exposure_type"`  // How exposed is this port
	RiskLevel     RiskLevel    `json:"risk_level"`     // Calculated risk
	RiskReason    string       `json:"risk_reason"`    // Why this risk level
}

// Container represents a Docker container with security info
type Container struct {
	ID          string        `json:"id"`
	Name        string        `json:"name"`
	Image       string        `json:"image"`
	State       string        `json:"state"`
	NetworkMode string        `json:"network_mode"`
	Ports       []PortBinding `json:"ports"`
	Networks    []string      `json:"networks"`
	HighestRisk RiskLevel     `json:"highest_risk"`
	RiskCount   RiskSummary   `json:"risk_count"`
	CreatedAt   time.Time     `json:"created_at"`
}

// RiskSummary counts issues by severity
type RiskSummary struct {
	Critical int `json:"critical"`
	High     int `json:"high"`
	Medium   int `json:"medium"`
	Low      int `json:"low"`
	Info     int `json:"info"`
}

// NetworkInfo represents a Docker network
type NetworkInfo struct {
	ID         string   `json:"id"`
	Name       string   `json:"name"`
	Driver     string   `json:"driver"`     // bridge, host, overlay, etc.
	Subnet     string   `json:"subnet"`     // Network CIDR
	Gateway    string   `json:"gateway"`    // Gateway IP
	Containers []string `json:"containers"` // Container IDs in this network
}

// FirewallInfo contains firewall analysis results
type FirewallInfo struct {
	UFWActive          bool     `json:"ufw_active"`
	DockerDetected     bool     `json:"docker_detected"`
	DockerBypassingUFW bool     `json:"docker_bypassing_ufw"`
	DockerChains       []string `json:"docker_chains,omitempty"`
	Warning            string   `json:"warning,omitempty"`
}

// SecurityChecks contains system-level security analysis results
type SecurityChecks struct {
	SSH       interface{} `json:"ssh,omitempty"`       // SSHConfig from internal/security
	Fail2ban  interface{} `json:"fail2ban,omitempty"`  // Fail2banStatus from internal/security
	System    interface{} `json:"system,omitempty"`    // SystemSecurityStatus from internal/security
	Hardening interface{} `json:"hardening,omitempty"` // HardeningStatus from internal/security
	Users     interface{} `json:"users,omitempty"`     // UserHardeningStatus from internal/security
	Rootkit   interface{} `json:"rootkit,omitempty"`   // RootkitStatus from internal/security
	Integrity interface{} `json:"integrity,omitempty"` // IntegrityStatus from internal/security
	Logs      interface{} `json:"logs,omitempty"`      // LogAnalysisStatus from internal/security
}

// ScanResult is the complete output of a security scan
type ScanResult struct {
	Timestamp      time.Time       `json:"timestamp"`
	Hostname       string          `json:"hostname"`
	Containers     []Container     `json:"containers"`
	Networks       []NetworkInfo   `json:"networks"`
	Firewall       *FirewallInfo   `json:"firewall,omitempty"`
	SecurityChecks *SecurityChecks `json:"security_checks,omitempty"` // New system security checks
	RiskSummary    RiskSummary     `json:"risk_summary"`
	OverallScore   int             `json:"overall_score"` // 0-100, lower is worse
}

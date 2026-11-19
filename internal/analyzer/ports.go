package analyzer

import (
	"fmt"
	"strconv"

	"github.com/adrian13508/dockershield/pkg/models"
)

// PortInfo contains metadata about a known port
type PortInfo struct {
	Port        int
	Service     string
	Category    string // "database", "admin", "web", "cache", etc.
	BaseRisk    models.RiskLevel
	Description string
}

// Well-known dangerous ports database
// These are ports that should NEVER be exposed to 0.0.0.0
var dangerousPorts = map[int]PortInfo{
	// CRITICAL: Database ports
	3306:  {3306, "MySQL", "database", models.RiskCritical, "MySQL database"},
	5432:  {5432, "PostgreSQL", "database", models.RiskCritical, "PostgreSQL database"},
	6379:  {6379, "Redis", "database", models.RiskCritical, "Redis cache/database"},
	27017: {27017, "MongoDB", "database", models.RiskCritical, "MongoDB database"},
	27018: {27018, "MongoDB", "database", models.RiskCritical, "MongoDB shard"},
	27019: {27019, "MongoDB", "database", models.RiskCritical, "MongoDB config server"},
	9200:  {9200, "Elasticsearch", "database", models.RiskCritical, "Elasticsearch"},
	9300:  {9300, "Elasticsearch", "database", models.RiskCritical, "Elasticsearch cluster"},
	5984:  {5984, "CouchDB", "database", models.RiskCritical, "CouchDB database"},
	8086:  {8086, "InfluxDB", "database", models.RiskCritical, "InfluxDB"},
	7000:  {7000, "Cassandra", "database", models.RiskCritical, "Cassandra"},
	7001:  {7001, "Cassandra", "database", models.RiskCritical, "Cassandra SSL"},

	// HIGH: Admin interfaces and management tools
	8080:  {8080, "HTTP Alt", "admin", models.RiskHigh, "Alternative HTTP (often admin panels)"},
	8443:  {8443, "HTTPS Alt", "admin", models.RiskHigh, "Alternative HTTPS"},
	9090:  {9090, "Prometheus", "admin", models.RiskHigh, "Prometheus monitoring"},
	3000:  {3000, "Grafana", "admin", models.RiskHigh, "Grafana dashboard"},
	8888:  {8888, "Admin Panel", "admin", models.RiskHigh, "Common admin panel port"},
	9000:  {9000, "Portainer", "admin", models.RiskHigh, "Portainer Docker UI"},
	2375:  {2375, "Docker", "admin", models.RiskCritical, "Docker daemon (unencrypted)"},
	2376:  {2376, "Docker", "admin", models.RiskHigh, "Docker daemon (TLS)"},
	6443:  {6443, "Kubernetes", "admin", models.RiskHigh, "Kubernetes API server"},
	10250: {10250, "Kubelet", "admin", models.RiskHigh, "Kubernetes Kubelet API"},

	// MEDIUM: Standard web services
	// 80/443 are normally meant to be public (reverse proxy), so they rate low
	80:   {80, "HTTP", "web", models.RiskLow, "HTTP web server"},
	443:  {443, "HTTPS", "web", models.RiskLow, "HTTPS web server"},
	8000: {8000, "HTTP Alt", "web", models.RiskMedium, "Development web server"},
	3001: {3001, "Node.js", "web", models.RiskMedium, "Node.js app (common dev port)"},
	5000: {5000, "Flask", "web", models.RiskMedium, "Flask/Python app"},

	// HIGH: Remote access
	22:   {22, "SSH", "remote", models.RiskHigh, "SSH server"},
	23:   {23, "Telnet", "remote", models.RiskCritical, "Telnet (unencrypted)"},
	3389: {3389, "RDP", "remote", models.RiskHigh, "Windows Remote Desktop"},
	5900: {5900, "VNC", "remote", models.RiskHigh, "VNC remote desktop"},

	// MEDIUM: Message queues
	5672:  {5672, "RabbitMQ", "queue", models.RiskMedium, "RabbitMQ"},
	15672: {15672, "RabbitMQ", "queue", models.RiskHigh, "RabbitMQ management"},
	9092:  {9092, "Kafka", "queue", models.RiskMedium, "Apache Kafka"},
	4222:  {4222, "NATS", "queue", models.RiskMedium, "NATS messaging"},

	// MEDIUM: Other services
	11211: {11211, "Memcached", "cache", models.RiskHigh, "Memcached"},
	25:    {25, "SMTP", "mail", models.RiskMedium, "SMTP mail server"},
	53:    {53, "DNS", "dns", models.RiskMedium, "DNS server"},
}

// AnalyzePortRisk determines the risk level of a port binding
// It considers both the port number and how it's exposed
func AnalyzePortRisk(binding *models.PortBinding) {
	portNum, err := strconv.Atoi(binding.ContainerPort)
	if err != nil {
		// Invalid port number, treat as low risk
		binding.RiskLevel = models.RiskLow
		binding.RiskReason = "Unknown port"
		return
	}

	// Look up port in our database
	portInfo, isKnown := dangerousPorts[portNum]

	service := "Port"
	if isKnown {
		service = portInfo.Service
	}

	switch {
	case binding.ExposureType == models.ExposurePublic, binding.AddressScope == models.ScopePublicAddress:
		// Reachable from other machines unless a firewall in front says otherwise
		binding.RiskLevel = models.RiskMedium
		if isKnown {
			binding.RiskLevel = portInfo.BaseRisk
		}
		if binding.ExposureType == models.ExposurePublic {
			binding.RiskReason = service + " published on all interfaces"
		} else {
			binding.RiskReason = fmt.Sprintf("%s published on public address %s", service, binding.HostIP)
		}

	case binding.ExposureType == models.ExposureLocalhost:
		binding.RiskLevel = models.RiskLow
		if isKnown {
			binding.RiskReason = fmt.Sprintf("%s (localhost only - OK)", portInfo.Service)
		} else {
			binding.RiskReason = "Localhost only"
		}

	default:
		// Private or VPN address: reachable only from that network
		if isKnown && portInfo.BaseRisk == models.RiskCritical {
			binding.RiskLevel = models.RiskMedium
			binding.RiskReason = fmt.Sprintf("%s on private or VPN address %s (check who can reach that network)", portInfo.Service, binding.HostIP)
		} else {
			binding.RiskLevel = models.RiskLow
			binding.RiskReason = "Bound to private or VPN address"
		}
	}
}

// GetPortInfo returns information about a port if it's in our database
func GetPortInfo(portNum int) (PortInfo, bool) {
	info, exists := dangerousPorts[portNum]
	return info, exists
}

// IsHighRiskPort returns true if the port is considered high risk
func IsHighRiskPort(portNum int) bool {
	info, exists := dangerousPorts[portNum]
	if !exists {
		return false
	}
	return info.BaseRisk == models.RiskCritical || info.BaseRisk == models.RiskHigh
}

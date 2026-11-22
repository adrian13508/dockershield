package analyzer

import (
	"net/netip"
	"strings"

	"github.com/adrian13508/skobel/pkg/models"
)

// 100.64.0.0/10: carrier-grade NAT range, also used by Tailscale
var cgnat = netip.MustParsePrefix("100.64.0.0/10")

// ClassifyHostIP maps the host address of a port binding to an exposure type
// (the original three-value field) and a finer address scope.
func ClassifyHostIP(hostIP string) (models.ExposureType, models.AddressScope) {
	hostIP = strings.Trim(hostIP, "[]")
	if hostIP == "" {
		// Podman reports an empty host IP for a binding on all interfaces
		return models.ExposurePublic, models.ScopeAllInterfaces
	}
	addr, err := netip.ParseAddr(hostIP)
	if err != nil {
		// Not an address we understand: assume it is reachable
		return models.ExposureSpecificIP, models.ScopePublicAddress
	}
	addr = addr.Unmap()
	switch {
	case addr.IsUnspecified():
		return models.ExposurePublic, models.ScopeAllInterfaces
	case addr.IsLoopback():
		return models.ExposureLocalhost, models.ScopeLocalhost
	case addr.IsPrivate(), addr.IsLinkLocalUnicast(), cgnat.Contains(addr):
		return models.ExposureSpecificIP, models.ScopePrivateOrVPN
	default:
		return models.ExposureSpecificIP, models.ScopePublicAddress
	}
}

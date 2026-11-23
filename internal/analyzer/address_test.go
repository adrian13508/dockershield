package analyzer

import (
	"testing"

	"github.com/adrian13508/skobel/pkg/models"
)

func TestClassifyHostIP(t *testing.T) {
	cases := []struct {
		ip       string
		exposure models.ExposureType
		scope    models.AddressScope
	}{
		{"0.0.0.0", models.ExposurePublic, models.ScopeAllInterfaces},
		{"::", models.ExposurePublic, models.ScopeAllInterfaces},
		{"[::]", models.ExposurePublic, models.ScopeAllInterfaces},
		{"", models.ExposurePublic, models.ScopeAllInterfaces},
		{"127.0.0.1", models.ExposureLocalhost, models.ScopeLocalhost},
		{"127.0.0.2", models.ExposureLocalhost, models.ScopeLocalhost},
		{"::1", models.ExposureLocalhost, models.ScopeLocalhost},
		{"10.0.0.5", models.ExposureSpecificIP, models.ScopePrivateOrVPN},
		{"192.168.1.10", models.ExposureSpecificIP, models.ScopePrivateOrVPN},
		{"172.17.0.1", models.ExposureSpecificIP, models.ScopePrivateOrVPN},
		{"100.101.79.8", models.ExposureSpecificIP, models.ScopePrivateOrVPN},
		{"fd7a:115c:a1e0::1", models.ExposureSpecificIP, models.ScopePrivateOrVPN},
		{"fe80::1", models.ExposureSpecificIP, models.ScopePrivateOrVPN},
		{"203.0.113.7", models.ExposureSpecificIP, models.ScopePublicAddress},
		{"2001:db8::1", models.ExposureSpecificIP, models.ScopePublicAddress},
		{"not-an-ip", models.ExposureSpecificIP, models.ScopePublicAddress},
	}
	for _, c := range cases {
		exposure, scope := ClassifyHostIP(c.ip)
		if exposure != c.exposure || scope != c.scope {
			t.Errorf("ClassifyHostIP(%q) = %s/%s, want %s/%s", c.ip, exposure, scope, c.exposure, c.scope)
		}
	}
}

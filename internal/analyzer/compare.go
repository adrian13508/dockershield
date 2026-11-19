package analyzer

import (
	"github.com/adrian13508/dockershield/pkg/models"
)

// Diff is the difference between two scans of the same host
type Diff struct {
	OldScore, NewScore int
	Resolved           []models.Finding // in the old report only
	New                []models.Finding // in the new report only
	Remaining          []models.Finding // in both
	Recomputed         bool             // a report had no findings list (v0.1.3 or older) and was rated with current rules
}

// Compare matches findings of two reports by ID, container and port.
func Compare(old, new models.ScanResult) Diff {
	d := Diff{OldScore: old.OverallScore, NewScore: new.OverallScore}
	oldFindings := findingsOf(&old, &d)
	newFindings := findingsOf(&new, &d)
	if d.Recomputed {
		d.OldScore, d.NewScore = old.OverallScore, new.OverallScore
	}

	inNew := map[string]bool{}
	for _, f := range newFindings {
		inNew[findingKey(f)] = true
	}
	inOld := map[string]bool{}
	for _, f := range oldFindings {
		inOld[findingKey(f)] = true
		if !inNew[findingKey(f)] {
			d.Resolved = append(d.Resolved, f)
		}
	}
	for _, f := range newFindings {
		if inOld[findingKey(f)] {
			d.Remaining = append(d.Remaining, f)
		} else {
			d.New = append(d.New, f)
		}
	}
	return d
}

func findingKey(f models.Finding) string {
	key := f.ID + "|" + f.Container + "|" + f.Port
	if f.Container == "" && f.Port == "" && len(f.Addresses) > 0 {
		key += "|" + f.Addresses[0] // daemon listeners differ by address
	}
	return key
}

// findingsOf returns the report's findings. Reports written before findings
// existed are rated again from their container list with the current rules,
// so that both sides of a comparison are measured the same way. Firewall and
// daemon findings cannot be reconstructed for such reports.
func findingsOf(report *models.ScanResult, d *Diff) []models.Finding {
	if report.Findings != nil {
		return report.Findings
	}
	d.Recomputed = true
	for i := range report.Containers {
		for j := range report.Containers[i].Ports {
			p := &report.Containers[i].Ports[j]
			p.ExposureType, p.AddressScope = ClassifyHostIP(p.HostIP)
		}
	}
	summary := AnalyzeContainers(report.Containers)
	findings := BuildFindings(report.Containers, nil, nil)
	AddToSummary(&summary, findings)
	report.OverallScore = CalculateSecurityScore(summary)
	return findings
}

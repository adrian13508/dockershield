package analyzer

import (
	"github.com/adrian13508/skobel/pkg/models"
)

// Diff is the difference between two scans of the same host
type Diff struct {
	OldScore, NewScore int
	Resolved           []models.Finding // in the old report only
	New                []models.Finding // in the new report only
	Remaining          []models.Finding // in both
	Recomputed         bool             // a report had no findings list (v0.1.3 or older): both were rated again with current rules
}

// Compare matches findings of two reports by ID, container and port.
// If either report was written before findings existed (v0.1.3 or older),
// both are rated again from their container lists with the current rules, so
// that the two sides are measured the same way. Firewall and daemon findings
// cannot be reconstructed for such a report and are left out on both sides.
func Compare(before, after models.ScanResult) Diff {
	d := Diff{OldScore: before.OverallScore, NewScore: after.OverallScore}
	oldFindings, newFindings := before.Findings, after.Findings
	if oldFindings == nil || newFindings == nil {
		d.Recomputed = true
		oldFindings, d.OldScore = rate(&before)
		newFindings, d.NewScore = rate(&after)
	}

	// Counts, not a set: two findings can share a key (the same host port
	// on two addresses that are rated differently).
	inOld := map[string]int{}
	for _, f := range oldFindings {
		inOld[findingKey(f)]++
	}
	inNew := map[string]int{}
	for _, f := range newFindings {
		key := findingKey(f)
		inNew[key]++
		if inNew[key] <= inOld[key] {
			d.Remaining = append(d.Remaining, f)
		} else {
			d.New = append(d.New, f)
		}
	}
	seen := map[string]int{}
	for _, f := range oldFindings {
		key := findingKey(f)
		seen[key]++
		if seen[key] > inNew[key] {
			d.Resolved = append(d.Resolved, f)
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

// rate computes findings and score from a report's container list
func rate(report *models.ScanResult) ([]models.Finding, int) {
	for i := range report.Containers {
		for j := range report.Containers[i].Ports {
			p := &report.Containers[i].Ports[j]
			p.ExposureType, p.AddressScope = ClassifyHostIP(p.HostIP)
		}
	}
	summary := AnalyzeContainers(report.Containers)
	findings := BuildFindings(report.Containers, nil, nil)
	AddToSummary(&summary, findings)
	return findings, CalculateSecurityScore(summary)
}

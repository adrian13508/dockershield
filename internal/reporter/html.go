package reporter

import (
	"bytes"
	_ "embed"
	"html/template"
	"strings"

	"github.com/adrian13508/dockershield/internal/analyzer"
	"github.com/adrian13508/dockershield/pkg/models"
)

//go:embed report.html.tmpl
var reportTemplate string

var reportTmpl = template.Must(template.New("report").Funcs(template.FuncMap{
	"upper": strings.ToUpper,
	"join":  strings.Join,
	"inc":   func(i int) int { return i + 1 },
}).Parse(reportTemplate))

type htmlPort struct {
	Container string
	models.PortBinding
}

type htmlData struct {
	models.ScanResult
	Rating  string
	Version string
	Ports   []htmlPort // bindings of running containers
}

// GenerateHTML renders a scan result as one self-contained HTML file: inline
// CSS, no scripts, no external resources, laid out to print cleanly.
// All values go through html/template escaping; container names and images
// are not trusted.
func GenerateHTML(result models.ScanResult, version string) ([]byte, error) {
	data := htmlData{
		ScanResult: result,
		Rating:     analyzer.GetScoreRating(result.OverallScore),
		Version:    version,
	}
	for _, c := range result.Containers {
		if c.State != "running" {
			continue
		}
		for _, p := range c.Ports {
			data.Ports = append(data.Ports, htmlPort{Container: c.Name, PortBinding: p})
		}
	}

	var buf bytes.Buffer
	if err := reportTmpl.Execute(&buf, data); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

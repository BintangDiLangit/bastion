package sbom

import (
	"fmt"
	"time"

	"code-security-auditor/internal/dependency"

	"github.com/CycloneDX/cyclonedx-go"
	"github.com/google/uuid"
	"github.com/sirupsen/logrus"
)

type CycloneDXGenerator struct {
	logger *logrus.Logger
}

func NewCycloneDXGenerator(logger *logrus.Logger) *CycloneDXGenerator {
	return &CycloneDXGenerator{logger: logger}
}

func (g *CycloneDXGenerator) Generate(manifest *dependency.DependencyManifest, vulnReports []dependency.VulnerabilityReport) (*cyclonedx.BOM, error) {
	metadata := g.buildMetadata(manifest)
	components := g.buildComponents(manifest.AllDependencies)
	vulnerabilities := g.buildVulnerabilities(vulnReports)

	bom := cyclonedx.NewBOM()
	bom.SerialNumber = "urn:uuid:" + uuid.New().String()
	bom.Metadata = &metadata
	bom.Components = &components

	if len(vulnerabilities) > 0 {
		bom.Vulnerabilities = &vulnerabilities
	}

	return bom, nil
}

func (g *CycloneDXGenerator) buildMetadata(manifest *dependency.DependencyManifest) cyclonedx.Metadata {
	return cyclonedx.Metadata{
		Timestamp: time.Now().Format(time.RFC3339),
		Tools: &cyclonedx.ToolsChoice{
			Tools: &[]cyclonedx.Tool{
				{
					Vendor:  "Bastion Security",
					Name:    "Bastion Code Security Auditor",
					Version: "1.0.0",
				},
			},
		},
		Component: &cyclonedx.Component{
			Type:    cyclonedx.ComponentTypeApplication,
			Name:    manifest.Metadata.ProjectName,
			Version: manifest.Metadata.ProjectVersion,
		},
	}
}

func (g *CycloneDXGenerator) buildComponents(deps []dependency.Dependency) []cyclonedx.Component {
	var components []cyclonedx.Component
	for _, dep := range deps {
		comp := cyclonedx.Component{
			Type:       cyclonedx.ComponentTypeLibrary,
			Name:       dep.Name,
			Version:    dep.Version,
			PackageURL: g.generatePURL(dep),
		}

		if dep.License != "" {
			comp.Licenses = &cyclonedx.Licenses{
				{
					License: &cyclonedx.License{
						ID: dep.License, // Assuming SPDX ID, otherwise should use Name
					},
				},
			}
		}

		components = append(components, comp)
	}
	return components
}

func (g *CycloneDXGenerator) buildVulnerabilities(reports []dependency.VulnerabilityReport) []cyclonedx.Vulnerability {
	var vulns []cyclonedx.Vulnerability
	for _, report := range reports {
		for _, v := range report.Vulnerabilities {
			cdxVuln := cyclonedx.Vulnerability{
				ID: v.ID,
				Source: &cyclonedx.Source{
					Name: "Bastion",
				},
				Description: v.Description,
				Affects: &[]cyclonedx.Affects{
					{
						Ref: g.generatePURL(report.Dependency),
					},
				},
			}

			// Map Severity roughly
			rating := cyclonedx.VulnerabilityRating{
				Source: &cyclonedx.Source{Name: "Bastion"},
			}
			switch v.Severity {
			case "CRITICAL":
				rating.Severity = cyclonedx.SeverityCritical
			case "HIGH":
				rating.Severity = cyclonedx.SeverityHigh
			case "MEDIUM":
				rating.Severity = cyclonedx.SeverityMedium
			case "LOW":
				rating.Severity = cyclonedx.SeverityLow
			default:
				rating.Severity = cyclonedx.SeverityInfo
			}
			cdxVuln.Ratings = &[]cyclonedx.VulnerabilityRating{rating}

			vulns = append(vulns, cdxVuln)
		}
	}
	return vulns
}

func (g *CycloneDXGenerator) generatePURL(dep dependency.Dependency) string {
	// Simple PURL generation - would need to know ecosystem here effectively
	// e.g. pkg:npm/lodash@4.17.20
	// We might need to pass ecosystem or store it
	return fmt.Sprintf("pkg:generic/%s@%s", dep.Name, dep.Version)
}

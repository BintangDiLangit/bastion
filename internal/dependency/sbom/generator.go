package sbom

import (
	"encoding/json"
	"time"

	"code-security-auditor/internal/dependency"
)

// Generator creates SBOMs
type Generator struct{}

func NewGenerator() *Generator {
	return &Generator{}
}

// TODO: Use actual CycloneDX definitions
// Minimal structure for demonstration
type CycloneDX struct {
	BomFormat   string      `json:"bomFormat"`
	SpecVersion string      `json:"specVersion"`
	Version     int         `json:"version"`
	Metadata    CDXMetadata `json:"metadata"`
	Components  []Component `json:"components"`
}

type CDXMetadata struct {
	Timestamp string `json:"timestamp"`
	Tool      Tool   `json:"tool"`
}

type Tool struct {
	Vendor  string `json:"vendor"`
	Name    string `json:"name"`
	Version string `json:"version"`
}

type Component struct {
	Type    string `json:"type"`
	Name    string `json:"name"`
	Version string `json:"version"`
	Purl    string `json:"purl,omitempty"` // Package URL
	License string `json:"license,omitempty"`
}

// GenerateCycloneDXJSON creates a simple CycloneDX 1.4 JSON SBOM
func (g *Generator) GenerateCycloneDXJSON(manifest *dependency.DependencyManifest) ([]byte, error) {
	cdx := CycloneDX{
		BomFormat:   "CycloneDX",
		SpecVersion: "1.4",
		Version:     1,
		Metadata: CDXMetadata{
			Timestamp: time.Now().Format(time.RFC3339),
			Tool: Tool{
				Vendor:  "Bastion",
				Name:    "Code Security Auditor",
				Version: "1.0.0",
			},
		},
	}

	for _, dep := range manifest.AllDependencies {
		comp := Component{
			Type:    "library",
			Name:    dep.Name,
			Version: dep.Version,
			License: dep.License,
			// Simplified PURL generation
			Purl: "pkg:" + string(manifest.PackageManager) + "/" + dep.Name + "@" + dep.Version,
		}
		cdx.Components = append(cdx.Components, comp)
	}

	return json.MarshalIndent(cdx, "", "  ")
}

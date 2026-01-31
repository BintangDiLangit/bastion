package sbom

import (
	"bytes"
	"context"
	"fmt"

	"code-security-auditor/internal/dependency"

	"github.com/CycloneDX/cyclonedx-go"
	"github.com/sirupsen/logrus"
)

type SBOMFormat string

const (
	CycloneDX SBOMFormat = "cyclonedx"
	SPDX      SBOMFormat = "spdx"
)

type OutputType string

const (
	JSON OutputType = "json"
	XML  OutputType = "xml"
)

type SBOMOptions struct {
	Format                 SBOMFormat
	OutputType             OutputType
	IncludeVulnerabilities bool
	IncludeLicenses        bool
	IncludeHashes          bool
}

type Generator struct {
	logger       *logrus.Logger
	cdxGenerator *CycloneDXGenerator
}

func NewGenerator(logger *logrus.Logger) *Generator {
	return &Generator{
		logger:       logger,
		cdxGenerator: NewCycloneDXGenerator(logger),
	}
}

// Generate creates an SBOM based on options
func (g *Generator) Generate(ctx context.Context, manifest *dependency.DependencyManifest, vulnReports []dependency.VulnerabilityReport, opts SBOMOptions) ([]byte, error) {
	switch opts.Format {
	case CycloneDX:
		return g.generateCycloneDX(manifest, vulnReports, opts)
	case SPDX:
		return nil, fmt.Errorf("SPDX format not yet implemented")
	default:
		// Default to CycloneDX JSON
		return g.generateCycloneDX(manifest, vulnReports, opts)
	}
}

func (g *Generator) generateCycloneDX(manifest *dependency.DependencyManifest, vulnReports []dependency.VulnerabilityReport, opts SBOMOptions) ([]byte, error) {
	bom, err := g.cdxGenerator.Generate(manifest, vulnReports)
	if err != nil {
		return nil, err
	}

	var buf bytes.Buffer
	encoder := cyclonedx.NewBOMEncoder(&buf, cyclonedx.BOMFileFormatJSON)
	encoder.SetPretty(true)

	if err := encoder.Encode(bom); err != nil {
		return nil, fmt.Errorf("failed to encode CycloneDX SBOM: %w", err)
	}

	return buf.Bytes(), nil
}

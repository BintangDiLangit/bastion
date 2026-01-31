package parsers

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"

	"code-security-auditor/internal/dependency"

	"github.com/sirupsen/logrus"
)

// NPMParser handles package.json and package-lock.json
type NPMParser struct {
	logger *logrus.Logger
}

func NewNPMParser(logger *logrus.Logger) *NPMParser {
	return &NPMParser{logger: logger}
}

func (p *NPMParser) GetPackageManager() dependency.PackageManager {
	return dependency.NPM
}

func (p *NPMParser) SupportsFile(path string) bool {
	base := filepath.Base(path)
	return base == "package.json" || base == "package-lock.json"
}

func (p *NPMParser) Parse(ctx context.Context, filePath string) (*dependency.DependencyManifest, error) {
	if filepath.Base(filePath) != "package.json" {
		return nil, fmt.Errorf("NPMParser currently main entry point must be package.json")
	}

	data, err := os.ReadFile(filePath)
	if err != nil {
		return nil, fmt.Errorf("failed to read file: %w", err)
	}

	var pkg packageJSON
	if err := json.Unmarshal(data, &pkg); err != nil {
		return nil, fmt.Errorf("failed to unmarshal package.json: %w", err)
	}

	manifest := &dependency.DependencyManifest{
		FilePath:       filePath,
		PackageManager: dependency.NPM,
		Metadata: dependency.ManifestMetadata{
			ProjectName:    pkg.Name,
			ProjectVersion: pkg.Version,
			Language:       "javascript",
		},
	}

	// Parse direct dependencies
	for name, version := range pkg.Dependencies {
		manifest.DirectDependencies = append(manifest.DirectDependencies, dependency.Dependency{
			Name:              name,
			Version:           version, // For now, assume exact version or use constraint
			VersionConstraint: version,
			Type:              dependency.Production,
			IsDirect:          true,
		})
	}

	// Parse dev dependencies
	for name, version := range pkg.DevDependencies {
		manifest.DevDependencies = append(manifest.DevDependencies, dependency.Dependency{
			Name:              name,
			Version:           version,
			VersionConstraint: version,
			Type:              dependency.Development,
			IsDirect:          true,
		})
	}

	// Combine all
	manifest.AllDependencies = append(manifest.AllDependencies, manifest.DirectDependencies...)
	manifest.AllDependencies = append(manifest.AllDependencies, manifest.DevDependencies...)

	return manifest, nil
}

type packageJSON struct {
	Name            string            `json:"name"`
	Version         string            `json:"version"`
	Dependencies    map[string]string `json:"dependencies"`
	DevDependencies map[string]string `json:"devDependencies"`
}

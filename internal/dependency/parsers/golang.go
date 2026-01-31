package parsers

import (
	"context"
	"fmt"
	"os"
	"path/filepath"

	"code-security-auditor/internal/dependency"

	"github.com/sirupsen/logrus"
	"golang.org/x/mod/modfile"
)

// GoModParser handles go.mod files
type GoModParser struct {
	logger *logrus.Logger
}

func NewGoModParser(logger *logrus.Logger) *GoModParser {
	return &GoModParser{logger: logger}
}

func (p *GoModParser) GetPackageManager() dependency.PackageManager {
	return dependency.GoMod
}

func (p *GoModParser) SupportsFile(path string) bool {
	return filepath.Base(path) == "go.mod"
}

func (p *GoModParser) Parse(ctx context.Context, filePath string) (*dependency.DependencyManifest, error) {
	data, err := os.ReadFile(filePath)
	if err != nil {
		return nil, fmt.Errorf("failed to read go.mod: %w", err)
	}

	f, err := modfile.Parse(filePath, data, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to parse go.mod: %w", err)
	}

	manifest := &dependency.DependencyManifest{
		FilePath:       filePath,
		PackageManager: dependency.GoMod,
		Metadata: dependency.ManifestMetadata{
			Language: "go",
		},
	}

	if f.Module != nil {
		manifest.Metadata.ProjectName = f.Module.Mod.Path
		manifest.Metadata.ProjectVersion = f.Module.Mod.Version
	}

	if f.Go != nil {
		manifest.Metadata.Language = fmt.Sprintf("go %s", f.Go.Version)
	}

	for _, require := range f.Require {
		dep := dependency.Dependency{
			Name:              require.Mod.Path,
			Version:           require.Mod.Version,
			VersionConstraint: require.Mod.Version,
			Type:              dependency.Production,
			IsDirect:          !require.Indirect,
			IsTransitive:      require.Indirect,
		}

		if require.Indirect {
			// In Go, usually all dependencies are listed in go.mod (direct + indirect)
			// We treat them as part of the full dependency list
			manifest.AllDependencies = append(manifest.AllDependencies, dep)
		} else {
			manifest.DirectDependencies = append(manifest.DirectDependencies, dep)
			manifest.AllDependencies = append(manifest.AllDependencies, dep)
		}
	}

	return manifest, nil
}

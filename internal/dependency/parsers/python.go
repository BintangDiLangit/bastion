package parsers

import (
	"bufio"
	"context"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"code-security-auditor/internal/dependency"

	"github.com/sirupsen/logrus"
)

// PipParser handles requirements.txt files
// Note: This is a simplified parser. Real-world python parsing is complex (setup.py, etc.)
type PipParser struct {
	logger *logrus.Logger
}

func NewPipParser(logger *logrus.Logger) *PipParser {
	return &PipParser{logger: logger}
}

func (p *PipParser) GetPackageManager() dependency.PackageManager {
	return dependency.Pip
}

func (p *PipParser) SupportsFile(path string) bool {
	return filepath.Base(path) == "requirements.txt"
}

func (p *PipParser) Parse(ctx context.Context, filePath string) (*dependency.DependencyManifest, error) {
	file, err := os.Open(filePath)
	if err != nil {
		return nil, fmt.Errorf("failed to open requirements.txt: %w", err)
	}
	defer file.Close()

	manifest := &dependency.DependencyManifest{
		FilePath:       filePath,
		PackageManager: dependency.Pip,
		Metadata: dependency.ManifestMetadata{
			Language: "python",
		},
	}

	scanner := bufio.NewScanner(file)
	// Regex for basic requirements: name==version, name>=version, etc.
	// Does not cover all PEP 508 cases
	re := regexp.MustCompile(`^([a-zA-Z0-9_\-\.]+)\s*(==|>=|<=|~=|!=)?\s*([a-zA-Z0-9_\-\.]*)?`)

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())

		// Skip comments and empty lines
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		// Skip flags like -r, -e
		if strings.HasPrefix(line, "-") {
			continue
		}

		matches := re.FindStringSubmatch(line)
		if len(matches) > 1 {
			name := matches[1]
			operator := matches[2]
			version := matches[3]

			constraint := ""
			if operator != "" {
				constraint = operator + version
			}

			dep := dependency.Dependency{
				Name:              name,
				Version:           version,
				VersionConstraint: constraint,
				Type:              dependency.Production,
				IsDirect:          true, // requirements.txt usually lists direct deps (or pinned transitive)
			}

			manifest.DirectDependencies = append(manifest.DirectDependencies, dep)
			manifest.AllDependencies = append(manifest.AllDependencies, dep)
		}
	}

	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("error scanning requirements.txt: %w", err)
	}

	return manifest, nil
}

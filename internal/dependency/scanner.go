package dependency

import (
	"context"
	"fmt"
	"time"

	"github.com/sirupsen/logrus"
)

// Scanner orchestrates the dependency scanning process
type Scanner struct {
	detector   *DependencyFileDetector
	parser     ParserManagerInterface       // Interface for ParserManager
	vulnClient VulnerabilityClientInterface // Interface for VulnClient
	// license    *license.Checker // Optional integration
	logger *logrus.Logger
}

// Interfaces to break circular imports if necessary or for easier mocking
type ParserManagerInterface interface {
	Parse(ctx context.Context, file DependencyFile) (*DependencyManifest, error)
}

type VulnerabilityClientInterface interface {
	CheckVulnerabilities(ctx context.Context, dep Dependency, pm PackageManager) ([]Vulnerability, error)
}

// Result represents the outcome of a dependency scan
type Result struct {
	Manifests       []DependencyManifest
	Vulnerabilities []Vulnerability
	ScannedFiles    int
	Duration        time.Duration
}

func NewScanner(
	detector *DependencyFileDetector,
	parser ParserManagerInterface,
	vulnClient VulnerabilityClientInterface,
	logger *logrus.Logger,
) *Scanner {
	return &Scanner{
		detector:   detector,
		parser:     parser,
		vulnClient: vulnClient,
		logger:     logger,
	}
}

// Scan performs a full dependency scan on the repository
func (s *Scanner) Scan(ctx context.Context, repoPath string) (*Result, error) {
	start := time.Now()

	files, err := s.detector.DetectDependencyFiles(ctx, repoPath)
	if err != nil {
		return nil, fmt.Errorf("failed to detect dependency files: %w", err)
	}

	result := &Result{
		ScannedFiles: len(files),
	}

	for _, file := range files {
		// Parse manifest
		manifest, err := s.parser.Parse(ctx, file)
		if err != nil {
			s.logger.Warnf("Failed to parse %s: %v", file.Path, err)
			continue
		}

		// Enrich dependencies with vulnerabilities
		for i, dep := range manifest.AllDependencies {
			vulns, err := s.vulnClient.CheckVulnerabilities(ctx, dep, manifest.PackageManager)
			if err != nil {
				s.logger.Warnf("Failed to check vulnerabilities for %s: %v", dep.Name, err)
				continue
			}

			if len(vulns) > 0 {
				manifest.AllDependencies[i].Vulnerabilities = vulns
				result.Vulnerabilities = append(result.Vulnerabilities, vulns...)
			}
		}

		result.Manifests = append(result.Manifests, *manifest)
	}

	result.Duration = time.Since(start)
	return result, nil
}

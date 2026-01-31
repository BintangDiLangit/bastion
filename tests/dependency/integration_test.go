package dependency_test

import (
	"context"
	"path/filepath"
	"testing"

	"code-security-auditor/internal/dependency"
	"code-security-auditor/internal/dependency/parsers"
	"code-security-auditor/internal/dependency/vulnerability"

	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestDependencyScanning(t *testing.T) {
	// Setup
	logger := logrus.New()
	logger.SetLevel(logrus.DebugLevel)
	ctx := context.Background()

	detector := dependency.NewDetector(logger)
	parserManager := dependency.NewParserManager(logger)

	// Register parsers
	parserManager.RegisterParser(dependency.NPM, parsers.NewNPMParser(logger))
	parserManager.RegisterParser(dependency.Pip, parsers.NewPipParser(logger))
	parserManager.RegisterParser(dependency.GoMod, parsers.NewGoModParser(logger))

	vulnClient := vulnerability.NewOSVClient(logger)

	scanner := dependency.NewScanner(detector, parserManager, vulnClient, logger)

	fixturesPath, _ := filepath.Abs("fixtures")

	t.Run("Scan NPM Project", func(t *testing.T) {
		path := filepath.Join(fixturesPath, "npm_project")
		result, err := scanner.Scan(ctx, path)
		require.NoError(t, err)

		assert.GreaterOrEqual(t, len(result.Manifests), 1)

		var npmManifest dependency.DependencyManifest
		found := false
		for _, m := range result.Manifests {
			if m.PackageManager == dependency.NPM {
				npmManifest = m
				found = true
				break
			}
		}
		require.True(t, found, "NPM manifest not found")

		// Check dependencies
		assert.Equal(t, "test-project", npmManifest.Metadata.ProjectName)

		// Expected: lodash, express, mocha
		foundLodash := false
		for _, dep := range npmManifest.AllDependencies {
			if dep.Name == "lodash" {
				foundLodash = true
				// Check for known vulnerability injected by mock client
				if assert.NotEmpty(t, dep.Vulnerabilities) {
					assert.Equal(t, "CVE-2020-8203", dep.Vulnerabilities[0].ID)
				}
			}
		}
		assert.True(t, foundLodash, "lodash dependency not found")
	})

	t.Run("Scan Python Project", func(t *testing.T) {
		path := filepath.Join(fixturesPath, "python_project")
		result, err := scanner.Scan(ctx, path)
		require.NoError(t, err)

		var pyManifest dependency.DependencyManifest
		found := false
		for _, m := range result.Manifests {
			if m.PackageManager == dependency.Pip {
				pyManifest = m
				found = true
				break
			}
		}
		require.True(t, found, "Python manifest not found")

		// Check for specific hacky mock "log4j" in python requirements just to test vuln client
		// (Yes, log4j isn't python, but for the mock it works based on name)
		foundLog4j := false
		for _, dep := range pyManifest.AllDependencies {
			if dep.Name == "log4j" {
				foundLog4j = true
				if assert.NotEmpty(t, dep.Vulnerabilities) {
					assert.Equal(t, "CVE-2021-44228", dep.Vulnerabilities[0].ID)
				}
			}
		}
		assert.True(t, foundLog4j, "log4j (mock) dependency not found")
	})

	t.Run("Scan Go Project", func(t *testing.T) {
		path := filepath.Join(fixturesPath, "go_project")
		result, err := scanner.Scan(ctx, path)
		require.NoError(t, err)

		var goManifest dependency.DependencyManifest
		found := false
		for _, m := range result.Manifests {
			if m.PackageManager == dependency.GoMod {
				goManifest = m
				found = true
				break
			}
		}
		require.True(t, found, "Go manifest not found")
		assert.Equal(t, "github.com/test/project", goManifest.Metadata.ProjectName)
	})
}

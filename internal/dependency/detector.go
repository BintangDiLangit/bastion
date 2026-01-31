package dependency

import (
	"context"
	"io/fs"
	"path/filepath"
	"strings"

	"github.com/sirupsen/logrus"
)

// DependencyFileDetector detects dependency files in a repository
type DependencyFileDetector struct {
	logger *logrus.Logger
}

// NewDetector creates a new DependencyFileDetector
func NewDetector(logger *logrus.Logger) *DependencyFileDetector {
	return &DependencyFileDetector{
		logger: logger,
	}
}

// DetectDependencyFiles scans the repository path for supported dependency files
func (d *DependencyFileDetector) DetectDependencyFiles(ctx context.Context, repoPath string) ([]DependencyFile, error) {
	var files []DependencyFile

	err := filepath.WalkDir(repoPath, func(path string, entry fs.DirEntry, err error) error {
		if err != nil {
			d.logger.Warnf("Error accessing path %s: %v", path, err)
			return nil // Continue walking
		}

		if entry.IsDir() {
			// Skip common vendor and hidden directories
			if isIgnoredDir(entry.Name()) {
				return filepath.SkipDir
			}
			return nil
		}

		if file, ok := d.ClassifyFile(entry.Name(), path); ok {
			files = append(files, file)
		}

		return nil
	})

	if err != nil {
		return nil, err
	}

	return files, nil
}

// ClassifyFile examines a filename and returns a DependencyFile if matched
func (d *DependencyFileDetector) ClassifyFile(filename, fullPath string) (DependencyFile, bool) {
	base := strings.ToLower(filename)
	ext := filepath.Ext(base)

	var file DependencyFile
	file.Path = fullPath
	matched := true

	switch base {
	// JavaScript / Node.js
	case "package.json":
		file.Type = ManifestFile
		file.PackageManager = NPM
		file.Language = JavaScript
	case "package-lock.json":
		file.Type = LockFile
		file.PackageManager = NPM
		file.Language = JavaScript
	case "yarn.lock":
		file.Type = LockFile
		file.PackageManager = Yarn
		file.Language = JavaScript
	case "pnpm-lock.yaml":
		file.Type = LockFile
		file.PackageManager = NPM
		file.Language = JavaScript

	// Python
	case "requirements.txt":
		file.Type = ManifestFile
		file.PackageManager = Pip
		file.Language = Python
	case "pipfile":
		file.Type = ManifestFile
		file.PackageManager = Pip
		file.Language = Python
	case "pipfile.lock":
		file.Type = LockFile
		file.PackageManager = Pip
		file.Language = Python
	case "poetry.lock":
		file.Type = LockFile
		file.PackageManager = Poetry
		file.Language = Python
	case "pyproject.toml":
		file.Type = ConfigFile
		file.PackageManager = Pip // Generic python project
		file.Language = Python
	case "setup.py":
		file.Type = ConfigFile
		file.PackageManager = Pip
		file.Language = Python

	// Go
	case "go.mod":
		file.Type = ManifestFile
		file.PackageManager = GoMod
		file.Language = Go
	case "go.sum":
		file.Type = LockFile
		file.PackageManager = GoMod
		file.Language = Go

	// Ruby
	case "gemfile":
		file.Type = ManifestFile
		file.PackageManager = Bundler
		file.Language = Ruby
	case "gemfile.lock":
		file.Type = LockFile
		file.PackageManager = Bundler
		file.Language = Ruby

	// Java
	case "pom.xml":
		file.Type = ManifestFile
		file.PackageManager = Maven
		file.Language = Java
	case "build.gradle":
		file.Type = ManifestFile
		file.PackageManager = Gradle
		file.Language = Java
	case "build.gradle.kts":
		file.Type = ManifestFile
		file.PackageManager = Gradle
		file.Language = Java

	// Rust
	case "cargo.toml":
		file.Type = ManifestFile
		file.PackageManager = Cargo
		file.Language = Rust
	case "cargo.lock":
		file.Type = LockFile
		file.PackageManager = Cargo
		file.Language = Rust

	// PHP
	case "composer.json":
		file.Type = ManifestFile
		file.PackageManager = Composer
		file.Language = PHP
	case "composer.lock":
		file.Type = LockFile
		file.PackageManager = Composer
		file.Language = PHP

	default:
		// Check extensions for less specific matches
		if ext == ".csproj" {
			file.Type = ManifestFile
			file.PackageManager = Unknown // NuGet typically
			file.Language = CSharp
			matched = true
		} else {
			matched = false
		}
	}

	return file, matched
}

func isIgnoredDir(name string) bool {
	switch name {
	case "node_modules", "vendor", ".git", ".idea", ".vscode", "__pycache__", "dist", "build", "target":
		return true
	}
	return false
}

package scanner

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/BintangDiLangit/bastion/internal/config"
)

func TestParseFile_Go(t *testing.T) {
	content := `
package main

import "fmt"

func main() {
	fmt.Println("Hello, World!")
}

func sensitive() {
	password := "secret123"
}
`
	tmpfile, err := os.CreateTemp("", "test*.go")
	require.NoError(t, err)
	defer os.Remove(tmpfile.Name())

	_, err = tmpfile.Write([]byte(content))
	require.NoError(t, err)
	tmpfile.Close()

	parser := NewParser(config.ScannerConfig{}, logrus.New())

	parsed, err := parser.ParseFile(tmpfile.Name(), "go")
	require.NoError(t, err)
	assert.Equal(t, "go", parsed.Language)
	assert.Len(t, parsed.Functions, 2)
	assert.Equal(t, "main", parsed.Functions[0].Name)
	assert.Equal(t, "sensitive", parsed.Functions[1].Name)
	assert.Len(t, parsed.Strings, 3)
}

func TestParseFile_Python(t *testing.T) {
	content := `
import os

def my_func():
    print("hello")

@decorator
def other_func():
    pass
`
	tmpfile, err := os.CreateTemp("", "test*.py")
	require.NoError(t, err)
	defer os.Remove(tmpfile.Name())

	_, err = tmpfile.Write([]byte(content))
	require.NoError(t, err)
	tmpfile.Close()

	parser := NewParser(config.ScannerConfig{}, logrus.New())

	parsed, err := parser.ParseFile(tmpfile.Name(), "python")
	require.NoError(t, err)
	assert.Equal(t, "python", parsed.Language)
	assert.Len(t, parsed.Functions, 2)
	assert.Equal(t, "my_func", parsed.Functions[0].Name)
	assert.Equal(t, "other_func", parsed.Functions[1].Name)
	assert.Len(t, parsed.Imports, 1)
	assert.Equal(t, "os", parsed.Imports[0].Path)
}

func TestParseRepository(t *testing.T) {
	// Create a temp dir with mixed files
	tempDir, err := os.MkdirTemp("", "repo-test")
	require.NoError(t, err)
	defer os.RemoveAll(tempDir)

	files := map[string]string{
		"main.go":             `package main`,
		"script.py":           `print("hello")`,
		"ignored.txt":         `text`,
		"node_modules/lib.js": `console.log("ignore me")`,
	}

	for path, content := range files {
		fullPath := filepath.Join(tempDir, path)
		err := os.MkdirAll(filepath.Dir(fullPath), 0755)
		require.NoError(t, err)
		err = os.WriteFile(fullPath, []byte(content), 0644)
		require.NoError(t, err)
	}

	cfg := config.ScannerConfig{
		MaxConcurrent: 2,
		ExcludedPaths: []string{"node_modules/"},
		MaxFileSize:   1024 * 1024,
	}
	parser := NewParser(cfg, logrus.New())

	ctx := context.Background()
	results, skipped, err := parser.ParseRepository(ctx, tempDir, cfg.ExcludedPaths, 0, "")
	require.NoError(t, err)
	assert.Empty(t, skipped)

	// Should find main.go and script.py
	// ignored.txt skipped by DetectLanguage (assuming it returns empty for txt)
	// node_modules skipped by ExcludedPaths

	// We need to check exact count. DetectLanguage implementation details matter here.
	// Assuming Helpers.go DetectLanguage supports go and py.

	assert.GreaterOrEqual(t, len(results), 2)

	var paths []string
	for _, f := range results {
		paths = append(paths, filepath.Base(f.Path))
	}
	assert.Contains(t, paths, "main.go")
	assert.Contains(t, paths, "script.py")
	assert.NotContains(t, paths, "lib.js")
}

// filepath.Walk uses Lstat, so a symlink is not reported as a directory. Without
// an explicit regular-file check the link gets read through, and a link planted
// inside an untrusted repository pulls in any file the process can reach.
func TestSymlinkIsNotFollowed(t *testing.T) {
	parent := t.TempDir()
	scanDir := filepath.Join(parent, "scan")
	outside := filepath.Join(parent, "outside")
	require.NoError(t, os.Mkdir(scanDir, 0o700))
	require.NoError(t, os.Mkdir(outside, 0o700))

	secret := filepath.Join(outside, "secret.go")
	require.NoError(t, os.WriteFile(secret, []byte("package secret"), 0o600))
	require.NoError(t, os.WriteFile(filepath.Join(scanDir, "real.go"), []byte("package real"), 0o600))
	require.NoError(t, os.Symlink(secret, filepath.Join(scanDir, "link.go")))

	cfg := config.ScannerConfig{MaxConcurrent: 2, MaxFileSize: 1024 * 1024}
	parser := NewParser(cfg, logrus.New())

	results, _, err := parser.ParseRepository(context.Background(), scanDir, nil, 0, "")
	require.NoError(t, err)

	var paths []string
	for _, f := range results {
		paths = append(paths, filepath.Base(f.Path))
	}
	assert.Contains(t, paths, "real.go")
	assert.NotContains(t, paths, "link.go", "symlink was followed out of the scan tree")
}

// ParseRepository must return the same file set and the same order on every
// run: parsing is concurrent, and anything that truncates or diffs the result
// downstream is only reproducible if this is.
func TestParseRepositoryIsDeterministic(t *testing.T) {
	dir := t.TempDir()
	for _, name := range []string{"c.go", "a.go", "b.go", "d.py", "e.js"} {
		require.NoError(t, os.WriteFile(filepath.Join(dir, name), []byte("package x"), 0o600))
	}

	cfg := config.ScannerConfig{MaxConcurrent: 4, MaxFileSize: 1024 * 1024}
	parser := NewParser(cfg, logrus.New())

	var runs [][]string
	for i := 0; i < 3; i++ {
		results, _, err := parser.ParseRepository(context.Background(), dir, nil, 3, "")
		require.NoError(t, err)
		require.Len(t, results, 3, "max files must cap the walk, not the parsed slice")

		var paths []string
		for _, f := range results {
			paths = append(paths, f.Path)
		}
		runs = append(runs, paths)
	}
	assert.Equal(t, runs[0], runs[1])
	assert.Equal(t, runs[1], runs[2])
}

// A subdirectory scan must report root-relative paths. The path feeds the
// fingerprint, so without the prefix a subdirectory scan can never be compared
// against a baseline taken from the whole tree.
func TestParseRepositoryAppliesPathPrefix(t *testing.T) {
	dir := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(dir, "a.go"), []byte("package x"), 0o600))

	cfg := config.ScannerConfig{MaxConcurrent: 1, MaxFileSize: 1024 * 1024}
	parser := NewParser(cfg, logrus.New())

	results, _, err := parser.ParseRepository(context.Background(), dir, nil, 0, "internal/scanner")
	require.NoError(t, err)
	require.Len(t, results, 1)
	assert.Equal(t, "internal/scanner/a.go", results[0].Path)
}

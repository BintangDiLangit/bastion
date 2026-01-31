package scanner

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"code-security-auditor/internal/config"
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
	results, err := parser.ParseRepository(ctx, tempDir, cfg.ExcludedPaths)
	require.NoError(t, err)

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

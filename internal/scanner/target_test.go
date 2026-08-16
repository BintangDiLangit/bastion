package scanner

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/sirupsen/logrus"

	"github.com/BintangDiLangit/bastion/internal/config"
)

func testManager(t *testing.T) *Manager {
	t.Helper()
	log := logrus.New()
	log.SetLevel(logrus.PanicLevel)
	return NewManager(
		config.ScannerConfig{Timeout: time.Minute, MaxConcurrent: 2, MaxFilesPerScan: 100, MaxFileSize: 1 << 20},
		config.GitConfig{TempDir: t.TempDir(), CloneTimeout: time.Minute, SupportedHosts: []string{"github.com"}},
		log,
	)
}

func TestScanTargetLiveURLNotImplemented(t *testing.T) {
	m := testManager(t)
	_, err := m.ScanTarget(context.Background(), uuid.New(), Target{Type: TargetLiveURL, URL: "https://x"}, ScanOptions{})
	if err == nil || !strings.Contains(err.Error(), "DAST") {
		t.Fatalf("want DAST-not-implemented error, got %v", err)
	}
}

func TestScanTargetUnknownType(t *testing.T) {
	m := testManager(t)
	if _, err := m.ScanTarget(context.Background(), uuid.New(), Target{Type: "bogus"}, ScanOptions{}); err == nil {
		t.Fatal("want error for unknown target type")
	}
}

func TestScanTargetLocal(t *testing.T) {
	dir := t.TempDir()
	src := "package main\nfunc main(){ _ = md5(\"x\") }\n"
	if err := os.WriteFile(filepath.Join(dir, "main.go"), []byte(src), 0644); err != nil {
		t.Fatal(err)
	}

	m := testManager(t)
	res, err := m.ScanTarget(context.Background(), uuid.New(),
		Target{Type: TargetSourceLocal, Path: dir},
		ScanOptions{MaxFiles: 10, Timeout: time.Minute})
	if err != nil {
		t.Fatalf("scan failed: %v", err)
	}
	if res.Metrics.TotalFiles < 1 {
		t.Errorf("expected at least 1 file scanned, got %d", res.Metrics.TotalFiles)
	}
}

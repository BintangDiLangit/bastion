package mcpserver

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/sirupsen/logrus"

	"github.com/BintangDiLangit/bastion/internal/models"
)

func TestResolveDirectoryRejectsEscape(t *testing.T) {
	parent := t.TempDir()
	root := filepath.Join(parent, "root")
	outside := filepath.Join(parent, "outside")
	if err := os.Mkdir(root, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(outside, 0700); err != nil {
		t.Fatal(err)
	}

	service, err := New(root, logrus.New())
	if err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{"..", outside} {
		if _, _, err := service.resolveDirectory(path); err == nil {
			t.Errorf("resolveDirectory(%q) accepted escape", path)
		}
	}

	if err := os.Symlink(outside, filepath.Join(root, "link")); err != nil {
		t.Fatal(err)
	}
	if _, _, err := service.resolveDirectory("link"); err == nil {
		t.Error("resolveDirectory accepted symlink escape")
	}
}

func TestCompareFingerprints(t *testing.T) {
	findings := []models.Vulnerability{
		{Fingerprint: "11111111111111111111111111111111"},
		{Fingerprint: "22222222222222222222222222222222"},
	}
	delta := compareFingerprints(findings, []string{
		"11111111111111111111111111111111",
		"33333333333333333333333333333333",
	})
	if delta.Unchanged != 1 || len(delta.New) != 1 || delta.New[0].Fingerprint != "22222222222222222222222222222222" {
		t.Fatalf("new delta = %#v", delta)
	}
	if len(delta.ResolvedFingerprints) != 1 || delta.ResolvedFingerprints[0] != "33333333333333333333333333333333" {
		t.Fatalf("resolved delta = %#v", delta)
	}
}

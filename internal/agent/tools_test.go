package agent

import (
	"os"
	"path/filepath"
	"testing"
)

func TestResolveFileWithin(t *testing.T) {
	base := t.TempDir()
	inside := filepath.Join(base, "inside.txt")
	if err := os.WriteFile(inside, []byte("ok"), 0600); err != nil {
		t.Fatal(err)
	}

	got, err := resolveFileWithin(base, "inside.txt")
	if err != nil {
		t.Fatal(err)
	}
	want, err := filepath.EvalSymlinks(inside)
	if err != nil {
		t.Fatal(err)
	}
	if got != want {
		t.Fatalf("got %q, want %q", got, want)
	}
}

func TestResolveFileWithinRejectsEscapes(t *testing.T) {
	parent := t.TempDir()
	base := filepath.Join(parent, "repo")
	if err := os.Mkdir(base, 0700); err != nil {
		t.Fatal(err)
	}
	outside := filepath.Join(parent, "secret.txt")
	if err := os.WriteFile(outside, []byte("secret"), 0600); err != nil {
		t.Fatal(err)
	}

	for _, path := range []string{"../secret.txt", outside} {
		if _, err := resolveFileWithin(base, path); err == nil {
			t.Errorf("resolveFileWithin(%q) accepted path escape", path)
		}
	}

	link := filepath.Join(base, "link")
	if err := os.Symlink(outside, link); err != nil {
		t.Fatal(err)
	}
	if _, err := resolveFileWithin(base, "link"); err == nil {
		t.Error("resolveFileWithin accepted symlink escape")
	}
}

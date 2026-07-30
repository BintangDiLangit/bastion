package scanner

import (
	"context"
	"os"
	"testing"

	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"code-security-auditor/internal/config"
)

func TestNewGitManager(t *testing.T) {
	tempDir, err := os.MkdirTemp("", "git-manager-test")
	require.NoError(t, err)
	defer os.RemoveAll(tempDir)

	cfg := config.GitConfig{
		TempDir:             tempDir,
		MaxConcurrentClones: 2,
	}
	logger := logrus.New()

	manager, err := NewGitManager(cfg, logger)
	require.NoError(t, err)
	assert.NotNil(t, manager)
	assert.DirExists(t, tempDir)
}

func TestValidateRepositoryURL(t *testing.T) {
	hosts := []string{"github.com", "gitlab.com"}

	tests := []struct {
		name    string
		url     string
		hosts   []string
		wantErr bool
	}{
		{name: "https on allowed host", url: "https://github.com/user/repo", hosts: hosts},
		{name: "ssh on allowed host", url: "ssh://git@github.com/user/repo.git", hosts: hosts},
		{name: "host match is case-insensitive", url: "https://GitHub.com/user/repo", hosts: hosts},
		{name: "explicit port is allowed", url: "https://github.com:443/user/repo", hosts: hosts},

		// The API clones URLs supplied by callers, so these must fail closed.
		{name: "file scheme reads the server's own disk", url: "file:///etc", hosts: hosts, wantErr: true},
		{name: "plain http is not encrypted", url: "http://github.com/user/repo", hosts: hosts, wantErr: true},
		{name: "git protocol is unauthenticated", url: "git://github.com/user/repo", hosts: hosts, wantErr: true},
		{name: "unknown scheme", url: "ftp://github.com/user/repo", hosts: hosts, wantErr: true},
		{name: "scp syntax has no scheme", url: "git@github.com:user/repo.git", hosts: hosts, wantErr: true},
		{name: "credentials in URL would be logged", url: "https://user:pw@github.com/a/b", hosts: hosts, wantErr: true},
		{name: "disallowed host", url: "https://evil.example.com/user/repo", hosts: hosts, wantErr: true},
		{name: "traversal in path", url: "https://github.com/../user/repo", hosts: hosts, wantErr: true},
		{name: "empty URL", url: "", hosts: hosts, wantErr: true},

		// An unconfigured allowlist is a misconfiguration, not a wildcard.
		{name: "empty allowlist fails closed", url: "https://github.com/user/repo", hosts: nil, wantErr: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := config.GitConfig{
				TempDir:        t.TempDir(),
				SupportedHosts: tt.hosts,
			}
			manager, err := NewGitManager(cfg, logrus.New())
			require.NoError(t, err)

			err = manager.ValidateRepositoryURL(tt.url)
			if tt.wantErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

// Clone is rejected before any network or disk work when the URL fails
// validation. The happy path needs a real remote and is not exercised here.
func TestCloneRejectsUnvalidatedURL(t *testing.T) {
	cfg := config.GitConfig{
		TempDir:             t.TempDir(),
		MaxConcurrentClones: 1,
		SupportedHosts:      []string{"github.com"},
	}
	manager, err := NewGitManager(cfg, logrus.New())
	require.NoError(t, err)

	_, err = manager.CloneRepository(context.Background(), "file:///tmp/whatever", "master")
	require.Error(t, err)

	entries, err := os.ReadDir(cfg.TempDir)
	require.NoError(t, err)
	assert.Empty(t, entries, "a rejected URL must not create a clone directory")
}

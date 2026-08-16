package scanner

import (
	"context"
	"fmt"

	"github.com/go-git/go-git/v5/plumbing/transport"
	"github.com/google/uuid"
)

// TargetType is what a scan points at. Source types are implemented today;
// live_url is the declared seam for the future DAST engine.
type TargetType string

const (
	TargetSourceLocal TargetType = "source_local" // a directory on disk
	TargetSourceGit   TargetType = "source_git"   // a git repo, cloned then scanned
	TargetLiveURL     TargetType = "live_url"     // DAST — see docs/DAST_ROADMAP.md
)

// Target describes what to assess. It is the single seam through which SAST
// today and DAST later both reach the Manager: a new engine adds an arm to
// ScanTarget and returns the same *ScanResult, leaving the CLI, report
// renderer, and engagement config untouched.
type Target struct {
	Type      TargetType
	Path      string               // source_local
	URL       string               // source_git repo URL (or live_url endpoint, later)
	Branch    string               // source_git
	CommitSHA string               // source_git
	Auth      transport.AuthMethod // source_git private-repo auth (nil = public)
}

// ScanTarget dispatches a scan by target type. Source targets reuse ScanPath so
// git-with-auth and a local directory converge on the same analysis path.
func (m *Manager) ScanTarget(ctx context.Context, scanID uuid.UUID, t Target, opts ScanOptions) (*ScanResult, error) {
	switch t.Type {
	case TargetSourceLocal:
		return m.ScanPath(ctx, scanID, t.Path, opts)

	case TargetSourceGit:
		clone, err := m.gitOps.Clone(ctx, CloneOptions{
			URL:       t.URL,
			Branch:    t.Branch,
			CommitSHA: t.CommitSHA,
			Auth:      t.Auth,
			Depth:     m.gitOps.config.CloneDepth,
		})
		if err != nil {
			return nil, fmt.Errorf("clone %s: %w", t.URL, err)
		}
		defer m.cleanup(clone.Path)
		return m.ScanPath(ctx, scanID, clone.Path, opts)

	case TargetLiveURL:
		return nil, fmt.Errorf("live-URL (DAST) scanning is not implemented yet; see docs/DAST_ROADMAP.md")

	default:
		return nil, fmt.Errorf("unknown target type %q", t.Type)
	}
}

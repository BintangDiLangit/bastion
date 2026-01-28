package scanner

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/go-git/go-git/v5"
	"github.com/go-git/go-git/v5/plumbing"
	"github.com/go-git/go-git/v5/plumbing/transport"
	"github.com/go-git/go-git/v5/plumbing/transport/http"
	"github.com/go-git/go-git/v5/plumbing/transport/ssh"
	"github.com/sirupsen/logrus"

	"github.com/code-security-auditor/internal/config"
)

// GitOperations handles Git repository operations.
type GitOperations struct {
	config config.GitConfig
	logger *logrus.Logger
}

// NewGitOperations creates a new GitOperations instance.
func NewGitOperations(cfg config.GitConfig, logger *logrus.Logger) *GitOperations {
	return &GitOperations{
		config: cfg,
		logger: logger,
	}
}

// CloneOptions holds options for cloning.
type CloneOptions struct {
	URL       string
	Branch    string
	CommitSHA string
	Depth     int
	Auth      transport.AuthMethod
	Timeout   time.Duration
}

// Clone clones a repository to a temporary directory.
func (g *GitOperations) Clone(ctx context.Context, repoURL, branch, commitSHA string) (string, error) {
	// Create unique clone directory
	clonePath := filepath.Join(g.config.CloneDir, fmt.Sprintf("repo-%d", time.Now().UnixNano()))
	if err := os.MkdirAll(clonePath, 0755); err != nil {
		return "", fmt.Errorf("failed to create clone directory: %w", err)
	}

	g.logger.WithFields(logrus.Fields{
		"url":    repoURL,
		"branch": branch,
		"path":   clonePath,
	}).Debug("Cloning repository")

	// Prepare clone options
	cloneOpts := &git.CloneOptions{
		URL:      repoURL,
		Progress: nil, // Could add progress writer
		Depth:    1,   // Shallow clone for performance
	}

	if branch != "" {
		cloneOpts.ReferenceName = plumbing.NewBranchReferenceName(branch)
		cloneOpts.SingleBranch = true
	}

	// Apply timeout
	timeout := g.config.CloneTimeout
	if timeout == 0 {
		timeout = 5 * time.Minute
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	// Clone repository
	repo, err := git.PlainCloneContext(ctx, clonePath, false, cloneOpts)
	if err != nil {
		os.RemoveAll(clonePath)
		return "", fmt.Errorf("failed to clone repository: %w", err)
	}

	// Checkout specific commit if specified
	if commitSHA != "" {
		if err := g.checkoutCommit(repo, commitSHA); err != nil {
			os.RemoveAll(clonePath)
			return "", fmt.Errorf("failed to checkout commit: %w", err)
		}
	}

	g.logger.WithFields(logrus.Fields{
		"url":  repoURL,
		"path": clonePath,
	}).Info("Repository cloned successfully")

	return clonePath, nil
}

// CloneWithAuth clones a repository with authentication.
func (g *GitOperations) CloneWithAuth(ctx context.Context, opts CloneOptions) (string, error) {
	clonePath := filepath.Join(g.config.CloneDir, fmt.Sprintf("repo-%d", time.Now().UnixNano()))
	if err := os.MkdirAll(clonePath, 0755); err != nil {
		return "", fmt.Errorf("failed to create clone directory: %w", err)
	}

	cloneOpts := &git.CloneOptions{
		URL:      opts.URL,
		Auth:     opts.Auth,
		Progress: nil,
		Depth:    opts.Depth,
	}

	if opts.Depth == 0 {
		cloneOpts.Depth = 1
	}

	if opts.Branch != "" {
		cloneOpts.ReferenceName = plumbing.NewBranchReferenceName(opts.Branch)
		cloneOpts.SingleBranch = true
	}

	timeout := opts.Timeout
	if timeout == 0 {
		timeout = g.config.CloneTimeout
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	repo, err := git.PlainCloneContext(ctx, clonePath, false, cloneOpts)
	if err != nil {
		os.RemoveAll(clonePath)
		return "", fmt.Errorf("failed to clone repository: %w", err)
	}

	if opts.CommitSHA != "" {
		if err := g.checkoutCommit(repo, opts.CommitSHA); err != nil {
			os.RemoveAll(clonePath)
			return "", fmt.Errorf("failed to checkout commit: %w", err)
		}
	}

	return clonePath, nil
}

// checkoutCommit checks out a specific commit.
func (g *GitOperations) checkoutCommit(repo *git.Repository, sha string) error {
	w, err := repo.Worktree()
	if err != nil {
		return err
	}

	return w.Checkout(&git.CheckoutOptions{
		Hash: plumbing.NewHash(sha),
	})
}

// GetCommitInfo returns information about a specific commit.
func (g *GitOperations) GetCommitInfo(repoPath, sha string) (*CommitInfo, error) {
	repo, err := git.PlainOpen(repoPath)
	if err != nil {
		return nil, fmt.Errorf("failed to open repository: %w", err)
	}

	var hash plumbing.Hash
	if sha == "" || sha == "HEAD" {
		ref, err := repo.Head()
		if err != nil {
			return nil, fmt.Errorf("failed to get HEAD: %w", err)
		}
		hash = ref.Hash()
	} else {
		hash = plumbing.NewHash(sha)
	}

	commit, err := repo.CommitObject(hash)
	if err != nil {
		return nil, fmt.Errorf("failed to get commit: %w", err)
	}

	return &CommitInfo{
		SHA:       commit.Hash.String(),
		Author:    commit.Author.Name,
		Email:     commit.Author.Email,
		Message:   commit.Message,
		Timestamp: commit.Author.When,
	}, nil
}

// CommitInfo holds information about a commit.
type CommitInfo struct {
	SHA       string    `json:"sha"`
	Author    string    `json:"author"`
	Email     string    `json:"email"`
	Message   string    `json:"message"`
	Timestamp time.Time `json:"timestamp"`
}

// GetDiff returns the diff between two commits.
func (g *GitOperations) GetDiff(repoPath, fromSHA, toSHA string) ([]FileDiff, error) {
	repo, err := git.PlainOpen(repoPath)
	if err != nil {
		return nil, fmt.Errorf("failed to open repository: %w", err)
	}

	fromCommit, err := repo.CommitObject(plumbing.NewHash(fromSHA))
	if err != nil {
		return nil, fmt.Errorf("failed to get from commit: %w", err)
	}

	toCommit, err := repo.CommitObject(plumbing.NewHash(toSHA))
	if err != nil {
		return nil, fmt.Errorf("failed to get to commit: %w", err)
	}

	fromTree, err := fromCommit.Tree()
	if err != nil {
		return nil, fmt.Errorf("failed to get from tree: %w", err)
	}

	toTree, err := toCommit.Tree()
	if err != nil {
		return nil, fmt.Errorf("failed to get to tree: %w", err)
	}

	changes, err := fromTree.Diff(toTree)
	if err != nil {
		return nil, fmt.Errorf("failed to get diff: %w", err)
	}

	var diffs []FileDiff
	for _, change := range changes {
		action, err := change.Action()
		if err != nil {
			continue
		}

		diff := FileDiff{
			Action: action.String(),
		}

		if change.From.Name != "" {
			diff.FromPath = change.From.Name
		}
		if change.To.Name != "" {
			diff.ToPath = change.To.Name
		}

		diffs = append(diffs, diff)
	}

	return diffs, nil
}

// FileDiff represents a file diff.
type FileDiff struct {
	FromPath string `json:"from_path"`
	ToPath   string `json:"to_path"`
	Action   string `json:"action"` // Insert, Delete, Modify
}

// GetChangedFiles returns files changed in a commit.
func (g *GitOperations) GetChangedFiles(repoPath, sha string) ([]string, error) {
	repo, err := git.PlainOpen(repoPath)
	if err != nil {
		return nil, fmt.Errorf("failed to open repository: %w", err)
	}

	commit, err := repo.CommitObject(plumbing.NewHash(sha))
	if err != nil {
		return nil, fmt.Errorf("failed to get commit: %w", err)
	}

	stats, err := commit.Stats()
	if err != nil {
		return nil, fmt.Errorf("failed to get stats: %w", err)
	}

	files := make([]string, 0, len(stats))
	for _, stat := range stats {
		files = append(files, stat.Name)
	}

	return files, nil
}

// HTTPAuth creates HTTP basic auth.
func HTTPAuth(username, password string) transport.AuthMethod {
	return &http.BasicAuth{
		Username: username,
		Password: password,
	}
}

// TokenAuth creates HTTP token auth (for GitHub/GitLab tokens).
func TokenAuth(token string) transport.AuthMethod {
	return &http.BasicAuth{
		Username: "oauth2",
		Password: token,
	}
}

// SSHKeyAuth creates SSH key authentication.
func SSHKeyAuth(privateKeyPath, password string) (transport.AuthMethod, error) {
	auth, err := ssh.NewPublicKeysFromFile("git", privateKeyPath, password)
	if err != nil {
		return nil, fmt.Errorf("failed to create SSH auth: %w", err)
	}
	return auth, nil
}

// Cleanup removes a cloned repository.
func (g *GitOperations) Cleanup(path string) error {
	if path == "" {
		return nil
	}
	return os.RemoveAll(path)
}

// ValidateRepository validates that a path is a valid git repository.
func (g *GitOperations) ValidateRepository(path string) error {
	_, err := git.PlainOpen(path)
	if err != nil {
		return fmt.Errorf("not a valid git repository: %w", err)
	}
	return nil
}

// GetBranches returns all branches in a repository.
func (g *GitOperations) GetBranches(repoPath string) ([]string, error) {
	repo, err := git.PlainOpen(repoPath)
	if err != nil {
		return nil, fmt.Errorf("failed to open repository: %w", err)
	}

	refs, err := repo.Branches()
	if err != nil {
		return nil, fmt.Errorf("failed to get branches: %w", err)
	}

	var branches []string
	refs.ForEach(func(ref *plumbing.Reference) error {
		branches = append(branches, ref.Name().Short())
		return nil
	})

	return branches, nil
}

// GetTags returns all tags in a repository.
func (g *GitOperations) GetTags(repoPath string) ([]string, error) {
	repo, err := git.PlainOpen(repoPath)
	if err != nil {
		return nil, fmt.Errorf("failed to open repository: %w", err)
	}

	refs, err := repo.Tags()
	if err != nil {
		return nil, fmt.Errorf("failed to get tags: %w", err)
	}

	var tags []string
	refs.ForEach(func(ref *plumbing.Reference) error {
		tags = append(tags, ref.Name().Short())
		return nil
	})

	return tags, nil
}

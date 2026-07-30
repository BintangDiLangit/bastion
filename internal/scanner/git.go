// Package scanner provides code scanning and analysis functionality.
package scanner

import (
	"context"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/go-git/go-git/v5"
	"github.com/go-git/go-git/v5/plumbing"
	"github.com/go-git/go-git/v5/plumbing/object"
	"github.com/go-git/go-git/v5/plumbing/transport"
	"github.com/go-git/go-git/v5/plumbing/transport/http"
	"github.com/go-git/go-git/v5/plumbing/transport/ssh"
	"github.com/sirupsen/logrus"

	"code-security-auditor/internal/config"
)

var (
	// ErrRepositoryTooLarge is returned when a repository exceeds the size limit.
	ErrRepositoryTooLarge = errors.New("repository size exceeds maximum allowed")

	// ErrUnsupportedHost is returned when the Git host is not in the allowed list.
	ErrUnsupportedHost = errors.New("git host is not supported")

	// ErrInvalidRepositoryURL is returned when the repository URL is invalid.
	ErrInvalidRepositoryURL = errors.New("invalid repository URL")

	// ErrCloneTimeout is returned when cloning times out.
	ErrCloneTimeout = errors.New("clone operation timed out")

	// ErrAuthenticationFailed is returned when Git authentication fails.
	ErrAuthenticationFailed = errors.New("git authentication failed")

	// ErrPathTraversal is returned when path traversal is detected.
	ErrPathTraversal = errors.New("path traversal detected")

	// ErrBinaryFile is returned when trying to read a binary file.
	ErrBinaryFile = errors.New("binary file detected")
)

// GitManager handles Git repository operations with security considerations.
type GitManager struct {
	config       config.GitConfig
	logger       *logrus.Logger
	tempDir      string
	cloneSem     chan struct{} // Semaphore for limiting concurrent clones
	mu           sync.Mutex
	activeClones map[string]bool
}

// NewGitManager creates a new GitManager instance.
func NewGitManager(cfg config.GitConfig, logger *logrus.Logger) (*GitManager, error) {
	// Ensure temp directory exists.
	// 0700: clones hold untrusted third-party source, often on a shared host.
	if err := os.MkdirAll(cfg.TempDir, 0700); err != nil {
		return nil, fmt.Errorf("failed to create temp directory: %w", err)
	}

	maxConcurrent := cfg.MaxConcurrentClones
	if maxConcurrent <= 0 {
		maxConcurrent = 5
	}

	return &GitManager{
		config:       cfg,
		logger:       logger,
		tempDir:      cfg.TempDir,
		cloneSem:     make(chan struct{}, maxConcurrent),
		activeClones: make(map[string]bool),
	}, nil
}

// CloneOptions holds options for cloning a repository.
type CloneOptions struct {
	URL       string
	Branch    string
	CommitSHA string
	Depth     int
	Auth      transport.AuthMethod
	Timeout   time.Duration
}

// CloneResult contains information about a cloned repository.
type CloneResult struct {
	Path       string
	CommitSHA  string
	Branch     string
	CommitInfo *CommitInfo
	Size       int64
}

// CloneRepository clones a repository to a temporary directory.
func (g *GitManager) CloneRepository(ctx context.Context, repoURL, branch string) (*CloneResult, error) {
	return g.Clone(ctx, CloneOptions{
		URL:    repoURL,
		Branch: branch,
		Depth:  g.config.CloneDepth,
	})
}

// Clone clones a repository with full options.
func (g *GitManager) Clone(ctx context.Context, opts CloneOptions) (*CloneResult, error) {
	// Validate repository URL
	if err := g.ValidateRepositoryURL(opts.URL); err != nil {
		return nil, err
	}

	// Acquire semaphore slot
	select {
	case g.cloneSem <- struct{}{}:
		defer func() { <-g.cloneSem }()
	case <-ctx.Done():
		return nil, ctx.Err()
	}

	// Check for duplicate clone operations
	g.mu.Lock()
	if g.activeClones[opts.URL] {
		g.mu.Unlock()
		return nil, errors.New("clone operation already in progress for this repository")
	}
	g.activeClones[opts.URL] = true
	g.mu.Unlock()

	defer func() {
		g.mu.Lock()
		delete(g.activeClones, opts.URL)
		g.mu.Unlock()
	}()

	// Create unique clone directory.
	// MkdirTemp rather than a name derived from the URL and the clock: the old
	// name was predictable, so another local user could pre-create or race it.
	// 0700 because the contents are untrusted third-party source.
	clonePath, err := os.MkdirTemp(g.tempDir, "repo-")
	if err != nil {
		return nil, fmt.Errorf("failed to create clone directory: %w", err)
	}

	g.logger.WithFields(logrus.Fields{
		"url":    sanitizeURL(opts.URL),
		"branch": opts.Branch,
		"path":   clonePath,
		"depth":  opts.Depth,
	}).Info("Cloning repository")

	// Prepare clone options
	cloneOpts := &git.CloneOptions{
		URL:      opts.URL,
		Progress: nil,
	}

	// Set depth
	depth := opts.Depth
	if depth <= 0 {
		depth = g.config.CloneDepth
	}
	if depth > 0 {
		cloneOpts.Depth = depth
	}

	// Set branch
	if opts.Branch != "" {
		cloneOpts.ReferenceName = plumbing.NewBranchReferenceName(opts.Branch)
		cloneOpts.SingleBranch = true
	}

	// Set authentication
	if opts.Auth != nil {
		cloneOpts.Auth = opts.Auth
	}

	// Apply timeout
	timeout := opts.Timeout
	if timeout == 0 {
		timeout = g.config.CloneTimeout
	}
	if timeout == 0 {
		timeout = 5 * time.Minute
	}

	cloneCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	// Enforce the size cap during the transfer. Checking only after the clone
	// finishes lets an untrusted URL fill the disk first and be rejected after
	// the damage is done.
	//
	// ponytail: polls the directory size on a ticker. Coarse — it can overshoot
	// by one interval's worth of data — but it needs no filesystem quota and no
	// custom billy backend. Swap in a quota-backed volume if the overshoot
	// matters.
	oversize := make(chan struct{})
	if g.config.MaxRepoSize > 0 {
		stopWatch := make(chan struct{})
		defer close(stopWatch)
		go func() {
			ticker := time.NewTicker(time.Second)
			defer ticker.Stop()
			for {
				select {
				case <-stopWatch:
					return
				case <-ticker.C:
					if size, err := g.getDirectorySize(clonePath); err == nil && size > g.config.MaxRepoSize {
						close(oversize)
						cancel()
						return
					}
				}
			}
		}()
	}

	// Clone repository
	repo, err := git.PlainCloneContext(cloneCtx, clonePath, false, cloneOpts)
	if err != nil {
		os.RemoveAll(clonePath)
		select {
		case <-oversize:
			return nil, fmt.Errorf("%w: exceeded %d bytes during clone", ErrRepositoryTooLarge, g.config.MaxRepoSize)
		default:
		}
		return nil, g.handleCloneError(err)
	}

	// Checkout specific commit if specified
	if opts.CommitSHA != "" {
		if err := g.checkoutCommit(repo, opts.CommitSHA); err != nil {
			os.RemoveAll(clonePath)
			return nil, fmt.Errorf("failed to checkout commit: %w", err)
		}
	}

	// Verify repository size
	size, err := g.getDirectorySize(clonePath)
	if err != nil {
		os.RemoveAll(clonePath)
		return nil, fmt.Errorf("failed to calculate repository size: %w", err)
	}

	if size > g.config.MaxRepoSize {
		os.RemoveAll(clonePath)
		return nil, fmt.Errorf("%w: %d bytes (max: %d bytes)", ErrRepositoryTooLarge, size, g.config.MaxRepoSize)
	}

	// Get commit info
	commitInfo, err := g.GetCommitInfo(clonePath, "")
	if err != nil {
		g.logger.WithError(err).Warn("Failed to get commit info")
	}

	result := &CloneResult{
		Path:       clonePath,
		Branch:     opts.Branch,
		Size:       size,
		CommitInfo: commitInfo,
	}

	if commitInfo != nil {
		result.CommitSHA = commitInfo.SHA
	}

	g.logger.WithFields(logrus.Fields{
		"url":  sanitizeURL(opts.URL),
		"path": clonePath,
		"size": size,
	}).Info("Repository cloned successfully")

	return result, nil
}

// handleCloneError converts Git errors to our error types.
func (g *GitManager) handleCloneError(err error) error {
	if err == nil {
		return nil
	}

	errStr := err.Error()

	if strings.Contains(errStr, "timeout") || errors.Is(err, context.DeadlineExceeded) {
		return fmt.Errorf("%w: %v", ErrCloneTimeout, err)
	}

	if strings.Contains(errStr, "authentication") ||
		strings.Contains(errStr, "Permission denied") ||
		strings.Contains(errStr, "could not read Username") {
		return fmt.Errorf("%w: %v", ErrAuthenticationFailed, err)
	}

	return fmt.Errorf("failed to clone repository: %w", err)
}

// checkoutCommit checks out a specific commit.
func (g *GitManager) checkoutCommit(repo *git.Repository, sha string) error {
	w, err := repo.Worktree()
	if err != nil {
		return err
	}

	hash := plumbing.NewHash(sha)
	return w.Checkout(&git.CheckoutOptions{
		Hash: hash,
	})
}

// ValidateRepositoryURL validates that a repository URL is allowed.
func (g *GitManager) ValidateRepositoryURL(repoURL string) error {
	if repoURL == "" {
		return ErrInvalidRepositoryURL
	}

	// Sanitize and validate URL
	repoURL = strings.TrimSpace(repoURL)

	// Parse URL
	parsedURL, err := url.Parse(repoURL)
	if err != nil {
		return fmt.Errorf("%w: %v", ErrInvalidRepositoryURL, err)
	}

	// Only transports that actually go over the network to a named host.
	// file:// would clone from the API server's own disk, and http:// and git://
	// are unauthenticated and unencrypted, so the host allowlist below means
	// nothing against an on-path attacker.
	validSchemes := map[string]bool{"https": true, "ssh": true}
	if !validSchemes[parsedURL.Scheme] {
		return fmt.Errorf("%w: unsupported scheme %q", ErrInvalidRepositoryURL, parsedURL.Scheme)
	}

	// Credentials in the URL would be logged and stored with the scan record.
	// An SSH username ("ssh://git@host/...") is not a credential; a password,
	// or any userinfo on an https URL (that is where tokens get pasted), is.
	if parsedURL.User != nil {
		if _, hasPassword := parsedURL.User.Password(); hasPassword || parsedURL.Scheme == "https" {
			return fmt.Errorf("%w: URL must not embed credentials", ErrInvalidRepositoryURL)
		}
	}

	// An empty allowlist is a misconfiguration, not permission to clone
	// anything the process can reach.
	if len(g.config.SupportedHosts) == 0 {
		return fmt.Errorf("%w: no supported hosts configured", ErrUnsupportedHost)
	}

	host := parsedURL.Hostname()
	allowed := false
	for _, supportedHost := range g.config.SupportedHosts {
		if strings.EqualFold(host, supportedHost) {
			allowed = true
			break
		}
	}
	if !allowed {
		return fmt.Errorf("%w: %s", ErrUnsupportedHost, host)
	}

	// Reject traversal only in the path, after the host has been vetted.
	// Testing the whole URL rejected legitimate hosts and was bypassable via
	// percent-encoding anyway.
	if strings.Contains(parsedURL.Path, "..") {
		return fmt.Errorf("%w: URL path contains path traversal", ErrPathTraversal)
	}

	return nil
}

// GetChangedFiles returns files changed between two commits.
func (g *GitManager) GetChangedFiles(ctx context.Context, repoPath, fromCommit, toCommit string) ([]string, error) {
	repo, err := git.PlainOpen(repoPath)
	if err != nil {
		return nil, fmt.Errorf("failed to open repository: %w", err)
	}

	fromHash := plumbing.NewHash(fromCommit)
	toHash := plumbing.NewHash(toCommit)

	fromCommitObj, err := repo.CommitObject(fromHash)
	if err != nil {
		return nil, fmt.Errorf("failed to get from commit: %w", err)
	}

	toCommitObj, err := repo.CommitObject(toHash)
	if err != nil {
		return nil, fmt.Errorf("failed to get to commit: %w", err)
	}

	fromTree, err := fromCommitObj.Tree()
	if err != nil {
		return nil, fmt.Errorf("failed to get from tree: %w", err)
	}

	toTree, err := toCommitObj.Tree()
	if err != nil {
		return nil, fmt.Errorf("failed to get to tree: %w", err)
	}

	changes, err := fromTree.Diff(toTree)
	if err != nil {
		return nil, fmt.Errorf("failed to get diff: %w", err)
	}

	var files []string
	for _, change := range changes {
		if change.To.Name != "" {
			files = append(files, change.To.Name)
		} else if change.From.Name != "" {
			files = append(files, change.From.Name)
		}
	}

	return files, nil
}

// GetFileContent reads file content at a specific commit.
func (g *GitManager) GetFileContent(repoPath, filePath, commit string) ([]byte, error) {
	// Prevent path traversal
	if err := validateFilePath(filePath); err != nil {
		return nil, err
	}

	repo, err := git.PlainOpen(repoPath)
	if err != nil {
		return nil, fmt.Errorf("failed to open repository: %w", err)
	}

	var hash plumbing.Hash
	if commit == "" || commit == "HEAD" {
		ref, err := repo.Head()
		if err != nil {
			return nil, fmt.Errorf("failed to get HEAD: %w", err)
		}
		hash = ref.Hash()
	} else {
		hash = plumbing.NewHash(commit)
	}

	commitObj, err := repo.CommitObject(hash)
	if err != nil {
		return nil, fmt.Errorf("failed to get commit: %w", err)
	}

	tree, err := commitObj.Tree()
	if err != nil {
		return nil, fmt.Errorf("failed to get tree: %w", err)
	}

	file, err := tree.File(filePath)
	if err != nil {
		return nil, fmt.Errorf("failed to get file: %w", err)
	}

	// Check if file is binary
	isBinary, err := file.IsBinary()
	if err != nil {
		return nil, fmt.Errorf("failed to check if file is binary: %w", err)
	}
	if isBinary {
		return nil, ErrBinaryFile
	}

	content, err := file.Contents()
	if err != nil {
		return nil, fmt.Errorf("failed to read file contents: %w", err)
	}

	return []byte(content), nil
}

// GetCommitInfo returns information about a specific commit.
func (g *GitManager) GetCommitInfo(repoPath, sha string) (*CommitInfo, error) {
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
		Message:   strings.TrimSpace(commit.Message),
		Timestamp: commit.Author.When,
		ParentSHAs: func() []string {
			var parents []string
			for _, parent := range commit.ParentHashes {
				parents = append(parents, parent.String())
			}
			return parents
		}(),
	}, nil
}

// CommitInfo holds information about a commit.
type CommitInfo struct {
	SHA        string    `json:"sha"`
	Author     string    `json:"author"`
	Email      string    `json:"email"`
	Message    string    `json:"message"`
	Timestamp  time.Time `json:"timestamp"`
	ParentSHAs []string  `json:"parent_shas,omitempty"`
}

// GetDiff returns the diff between two commits.
func (g *GitManager) GetDiff(repoPath, fromSHA, toSHA string) ([]FileDiff, error) {
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

		// Get patch if not too large
		patch, err := change.Patch()
		if err == nil && patch != nil {
			patchText := patch.String()
			if len(patchText) < 100000 { // Limit patch size
				diff.Patch = patchText
			}
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
	Patch    string `json:"patch,omitempty"`
}

// GetBranches returns all branches in a repository.
func (g *GitManager) GetBranches(repoPath string) ([]BranchInfo, error) {
	repo, err := git.PlainOpen(repoPath)
	if err != nil {
		return nil, fmt.Errorf("failed to open repository: %w", err)
	}

	refs, err := repo.Branches()
	if err != nil {
		return nil, fmt.Errorf("failed to get branches: %w", err)
	}

	var branches []BranchInfo
	err = refs.ForEach(func(ref *plumbing.Reference) error {
		branch := BranchInfo{
			Name: ref.Name().Short(),
			SHA:  ref.Hash().String(),
		}

		// Get commit info for the branch
		commit, err := repo.CommitObject(ref.Hash())
		if err == nil {
			branch.LastCommit = commit.Author.When
			branch.Author = commit.Author.Name
		}

		branches = append(branches, branch)
		return nil
	})

	return branches, err
}

// BranchInfo represents information about a branch.
type BranchInfo struct {
	Name       string    `json:"name"`
	SHA        string    `json:"sha"`
	LastCommit time.Time `json:"last_commit"`
	Author     string    `json:"author"`
}

// GetTags returns all tags in a repository.
func (g *GitManager) GetTags(repoPath string) ([]TagInfo, error) {
	repo, err := git.PlainOpen(repoPath)
	if err != nil {
		return nil, fmt.Errorf("failed to open repository: %w", err)
	}

	refs, err := repo.Tags()
	if err != nil {
		return nil, fmt.Errorf("failed to get tags: %w", err)
	}

	var tags []TagInfo
	err = refs.ForEach(func(ref *plumbing.Reference) error {
		tag := TagInfo{
			Name: ref.Name().Short(),
			SHA:  ref.Hash().String(),
		}

		// Try to get annotated tag info
		tagObj, err := repo.TagObject(ref.Hash())
		if err == nil {
			tag.Message = strings.TrimSpace(tagObj.Message)
			tag.Tagger = tagObj.Tagger.Name
			tag.Date = tagObj.Tagger.When
		} else {
			// Lightweight tag, get commit info
			commit, err := repo.CommitObject(ref.Hash())
			if err == nil {
				tag.Date = commit.Author.When
				tag.Tagger = commit.Author.Name
			}
		}

		tags = append(tags, tag)
		return nil
	})

	return tags, err
}

// TagInfo represents information about a tag.
type TagInfo struct {
	Name    string    `json:"name"`
	SHA     string    `json:"sha"`
	Message string    `json:"message,omitempty"`
	Tagger  string    `json:"tagger,omitempty"`
	Date    time.Time `json:"date"`
}

// ListFiles lists all files in the repository.
func (g *GitManager) ListFiles(repoPath string, filterFunc func(string) bool) ([]string, error) {
	var files []string

	err := filepath.WalkDir(repoPath, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return nil // Skip files with errors
		}

		// Skip .git directory
		if d.IsDir() && d.Name() == ".git" {
			return filepath.SkipDir
		}

		if d.IsDir() {
			return nil
		}

		relPath, err := filepath.Rel(repoPath, path)
		if err != nil {
			return nil
		}

		// Apply filter if provided
		if filterFunc != nil && !filterFunc(relPath) {
			return nil
		}

		files = append(files, relPath)
		return nil
	})

	return files, err
}

// GetRecentCommits returns the most recent commits.
func (g *GitManager) GetRecentCommits(repoPath string, limit int) ([]CommitInfo, error) {
	repo, err := git.PlainOpen(repoPath)
	if err != nil {
		return nil, fmt.Errorf("failed to open repository: %w", err)
	}

	ref, err := repo.Head()
	if err != nil {
		return nil, fmt.Errorf("failed to get HEAD: %w", err)
	}

	commitIter, err := repo.Log(&git.LogOptions{
		From:  ref.Hash(),
		Order: git.LogOrderCommitterTime,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to get log: %w", err)
	}

	var commits []CommitInfo
	count := 0

	err = commitIter.ForEach(func(c *object.Commit) error {
		if count >= limit {
			return errors.New("limit reached")
		}

		commits = append(commits, CommitInfo{
			SHA:       c.Hash.String(),
			Author:    c.Author.Name,
			Email:     c.Author.Email,
			Message:   strings.TrimSpace(c.Message),
			Timestamp: c.Author.When,
		})

		count++
		return nil
	})

	// Ignore "limit reached" error
	if err != nil && err.Error() != "limit reached" {
		return nil, err
	}

	return commits, nil
}

// Cleanup removes a cloned repository.
func (g *GitManager) Cleanup(path string) error {
	if path == "" {
		return nil
	}

	// Ensure the path is within our temp directory
	absPath, err := filepath.Abs(path)
	if err != nil {
		return fmt.Errorf("failed to get absolute path: %w", err)
	}

	absTempDir, err := filepath.Abs(g.tempDir)
	if err != nil {
		return fmt.Errorf("failed to get absolute temp dir: %w", err)
	}

	if !strings.HasPrefix(absPath, absTempDir) {
		return fmt.Errorf("refusing to delete path outside temp directory: %s", path)
	}

	return os.RemoveAll(path)
}

// CleanupAll removes all cloned repositories.
func (g *GitManager) CleanupAll() error {
	g.logger.Info("Cleaning up all cloned repositories")

	entries, err := os.ReadDir(g.tempDir)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return err
	}

	for _, entry := range entries {
		if entry.IsDir() && strings.HasPrefix(entry.Name(), "repo-") {
			path := filepath.Join(g.tempDir, entry.Name())
			if err := os.RemoveAll(path); err != nil {
				g.logger.WithError(err).Warnf("Failed to remove: %s", path)
			}
		}
	}

	return nil
}

// CleanupOld removes repositories older than the specified duration.
func (g *GitManager) CleanupOld(maxAge time.Duration) error {
	g.logger.WithField("max_age", maxAge).Info("Cleaning up old cloned repositories")

	entries, err := os.ReadDir(g.tempDir)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return err
	}

	cutoff := time.Now().Add(-maxAge)

	for _, entry := range entries {
		if !entry.IsDir() || !strings.HasPrefix(entry.Name(), "repo-") {
			continue
		}

		path := filepath.Join(g.tempDir, entry.Name())
		info, err := entry.Info()
		if err != nil {
			continue
		}

		if info.ModTime().Before(cutoff) {
			if err := os.RemoveAll(path); err != nil {
				g.logger.WithError(err).Warnf("Failed to remove old repo: %s", path)
			} else {
				g.logger.WithField("path", path).Debug("Removed old repository")
			}
		}
	}

	return nil
}

// getDirectorySize calculates the total size of a directory.
func (g *GitManager) getDirectorySize(path string) (int64, error) {
	var size int64

	err := filepath.WalkDir(path, func(_ string, d fs.DirEntry, err error) error {
		if err != nil {
			return nil // Skip files with errors
		}

		if !d.IsDir() {
			info, err := d.Info()
			if err == nil {
				size += info.Size()
			}
		}

		return nil
	})

	return size, err
}

// ============================================================================
// Authentication Helpers
// ============================================================================

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

// SSHKeyAuth creates SSH key authentication from a file.
func SSHKeyAuth(privateKeyPath, password string) (transport.AuthMethod, error) {
	auth, err := ssh.NewPublicKeysFromFile("git", privateKeyPath, password)
	if err != nil {
		return nil, fmt.Errorf("failed to create SSH auth: %w", err)
	}
	return auth, nil
}

// SSHKeyAuthFromBytes creates SSH key authentication from bytes.
func SSHKeyAuthFromBytes(privateKey []byte, password string) (transport.AuthMethod, error) {
	auth, err := ssh.NewPublicKeys("git", privateKey, password)
	if err != nil {
		return nil, fmt.Errorf("failed to create SSH auth: %w", err)
	}
	return auth, nil
}

// ============================================================================
// Utility Functions
// ============================================================================

// validateFilePath validates that a file path doesn't contain path traversal.
func validateFilePath(path string) error {
	// Normalize path
	cleaned := filepath.Clean(path)

	// Check for path traversal
	if strings.HasPrefix(cleaned, "..") || strings.Contains(cleaned, ".."+string(filepath.Separator)) {
		return ErrPathTraversal
	}

	// Check for absolute paths
	if filepath.IsAbs(cleaned) {
		return fmt.Errorf("%w: absolute paths not allowed", ErrPathTraversal)
	}

	return nil
}

// sanitizeURL removes credentials from a URL for logging.
func sanitizeURL(rawURL string) string {
	parsed, err := url.Parse(rawURL)
	if err != nil {
		return "[invalid-url]"
	}

	// Remove user info (credentials)
	parsed.User = nil

	return parsed.String()
}

// ExtractRepoInfo extracts owner and repo name from a repository URL.
func ExtractRepoInfo(repoURL string) (owner, repo string, err error) {
	parsed, err := url.Parse(repoURL)
	if err != nil {
		return "", "", fmt.Errorf("invalid URL: %w", err)
	}

	// Handle git@github.com:owner/repo.git format
	if parsed.Scheme == "" && strings.Contains(repoURL, "@") {
		re := regexp.MustCompile(`@[^:]+:(.+)/(.+?)(?:\.git)?$`)
		matches := re.FindStringSubmatch(repoURL)
		if len(matches) == 3 {
			return matches[1], strings.TrimSuffix(matches[2], ".git"), nil
		}
	}

	// Handle https://github.com/owner/repo.git format
	path := strings.TrimPrefix(parsed.Path, "/")
	path = strings.TrimSuffix(path, ".git")
	parts := strings.Split(path, "/")

	if len(parts) >= 2 {
		return parts[0], parts[1], nil
	}

	return "", "", errors.New("could not extract repository info from URL")
}

// ReadFileFromDisk reads a file from the filesystem with size limit.
func ReadFileFromDisk(path string, maxSize int64) ([]byte, error) {
	info, err := os.Stat(path)
	if err != nil {
		return nil, err
	}

	if info.Size() > maxSize {
		return nil, fmt.Errorf("file too large: %d bytes (max: %d)", info.Size(), maxSize)
	}

	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	return io.ReadAll(io.LimitReader(file, maxSize))
}

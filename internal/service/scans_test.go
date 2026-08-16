package service

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/sirupsen/logrus"

	"github.com/BintangDiLangit/bastion/internal/config"
	"github.com/BintangDiLangit/bastion/internal/models"
	"github.com/BintangDiLangit/bastion/internal/scanner"
)

type fakeStore struct {
	mu         sync.Mutex
	repository *models.Repository
	scan       *models.Scan
	completed  chan struct{}
}

func (s *fakeStore) EnsureRepository(_ context.Context, rawURL, branch string) (*models.Repository, error) {
	repository, _ := models.NewRepository(rawURL)
	repository.DefaultBranch = branch
	s.repository = repository
	return repository, nil
}
func (s *fakeStore) CreateScan(_ context.Context, scan *models.Scan) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	copy := *scan
	s.scan = &copy
	return nil
}
func (s *fakeStore) GetScan(_ context.Context, _ uuid.UUID) (*models.Scan, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	copy := *s.scan
	return &copy, nil
}
func (s *fakeStore) MarkRunning(_ context.Context, _ uuid.UUID) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.scan.Status = models.ScanStatusRunning
	return nil
}
func (s *fakeStore) Complete(_ context.Context, _ *models.Scan, result *scanner.ScanResult) error {
	s.mu.Lock()
	s.scan.Status = models.ScanStatusCompleted
	s.scan.FilesScanned = result.FilesScanned
	s.mu.Unlock()
	close(s.completed)
	return nil
}
func (s *fakeStore) Fail(_ context.Context, _ uuid.UUID, _ string) error { return nil }
func (s *fakeStore) Cancel(_ context.Context, _ uuid.UUID) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.scan.Status = models.ScanStatusCancelled
	return nil
}
func (s *fakeStore) ListVulnerabilities(context.Context, uuid.UUID, int, int) ([]models.Vulnerability, error) {
	return nil, nil
}
func (s *fakeStore) Compare(_ context.Context, id uuid.UUID, baselineID *uuid.UUID) (*models.ScanDelta, error) {
	return &models.ScanDelta{ScanID: id, BaselineScanID: baselineID}, nil
}

type fakeRunner struct{}

func (fakeRunner) Scan(context.Context, *models.Repository, *models.Scan, scanner.ScanOptions) (*scanner.ScanResult, error) {
	return &scanner.ScanResult{FilesScanned: 3}, nil
}

func TestScanLifecycle(t *testing.T) {
	store := &fakeStore{completed: make(chan struct{})}
	service := NewScans(
		store,
		fakeRunner{},
		config.ScannerConfig{Timeout: time.Minute},
		config.GitConfig{SupportedHosts: []string{"github.com"}},
		logrus.New(),
	)

	scan, err := service.Create(context.Background(), models.ScanRequest{
		RepositoryURL: "https://github.com/example/project",
		Branch:        "main",
	})
	if err != nil {
		t.Fatal(err)
	}
	select {
	case <-store.completed:
	case <-time.After(time.Second):
		t.Fatal("scan did not complete")
	}
	got, err := service.Get(context.Background(), scan.ID)
	if err != nil {
		t.Fatal(err)
	}
	if got.Status != models.ScanStatusCompleted || got.FilesScanned != 3 {
		t.Fatalf("got status=%s files=%d", got.Status, got.FilesScanned)
	}
}

func TestScanRejectsUntrustedRepositoryURL(t *testing.T) {
	service := NewScans(
		&fakeStore{},
		fakeRunner{},
		config.ScannerConfig{Timeout: time.Minute},
		config.GitConfig{SupportedHosts: []string{"github.com"}},
		logrus.New(),
	)
	for _, rawURL := range []string{
		"http://github.com/example/project",
		"https://token@github.com/example/project",
		"https://evil.example/project",
	} {
		if _, err := service.Create(context.Background(), models.ScanRequest{RepositoryURL: rawURL}); err == nil {
			t.Errorf("accepted %q", rawURL)
		}
	}
}

func TestCompareFindings(t *testing.T) {
	baselineID := uuid.New()
	current := []models.Vulnerability{
		{Fingerprint: "unchanged"},
		{Fingerprint: "new"},
	}
	baseline := []models.Vulnerability{
		{Fingerprint: "unchanged"},
		{Fingerprint: "resolved"},
	}
	delta := compareFindings(uuid.New(), &baselineID, current, baseline)
	if delta.Unchanged != 1 || len(delta.New) != 1 || delta.New[0].Fingerprint != "new" {
		t.Fatalf("new delta = %#v", delta)
	}
	if len(delta.Resolved) != 1 || delta.Resolved[0].Fingerprint != "resolved" {
		t.Fatalf("resolved delta = %#v", delta)
	}
}

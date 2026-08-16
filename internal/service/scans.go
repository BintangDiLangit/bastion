package service

import (
	"context"
	"errors"
	"fmt"
	"net/url"
	"strings"
	"sync"

	"github.com/google/uuid"
	"github.com/sirupsen/logrus"

	"github.com/BintangDiLangit/bastion/internal/config"
	"github.com/BintangDiLangit/bastion/internal/models"
	"github.com/BintangDiLangit/bastion/internal/scanner"
)

var ErrNotFound = errors.New("not found")
var ErrInvalidRepository = errors.New("invalid repository")

type ScanStore interface {
	EnsureRepository(context.Context, string, string) (*models.Repository, error)
	CreateScan(context.Context, *models.Scan) error
	GetScan(context.Context, uuid.UUID) (*models.Scan, error)
	MarkRunning(context.Context, uuid.UUID) error
	Complete(context.Context, *models.Scan, *scanner.ScanResult) error
	Fail(context.Context, uuid.UUID, string) error
	Cancel(context.Context, uuid.UUID) error
	ListVulnerabilities(context.Context, uuid.UUID, int, int) ([]models.Vulnerability, error)
	Compare(context.Context, uuid.UUID, *uuid.UUID) (*models.ScanDelta, error)
}

type Runner interface {
	Scan(context.Context, *models.Repository, *models.Scan, scanner.ScanOptions) (*scanner.ScanResult, error)
}

type Scans struct {
	store          ScanStore
	runner         Runner
	config         config.ScannerConfig
	supportedHosts map[string]bool
	logger         *logrus.Logger
	mu             sync.Mutex
	cancels        map[uuid.UUID]context.CancelFunc
}

func NewScans(store ScanStore, runner Runner, scannerConfig config.ScannerConfig, gitConfig config.GitConfig, logger *logrus.Logger) *Scans {
	hosts := make(map[string]bool, len(gitConfig.SupportedHosts))
	for _, host := range gitConfig.SupportedHosts {
		hosts[strings.ToLower(host)] = true
	}
	return &Scans{
		store:          store,
		runner:         runner,
		config:         scannerConfig,
		supportedHosts: hosts,
		logger:         logger,
		cancels:        make(map[uuid.UUID]context.CancelFunc),
	}
}

func (s *Scans) Create(ctx context.Context, request models.ScanRequest) (*models.Scan, error) {
	if err := s.validateRepositoryURL(request.RepositoryURL); err != nil {
		return nil, err
	}
	repository, err := s.store.EnsureRepository(ctx, request.RepositoryURL, request.Branch)
	if err != nil {
		return nil, fmt.Errorf("save repository: %w", err)
	}

	scanType := request.ScanType
	if scanType == "" {
		scanType = models.ScanTypeFull
	}
	scan := models.NewScan(repository.ID, scanType, models.ScanTriggerManual)
	scan.Branch = request.Branch
	if scan.Branch == "" {
		scan.Branch = repository.DefaultBranch
	}
	scan.CommitSHA = request.CommitSHA
	scan.Metadata.ScanOptions = request.Options
	if err := s.store.CreateScan(ctx, scan); err != nil {
		return nil, fmt.Errorf("create scan: %w", err)
	}

	runContext, cancel := context.WithTimeout(context.Background(), s.config.Timeout)
	s.mu.Lock()
	s.cancels[scan.ID] = cancel
	s.mu.Unlock()
	go s.run(runContext, cancel, repository, scan)
	return scan, nil
}

func (s *Scans) Get(ctx context.Context, id uuid.UUID) (*models.Scan, error) {
	return s.store.GetScan(ctx, id)
}

func (s *Scans) Findings(ctx context.Context, id uuid.UUID, limit, offset int) ([]models.Vulnerability, error) {
	if limit < 1 {
		limit = 50
	}
	if limit > 200 {
		limit = 200
	}
	if offset < 0 {
		offset = 0
	}
	return s.store.ListVulnerabilities(ctx, id, limit, offset)
}

func (s *Scans) Delta(ctx context.Context, id uuid.UUID, baselineID *uuid.UUID) (*models.ScanDelta, error) {
	return s.store.Compare(ctx, id, baselineID)
}

func (s *Scans) Cancel(ctx context.Context, id uuid.UUID) error {
	s.mu.Lock()
	cancel := s.cancels[id]
	delete(s.cancels, id)
	s.mu.Unlock()
	if cancel != nil {
		cancel()
	}
	return s.store.Cancel(ctx, id)
}

func (s *Scans) run(ctx context.Context, cancel context.CancelFunc, repository *models.Repository, scan *models.Scan) {
	defer cancel()
	defer func() {
		s.mu.Lock()
		delete(s.cancels, scan.ID)
		s.mu.Unlock()
	}()

	if err := s.store.MarkRunning(ctx, scan.ID); err != nil {
		s.logger.WithError(err).WithField("scan_id", scan.ID).Error("Mark scan running")
		_ = s.store.Fail(context.Background(), scan.ID, err.Error())
		return
	}
	scan.Start()
	result, err := s.runner.Scan(ctx, repository, scan, scanner.ScanOptions{
		Branch:    scan.Branch,
		CommitSHA: scan.CommitSHA,
		Timeout:   s.config.Timeout,
	})
	if err != nil {
		if errors.Is(ctx.Err(), context.Canceled) {
			return
		}
		_ = s.store.Fail(context.Background(), scan.ID, err.Error())
		return
	}
	if err := s.store.Complete(context.Background(), scan, result); err != nil {
		s.logger.WithError(err).WithField("scan_id", scan.ID).Error("Persist scan result")
	}
}

func (s *Scans) validateRepositoryURL(raw string) error {
	parsed, err := url.Parse(raw)
	if err != nil || parsed.Scheme != "https" || parsed.Hostname() == "" || parsed.User != nil {
		return fmt.Errorf("%w: repository_url must be an HTTPS URL without embedded credentials", ErrInvalidRepository)
	}
	if len(s.supportedHosts) > 0 && !s.supportedHosts[strings.ToLower(parsed.Hostname())] {
		return fmt.Errorf("%w: repository host is not allowed", ErrInvalidRepository)
	}
	return nil
}

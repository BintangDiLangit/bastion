package dependency

import (
	"context"
	"fmt"

	"github.com/sirupsen/logrus"
)

// DependencyParser interface for all dependency file parsers
type DependencyParser interface {
	Parse(ctx context.Context, filePath string) (*DependencyManifest, error)
	SupportsFile(filePath string) bool
	GetPackageManager() PackageManager
}

// ParserManager coordinates different parsers
type ParserManager struct {
	parsers map[PackageManager]DependencyParser
	logger  *logrus.Logger
}

// NewParserManager creates a new ParserManager with registered parsers
func NewParserManager(logger *logrus.Logger) *ParserManager {
	pm := &ParserManager{
		parsers: make(map[PackageManager]DependencyParser),
		logger:  logger,
	}
	return pm
}

// RegisterParser adds a parser for a specific package manager
func (pm *ParserManager) RegisterParser(pmType PackageManager, parser DependencyParser) {
	pm.parsers[pmType] = parser
}

// Parse selects the appropriate parser and processes the file
func (pm *ParserManager) Parse(ctx context.Context, file DependencyFile) (*DependencyManifest, error) {
	parser, exists := pm.parsers[file.PackageManager]
	if !exists {
		return nil, fmt.Errorf("no parser registered for package manager: %s", file.PackageManager)
	}

	if !parser.SupportsFile(file.Path) {
		return nil, fmt.Errorf("parser %s does not support file: %s", file.PackageManager, file.Path)
	}

	return parser.Parse(ctx, file.Path)
}

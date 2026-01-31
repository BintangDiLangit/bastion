// Package logger provides logging utilities.
package logger

import (
	"io"
	"os"

	"github.com/sirupsen/logrus"

	"code-security-auditor/internal/config"
)

// New creates a new logger based on configuration.
func New(cfg config.LoggingConfig) *logrus.Logger {
	log := logrus.New()

	// Set log level
	level, err := logrus.ParseLevel(cfg.Level)
	if err != nil {
		level = logrus.InfoLevel
	}
	log.SetLevel(level)

	// Set formatter
	switch cfg.Format {
	case "json":
		log.SetFormatter(&logrus.JSONFormatter{
			TimestampFormat: "2006-01-02T15:04:05.000Z07:00",
		})
	default:
		log.SetFormatter(&logrus.TextFormatter{
			FullTimestamp:   true,
			TimestampFormat: "2006-01-02 15:04:05",
		})
	}

	// Set output
	switch cfg.Output {
	case "file":
		file, err := os.OpenFile(cfg.FilePath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0666)
		if err == nil {
			log.SetOutput(file)
		} else {
			log.SetOutput(os.Stdout)
			log.WithError(err).Warn("Failed to open log file, using stdout")
		}
	default:
		log.SetOutput(os.Stdout)
	}

	return log
}

// NewWithWriter creates a logger with a custom writer.
func NewWithWriter(w io.Writer, level string, format string) *logrus.Logger {
	log := logrus.New()
	log.SetOutput(w)

	lvl, err := logrus.ParseLevel(level)
	if err != nil {
		lvl = logrus.InfoLevel
	}
	log.SetLevel(lvl)

	switch format {
	case "json":
		log.SetFormatter(&logrus.JSONFormatter{})
	default:
		log.SetFormatter(&logrus.TextFormatter{
			FullTimestamp: true,
		})
	}

	return log
}

// Fields is an alias for logrus.Fields.
type Fields = logrus.Fields

// WithFields returns a new entry with fields.
func WithFields(log *logrus.Logger, fields Fields) *logrus.Entry {
	return log.WithFields(fields)
}

// NewNop creates a no-op logger for testing.
func NewNop() *logrus.Logger {
	log := logrus.New()
	log.SetOutput(io.Discard)
	return log
}

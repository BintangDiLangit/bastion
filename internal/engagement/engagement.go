// Package engagement loads the multi-application pentest config (bastion.yaml):
// the assessor identity plus the list of projects to assess. It is a flat
// config list, not a project-management system.
package engagement

import (
	"fmt"
	"strings"

	"github.com/spf13/viper"
)

// Engagement is the whole bastion.yaml: who is assessing, and what.
type Engagement struct {
	Assessor Assessor  `mapstructure:"assessor"`
	Projects []Project `mapstructure:"projects"`
}

// Assessor is the person or team producing the reports (report cover metadata).
type Assessor struct {
	Name    string `mapstructure:"name"`
	Company string `mapstructure:"company"`
	Contact string `mapstructure:"contact"`
}

// Project is one application under assessment (Avora, Airapay, ...).
type Project struct {
	Name    string `mapstructure:"name"`
	Client  string `mapstructure:"client"`
	Contact string `mapstructure:"contact"`
	Source  Source `mapstructure:"source"`
}

// Source is where a project's code lives. Tokens are never stored here — only
// the NAME of an env var that holds one (TokenEnv).
type Source struct {
	Type     string `mapstructure:"type"`   // "local" | "git"
	Path     string `mapstructure:"path"`   // local
	URL      string `mapstructure:"url"`    // git
	Branch   string `mapstructure:"branch"` // git (optional)
	TokenEnv string `mapstructure:"token_env"`
}

// Load reads and parses a bastion.yaml at the given path.
func Load(path string) (*Engagement, error) {
	v := viper.New() // fresh instance: no CSA_ env prefix, no API config lifecycle
	v.SetConfigFile(path)
	if err := v.ReadInConfig(); err != nil {
		return nil, fmt.Errorf("read engagement config %s: %w", path, err)
	}
	var e Engagement
	if err := v.Unmarshal(&e); err != nil {
		return nil, fmt.Errorf("parse engagement config %s: %w", path, err)
	}
	return &e, nil
}

// Project looks up a project by name, case-insensitively. The error lists the
// known names so a typo is self-correcting.
func (e *Engagement) Project(name string) (*Project, error) {
	for i := range e.Projects {
		if strings.EqualFold(e.Projects[i].Name, name) {
			return &e.Projects[i], nil
		}
	}
	known := make([]string, len(e.Projects))
	for i, p := range e.Projects {
		known[i] = p.Name
	}
	return nil, fmt.Errorf("project %q not found; known projects: %s", name, strings.Join(known, ", "))
}

// Validate checks a source is internally consistent.
func (s Source) Validate() error {
	switch s.Type {
	case "local":
		if strings.TrimSpace(s.Path) == "" {
			return fmt.Errorf("source type %q requires a path", s.Type)
		}
	case "git":
		if strings.TrimSpace(s.URL) == "" {
			return fmt.Errorf("source type %q requires a url", s.Type)
		}
	case "":
		return fmt.Errorf("source type is required (local|git)")
	default:
		return fmt.Errorf("unknown source type %q (want local|git)", s.Type)
	}
	return nil
}

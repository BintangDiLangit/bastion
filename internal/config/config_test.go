package config

import "testing"

func TestLoadExampleConfig(t *testing.T) {
	config, err := Load("../../configs/config.yaml")
	if err != nil {
		t.Fatal(err)
	}
	if config.Database.DBName != "code_security_auditor" {
		t.Fatalf("database name = %q", config.Database.DBName)
	}
	if config.Git.TempDir != "/tmp/code-security-auditor/repos" {
		t.Fatalf("git temp dir = %q", config.Git.TempDir)
	}
	if config.ADK.Enabled {
		t.Fatal("example config must not enable unconfigured AI")
	}
}

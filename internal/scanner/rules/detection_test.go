package rules

// bastion:ignore-file sql_injection,xss,secrets detector regression fixtures

import "testing"

func parsed(path, language string, lines ...string) *ParsedFileAdapter {
	return &ParsedFileAdapter{Path: path, Language: language, Lines: lines}
}

func TestSQLInjectionSignal(t *testing.T) {
	rule := NewSQLInjectionRule()
	if got := rule.Check(parsed("app.go", "go", `db.Query("SELECT * FROM users WHERE id=" + userID)`)); len(got) != 1 {
		t.Fatalf("vulnerable query: got %d findings", len(got))
	}
	if got := rule.Check(parsed("app.go", "go", `fmt.Errorf("refusing to DELETE path: %s", path)`)); len(got) != 0 {
		t.Fatalf("error message: got %d findings", len(got))
	}
}

func TestXSSSignal(t *testing.T) {
	rule := NewXSSRule()
	if got := rule.Check(parsed("app.js", "javascript", `element.innerHTML = userInput`)); len(got) != 1 {
		t.Fatalf("unsafe DOM write: got %d findings", len(got))
	}
	if got := rule.Check(parsed("redis.go", "go", `client.Eval(ctx, script)`)); len(got) != 0 {
		t.Fatalf("Redis Eval: got %d findings", len(got))
	}
}

func TestSecretSignal(t *testing.T) {
	rule := NewSecretsRule()
	if got := rule.Check(parsed("app.go", "go", `header := "Basic QWxhZGRpbjpvcGVuIHNlc2FtZQ=="`)); len(got) != 1 {
		t.Fatalf("Basic credential: got %d findings", len(got))
	}
	if got := rule.Check(parsed("app.go", "go", `header := "Basic realm=Restricted"`)); len(got) != 0 {
		t.Fatalf("Basic challenge: got %d findings", len(got))
	}
}

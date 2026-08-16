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

// The suggested-fix feature relies on the match span being captured. An
// interface rule (SQL) and a pattern rule (TLS) exercise both match sites.
func TestMatchSpanCaptured(t *testing.T) {
	line := `db.Query("SELECT * FROM users WHERE id=" + userID)`
	got := NewSQLInjectionRule().Check(parsed("app.go", "go", line))
	if len(got) != 1 {
		t.Fatalf("got %d findings", len(got))
	}
	f := got[0]
	if f.MatchText == "" || f.MatchEnd <= f.MatchStart {
		t.Fatalf("no span captured: text=%q start=%d end=%d", f.MatchText, f.MatchStart, f.MatchEnd)
	}
	if line[f.MatchStart:f.MatchEnd] != f.MatchText {
		t.Errorf("span/text disagree: line[%d:%d]=%q, MatchText=%q",
			f.MatchStart, f.MatchEnd, line[f.MatchStart:f.MatchEnd], f.MatchText)
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

// The README advertises seven languages. Every one of them has its own regex
// table, and only Go and JavaScript had a fixture — a typo in any of the other
// five would have shipped silently.
func TestSQLInjectionPerLanguage(t *testing.T) {
	rule := NewSQLInjectionRule()
	for _, test := range []struct {
		path     string
		language string
		line     string
	}{
		{"a.go", "go", `db.Query("SELECT * FROM users WHERE id=" + userID)`},
		{"a.py", "python", `cursor.execute(f"SELECT * FROM users WHERE id={user_id}")`},
		{"a.js", "javascript", "conn.query(`SELECT * FROM users WHERE id=${id}`)"},
		{"a.ts", "typescript", "conn.query(`SELECT * FROM users WHERE id=${id}`)"},
		{"a.java", "java", `stmt.executeQuery("SELECT * FROM users WHERE id=" + id);`},
		{"a.php", "php", `mysqli_query($conn, "SELECT * FROM users WHERE id=" . $id);`},
		{"a.rb", "ruby", `User.where("name = #{params[:name]}")`},
	} {
		t.Run(test.language, func(t *testing.T) {
			if got := rule.Check(parsed(test.path, test.language, test.line)); len(got) == 0 {
				t.Fatalf("%s: no finding for %q", test.language, test.line)
			}
		})
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

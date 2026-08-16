package engagement

import "testing"

func TestLoadAndResolve(t *testing.T) {
	e, err := Load("testdata/bastion.yaml")
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if e.Assessor.Name != "Test Assessor" {
		t.Errorf("assessor = %q", e.Assessor.Name)
	}
	if len(e.Projects) != 2 {
		t.Fatalf("got %d projects", len(e.Projects))
	}

	// case-insensitive lookup
	p, err := e.Project("AVORA")
	if err != nil {
		t.Fatalf("resolve avora: %v", err)
	}
	if p.Source.Type != "git" || p.Source.URL == "" || p.Source.Branch != "develop" {
		t.Errorf("avora source = %+v", p.Source)
	}

	if _, err := e.Project("nope"); err == nil {
		t.Error("expected error for unknown project")
	}
}

func TestSourceValidate(t *testing.T) {
	cases := []struct {
		src Source
		ok  bool
	}{
		{Source{Type: "local", Path: "/x"}, true},
		{Source{Type: "git", URL: "https://x"}, true},
		{Source{Type: "git"}, false},
		{Source{Type: "local"}, false},
		{Source{Type: ""}, false},
		{Source{Type: "url"}, false},
	}
	for i, c := range cases {
		err := c.src.Validate()
		if (err == nil) != c.ok {
			t.Errorf("case %d: got err=%v, want ok=%v", i, err, c.ok)
		}
	}
}

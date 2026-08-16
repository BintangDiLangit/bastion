package report

import (
	"strings"
	"testing"
)

func TestHexOK(t *testing.T) {
	ok := []string{"#123a5e", "#FFFFFF", "#000000"}
	bad := []string{"", "123a5e", "#12345", "#12345g", "navy", "#1234567"}
	for _, s := range ok {
		if !hexOK(s) {
			t.Errorf("hexOK(%q) = false, want true", s)
		}
	}
	for _, s := range bad {
		if hexOK(s) {
			t.Errorf("hexOK(%q) = true, want false", s)
		}
	}
}

func TestDarken(t *testing.T) {
	// #808080 (128) * 0.5 -> 64 = 0x40
	if got := darken("#808080", 0.5); got != "#404040" {
		t.Errorf("darken = %q, want #404040", got)
	}
	// invalid passes through unchanged
	if got := darken("nope", 0.5); got != "nope" {
		t.Errorf("darken(invalid) = %q", got)
	}
}

func TestBrandCSS(t *testing.T) {
	if brandCSS("bogus") != "" {
		t.Error("invalid color should yield empty CSS")
	}
	css := string(brandCSS("#7b2d8e"))
	for _, want := range []string{"--brand:#7b2d8e", "--brand-deep:", "--brand-mid:#7b2d8e"} {
		if !strings.Contains(css, want) {
			t.Errorf("brandCSS missing %q in %q", want, css)
		}
	}
}

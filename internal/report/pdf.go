package report

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
)

// ErrNoBrowser means no Chrome/Chromium/Edge was found to render the PDF. The
// CLI treats this as non-fatal: the HTML report is still written.
var ErrNoBrowser = errors.New("no Chrome/Chromium/Edge browser found for PDF rendering")

// browserNames are looked up on PATH.
var browserNames = []string{
	"google-chrome", "google-chrome-stable", "chromium", "chromium-browser",
	"chrome", "microsoft-edge", "microsoft-edge-stable", "msedge", "brave-browser",
}

// browserPaths are absolute fallbacks (macOS/Windows app bundles not on PATH).
var browserPaths = []string{
	"/Applications/Google Chrome.app/Contents/MacOS/Google Chrome",
	"/Applications/Chromium.app/Contents/MacOS/Chromium",
	"/Applications/Microsoft Edge.app/Contents/MacOS/Microsoft Edge",
	"/Applications/Brave Browser.app/Contents/MacOS/Brave Browser",
	`C:\Program Files\Google\Chrome\Application\chrome.exe`,
	`C:\Program Files (x86)\Google\Chrome\Application\chrome.exe`,
	`C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe`,
}

// FindBrowser returns the path to a usable headless browser, or ErrNoBrowser.
func FindBrowser() (string, error) {
	for _, name := range browserNames {
		if p, err := exec.LookPath(name); err == nil {
			return p, nil
		}
	}
	for _, p := range browserPaths {
		if info, err := os.Stat(p); err == nil && !info.IsDir() {
			return p, nil
		}
	}
	return "", ErrNoBrowser
}

// RenderPDF converts rendered HTML to PDF via headless Chrome. It returns
// ErrNoBrowser (wrapped) if no browser is available, so the caller can fall
// back to the HTML output. The HTML is the single source of truth — no second
// layout engine.
func RenderPDF(ctx context.Context, html []byte) ([]byte, error) {
	browser, err := FindBrowser()
	if err != nil {
		return nil, err
	}

	dir, err := os.MkdirTemp("", "bastion-pdf-*")
	if err != nil {
		return nil, fmt.Errorf("pdf temp dir: %w", err)
	}
	defer os.RemoveAll(dir)

	inPath := filepath.Join(dir, "report.html")
	outPath := filepath.Join(dir, "report.pdf")
	if err := os.WriteFile(inPath, html, 0600); err != nil {
		return nil, fmt.Errorf("pdf write html: %w", err)
	}

	// file:// URL so the browser loads local content only (no network).
	fileURL := "file://" + filepath.ToSlash(inPath)
	args := []string{
		"--headless=new", "--disable-gpu", "--no-sandbox",
		"--print-to-pdf=" + outPath, fileURL,
	}
	cmd := exec.CommandContext(ctx, browser, args...)
	if out, err := cmd.CombinedOutput(); err != nil {
		return nil, fmt.Errorf("headless browser failed: %w: %s", err, out)
	}

	pdf, err := os.ReadFile(outPath)
	if err != nil {
		return nil, fmt.Errorf("pdf read: %w", err)
	}
	return pdf, nil
}

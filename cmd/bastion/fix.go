package main

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/BintangDiLangit/bastion/internal/models"
	"github.com/BintangDiLangit/bastion/internal/scanner"
)

// fixCmd creates the `fix` command: it scans, then previews or applies the
// deterministic, value-restoring fixes. `scan` stays read-only; writing lives
// here behind an explicit --write, and only ever touches models.FixSafeReplace
// findings. Everything else is guidance the agent or a human applies.
func fixCmd() *cobra.Command {
	var (
		excludePaths []string
		enableRules  []string
		maxFiles     int
		timeout      int
		write        bool
	)

	cmd := &cobra.Command{
		Use:   "fix [path]",
		Short: "Preview or apply the safe, auto-fixable findings",
		Long: `Scan a directory, then show the deterministic fixes Bastion can apply
safely (for example, re-enabling disabled TLS verification).

By default it prints a diff and changes nothing. Pass --write to apply.
Findings that are not mechanically safe to fix are left untouched; use their
suggested-fix guidance in the scan output instead.

Examples:
  # Preview the safe fixes
  bastion fix .

  # Apply them to the working tree
  bastion fix . --write`,
		Args: cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			path := "."
			if len(args) > 0 {
				path = args[0]
			}
			return runFix(path, scanOptions{
				excludePaths:   excludePaths,
				enableRules:    enableRules,
				maxFiles:       maxFiles,
				timeout:        time.Duration(timeout) * time.Minute,
				failOnCritical: false,
			}, write)
		},
	}

	cmd.Flags().BoolVar(&write, "write", false, "apply the fixes to the working tree (default: preview only)")
	cmd.Flags().StringSliceVarP(&excludePaths, "exclude", "e", nil, "paths to exclude (comma-separated)")
	cmd.Flags().StringSliceVarP(&enableRules, "rules", "r", nil, "rules to enable (comma-separated)")
	cmd.Flags().IntVarP(&maxFiles, "max-files", "m", 1000, "maximum files to scan")
	cmd.Flags().IntVarP(&timeout, "timeout", "t", 30, "scan timeout in minutes")

	return cmd
}

// safeFix is one applicable replacement, resolved to absolute byte offsets.
type safeFix struct {
	line     int // 1-based
	colStart int // 1-based, inclusive
	colEnd   int // 1-based, exclusive
	before   string
	after    string
}

func runFix(path string, opts scanOptions, write bool) error {
	log := newLogger()

	absPath, err := filepath.Abs(path)
	if err != nil {
		return fmt.Errorf("invalid path: %w", err)
	}
	info, err := os.Stat(absPath)
	if err != nil {
		return fmt.Errorf("path does not exist: %w", err)
	}
	if !info.IsDir() {
		return fmt.Errorf("path is not a directory")
	}

	result, err := scanTarget(scanner.Target{Type: scanner.TargetSourceLocal, Path: absPath}, opts, log)
	if err != nil {
		return fmt.Errorf("scan failed: %w", err)
	}

	// Group applicable fixes by file.
	byFile := map[string][]safeFix{}
	for _, v := range result.Vulnerabilities {
		if v.Fix == nil || v.Fix.Kind != models.FixSafeReplace {
			continue
		}
		if v.ColumnStart == nil || v.ColumnEnd == nil {
			continue
		}
		byFile[v.FilePath] = append(byFile[v.FilePath], safeFix{
			line:     v.LineStart,
			colStart: *v.ColumnStart,
			colEnd:   *v.ColumnEnd,
			before:   v.Fix.Before,
			after:    v.Fix.Replacement,
		})
	}

	if len(byFile) == 0 {
		fmt.Println("No auto-fixable findings. Run `bastion scan` to see guidance for the rest.")
		return nil
	}

	applied, skipped := 0, 0
	for _, file := range sortedKeys(byFile) {
		// Findings carry a path relative to the scan root; resolve it to read
		// and write the real file, but print the relative path.
		readPath := file
		if !filepath.IsAbs(readPath) {
			readPath = filepath.Join(absPath, file)
		}
		n, s, err := applyFileFixes(readPath, file, byFile[file], write)
		if err != nil {
			log.WithError(err).WithField("file", file).Warn("skipped file")
			skipped += len(byFile[file])
			continue
		}
		applied += n
		skipped += s
	}

	verb := "applicable"
	if write {
		verb = "applied"
	}
	fmt.Printf("\n%d fix(es) %s", applied, verb)
	if skipped > 0 {
		fmt.Printf(", %d skipped (source changed since scan)", skipped)
	}
	fmt.Println(".")
	if !write && applied > 0 {
		fmt.Println("Re-run with --write to apply.")
	}
	return nil
}

// applyFileFixes resolves the fixes for one file, prints a diff, and (when
// write is set) writes the result back. Fixes are applied right-to-left within
// a line and bottom-to-top across lines so earlier edits never shift a later
// offset. A fix whose recorded `before` no longer matches the file is skipped.
func applyFileFixes(path, display string, fixes []safeFix, write bool) (applied, skipped int, err error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return 0, 0, err
	}
	lines := strings.Split(string(raw), "\n")

	sort.Slice(fixes, func(i, j int) bool {
		if fixes[i].line != fixes[j].line {
			return fixes[i].line > fixes[j].line
		}
		return fixes[i].colStart > fixes[j].colStart
	})

	changed := false
	for _, f := range fixes {
		idx := f.line - 1
		if idx < 0 || idx >= len(lines) {
			skipped++
			continue
		}
		line := lines[idx]
		s, e := f.colStart-1, f.colEnd-1
		if s < 0 || e > len(line) || s > e || line[s:e] != f.before {
			// Drift: the file changed since the scan, or offsets don't line up.
			skipped++
			continue
		}
		newLine := line[:s] + f.after + line[e:]
		fmt.Printf("%s:%d\n- %s\n+ %s\n", display, f.line, line, newLine)
		lines[idx] = newLine
		changed = true
		applied++
	}

	if write && changed {
		if err := os.WriteFile(path, []byte(strings.Join(lines, "\n")), 0o644); err != nil {
			return applied, skipped, err
		}
	}
	return applied, skipped, nil
}

func sortedKeys(m map[string][]safeFix) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

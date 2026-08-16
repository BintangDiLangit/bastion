---
name: security-review
description: "Drive Bastion to run a full source-code security review: scan for vulnerabilities, triage new critical/high findings, apply the safe auto-fixes, draft patches for the rest from each finding's structured Fix, verify the delta with fingerprints, and produce a professional report. Use when the user asks to security-review, audit, pentest, or find-and-fix vulnerabilities in code they own or are authorized to test. Bastion is SAST — it reads source; it does not touch a live website."
argument-hint: "[path-or-project] [--write] [--report]"
license: MIT
metadata:
  author: BintangDiLangit
  version: "0.1.0"
---

# Security Review (Bastion)

Turn a codebase into a triaged, mostly-fixed, reportable security assessment by
driving [Bastion](https://github.com/BintangDiLangit/bastion). Bastion is a
deterministic static scanner: stable finding fingerprints, a machine-readable
`Fix` per finding, and professional HTML/Markdown/PDF reports.

## When to use

- "Security-review / audit / pentest this repo", "find and fix vulnerabilities".
- Before a release, or as an agent step after writing code: scan the delta,
  explain only what's new, apply the safe fixes.
- Producing a client-facing security report from a configured engagement.

## Authorization — read first

Bastion reads **source code**. Only ever run it against code the user **owns or
is explicitly authorized to test**. Do not use this skill to point Bastion (or
any other tool) at a system, repository, or website the user has no permission
for — "to help them fix it" is not authorization, and scanning a target without
it can be a crime. If the target's ownership is unclear, ask before scanning.
Bastion cannot test a live website; it needs the source on disk.

## Prerequisites

Bastion must be installed (`bastion version`). If it is not:

```sh
brew install --cask BintangDiLangit/tap/bastion   # macOS / Linux
# or
go install github.com/BintangDiLangit/bastion/cmd/bastion@latest
```

Two ways to drive it, both used below:

- **CLI** — `bastion scan|fix|report`. Best for the fix/report steps.
- **MCP** — the `bastion_scan` tool (read-only), when Bastion's MCP server is
  configured in the client. Best for scanning inside an agent loop.

## Workflow

Run these in order. Stop and report if the target is not authorized (see above).

### 1. Baseline scan

```sh
bastion scan <path> --format json -o bastion.json
```

Or via MCP: call `bastion_scan` with `{ "path": "<relative-dir>" }`. The result
is `ScanOutput`; each entry in `.vulnerabilities` (CLI) / `.findings` (MCP) is a
finding — see **Finding & Fix contract** below. Keep the `fingerprint` of every
finding: it is how step 5 proves a fix worked.

`scan` exits non-zero only on a **critical** finding. Read the JSON regardless.

### 2. Triage — explain what matters, not everything

Rank by `severity` (critical → high) and `cvss_score`. For each **new**
critical/high finding: open the file at `file_path:line_start`, read the code,
and explain the concrete risk in one or two sentences using the finding's
`description` and `fix.summary`. Do not dump every low/medium finding at the
user — summarize those as counts.

### 3. Apply the safe auto-fixes

```sh
bastion fix <path>            # preview: prints a diff, writes nothing
bastion fix <path> --write    # apply the safe, value-restoring fixes
```

`bastion fix` only touches findings whose `fix.kind == "safe_replace"` (for
example, re-enabling disabled TLS verification). Show the user the preview diff
before running `--write`. It skips any finding whose recorded code has drifted.

### 4. Draft patches for the guidance findings

For findings with `fix.kind == "guidance"`, Bastion will not rewrite them — the
secure form needs judgement (parameterizing a query, changing a hash). Use the
finding's `fix.before` (the real matched code) and `fix.after` (a secure
exemplar) plus the surrounding file to write a correct patch, apply it, and
explain the change. Never blind-apply a guidance `fix.after` — it is an example,
not a drop-in.

### 5. Verify the delta

Re-scan and compare against the baseline fingerprints so you report what
actually changed, not the whole list again:

- MCP: pass the step-1 fingerprints as `baseline_fingerprints` to `bastion_scan`;
  the result's `delta` gives `new`, `resolved_fingerprints`, and `unchanged`.
- CLI: re-run `bastion scan <path> --format json` and diff the `fingerprint`
  set against `bastion.json`. A fixed finding disappears; confirm the ones you
  fixed are in the resolved set and no new criticals appeared.

### 6. Report

If the repo has an engagement config (`bastion.yaml`, see
`bastion.yaml.example`):

```sh
bastion report --project <name> --report-format all -o <name>-report
```

That produces a branded HTML/Markdown/PDF report with per-finding remediation
and the suggested fixes. If there is no engagement config, summarize the
assessment yourself: what was scanned, what was found by severity, what was
auto-fixed, what still needs a human, and the residual risk.

## Finding & Fix contract

Each finding (JSON) carries at least:

| Field | Meaning |
|---|---|
| `rule_id`, `title`, `severity`, `category` | what and how bad |
| `file_path`, `line_start`, `column_start`, `column_end` | where |
| `fingerprint` | stable id for delta comparison |
| `cvss_score`, `cvss_vector`, `cwe` | scoring (CVSS values are signed off, not generated) |
| `code_snippet` | rendered ±2-line evidence block |
| `remediation` | human-prose "how to fix" |
| `fix` | machine-readable suggested fix (below) |

The `fix` object:

| Field | Meaning |
|---|---|
| `summary` | one line: what to change |
| `kind` | `safe_replace` (auto-fixable) or `guidance` (you apply it) |
| `before` | the **real matched code** from the file |
| `after` | transformed code (safe) or a secure exemplar (guidance) |
| `replacement` | for `safe_replace` only: exact text for the matched span |

A finding may have no `fix` (older/unmapped rule) — fall back to `remediation`.

## Guardrails

- Never auto-apply a `guidance` fix; only `safe_replace` is mechanical.
- Re-scan after fixing; never claim a finding is resolved without the delta.
- Report faithfully: if a fix was skipped as drifted, or a guidance patch is
  uncertain, say so. Don't inflate or hide severity — CVSS values are reviewed.
- Secrets are masked in output by design; do not try to recover the raw value.

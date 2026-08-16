# Five-minute video demo

This script shows working behavior without slides or invented features.

## 1. Hook — 20 seconds

> Most security tools repeat the same wall of warnings. Bastion is local-first,
> agent-friendly, and built around one useful question: what changed?

Show the repository and say that CLI and MCP keep source local.

## 2. Scan — 45 seconds

```bash
make build-cli
./bin/bastion scan /path/to/demo-project
```

Open one finding. Explain rule ID, severity, location, evidence, and stable
fingerprint. Say “review lead,” not “proven vulnerability.”

## 3. Suppress with accountability — 45 seconds

For a deliberately safe finding, add:

```go
// bastion:ignore-next-line RULE_ID -- short technical reason
```

Run the scan again and show that only the reviewed finding disappears. Avoid
using `all` in the demo.

## 4. MCP — 60 seconds

Show the MCP config from the README. In the coding agent, ask:

> Run `bastion_scan`. Explain only new critical or high findings. Do not edit.

Point out that the tool is read-only, rooted to one directory, rejects path
escapes, and has scan limits.

## 5. Delta — 60 seconds

Run a baseline scan, make a small intentionally vulnerable change, then scan
again with the baseline fingerprints. Show:

- the introduced finding under `new`;
- old findings counted under `unchanged`;
- after fixing it, its fingerprint under `resolved`.

This is the main product moment.

## 6. Close — 20 seconds

> Bastion is alpha and pattern-based. It will not replace human security
> judgment. It gives developers a small, local, auditable security loop that
> works from the terminal or through MCP.

End on the repository URL and the exact quick-start command:

```bash
go run ./cmd/bastion scan .
```

## Recording checklist

- Use a disposable demo repository with an intentional example vulnerability.
- Increase terminal font size and hide tokens, usernames, and unrelated tabs.
- Prebuild once so dependency downloads do not consume recording time.
- Keep the raw scan visible; do not imply AI generated the underlying finding.
- Do not claim hosted service, UI, automatic fixes, full data-flow analysis, or
  production sandboxing.

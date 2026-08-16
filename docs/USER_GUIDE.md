# Developer guide

Use the CLI for local development and CI. Use MCP when an AI coding agent needs
structured findings. Use the API only when scan history must be shared.

## Local review

```bash
make build-cli
./bin/bastion scan .
```

The command exits non-zero when it finds a critical issue. Override this for
exploration:

```bash
./bin/bastion scan . --fail-on-critical=false
```

Save JSON for automation or SARIF for a code-scanning platform:

```bash
./bin/bastion scan . --format json --output bastion.json
./bin/bastion scan . --format sarif --output bastion.sarif
```

Use `./bin/bastion scan --help` for limits, exclusions, and rule selection.

## Read a finding

Treat a finding as a review lead, not a verdict:

1. Check whether untrusted input reaches the reported operation.
2. Check whether validation or encoding already exists upstream.
3. Fix the data flow when exploitable.
4. Suppress only when reviewed, using the exact rule ID and a reason.

```go
// bastion:ignore-next-line xss -- sanitized by renderSafeHTML
template.HTML(reviewedHTML)
```

Stable fingerprints identify the same finding after nearby lines move. MCP and
the API use them to show review delta instead of repeating old noise.

## MCP workflow

Build `bin/bastion-mcp`, configure it as shown in the
[README](../README.md#connect-an-ai-coding-tool-with-mcp), then ask your agent:

> Run `bastion_scan`. Show critical and high findings, trace each data flow,
> and do not edit code until I approve.

On the next review, pass the previous fingerprints as
`baseline_fingerprints`. Bastion returns:

- `new`: full findings not in the baseline
- `resolved`: baseline fingerprints no longer found
- `unchanged`: number already reviewed

## What Bastion does not do

Bastion does not currently provide accounts, a web UI, automatic fixes,
dismissal APIs, hosted repository registration, or a published GitHub Action.
Do not follow tutorials claiming those features exist.

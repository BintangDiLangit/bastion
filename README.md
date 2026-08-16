# Bastion

Local-first security review for developers and AI coding agents.

Bastion scans source code with deterministic rules, produces stable finding
fingerprints, and compares a scan with its baseline. It works as a CLI, an MCP
server, or a small self-hosted API.

> **Alpha:** CLI and MCP are the recommended paths. The API is usable for
> trusted self-hosted environments, but scans run inside the API process and
> repositories are not sandboxed.

## Why Bastion?

- **Local first:** source stays on your machine when using CLI or MCP.
- **Agent friendly:** one read-only `bastion_scan` MCP tool with bounded access.
- **Review the delta:** stable fingerprints separate new, resolved, and
  unchanged findings.
- **Auditable suppression:** suppress a specific rule with a reason in code.
- **Useful output:** text for humans, JSON for automation, SARIF for code hosts.

Rules are tuned for Go, Python, JavaScript, TypeScript, Java, PHP, and Ruby.
Language-agnostic rules — secrets, weak crypto, dependency manifests — apply to
every recognized text file.

## Install

**Homebrew** (macOS and Linux)

```bash
brew install --cask BintangDiLangit/tap/bastion
```

**Go** (requires Go 1.25 or newer)

```bash
go install github.com/BintangDiLangit/bastion/cmd/bastion@latest
```

**Docker** — no install at all

```bash
docker run --rm -v "$PWD:/src" ghcr.io/bintangdilangit/bastion
```

**Debian, RPM, Alpine** packages and prebuilt binaries for macOS, Linux and
Windows are attached to every
[release](https://github.com/BintangDiLangit/bastion/releases).

**From source**

```bash
git clone https://github.com/BintangDiLangit/bastion.git
cd bastion && make build-cli
```

## Try it in 60 seconds

```bash
bastion scan .
```

Useful commands:

```bash
# Keep a machine-readable report
bastion scan . --format json --output bastion.json

# Produce a GitHub-compatible SARIF report
bastion scan . --format sarif --output bastion.sarif

# Select rules or exclude paths.
# A selector matches a rule ID or a category, so this keeps both the
# sql_injection rule and RULE-SQL-001.
bastion scan . --rules sql_injection,xss,secrets \
  --exclude vendor,node_modules

# Do not fail the command when a critical finding exists
bastion scan . --fail-on-critical=false
```

`scan` exits non-zero only on a **critical** finding. High findings are
reported and do not fail the command.

Run `bastion rules` to see the rules implemented by your installed version.

## Connect an AI coding tool with MCP

`bastion-mcp` ships alongside the CLI in every install method above (from
source: `make build-mcp`). Add it to an MCP client, replacing the project path:

```json
{
  "mcpServers": {
    "bastion": {
      "command": "bastion-mcp",
      "args": ["-root", "/absolute/path/to/project"]
    }
  }
}
```

If your client does not resolve `PATH`, use the absolute path that
`which bastion-mcp` prints.

Ask the agent: **“Run `bastion_scan` on this project and explain only new
critical or high findings.”**

The MCP server is read-only. It accepts relative paths inside `-root`, rejects
path and symlink escapes, never reads through a symlink inside the scan tree,
and limits scan size. Pass fingerprints from a prior result as
`baseline_fingerprints` to receive new findings, resolved fingerprints, and an
unchanged count. Reported paths are relative to `-root`, so a scan of one
subdirectory compares cleanly against a baseline taken from the whole tree.

## Suppress a reviewed false positive

Suppress one finding with its exact rule ID:

```go
// bastion:ignore-next-line xss -- sanitized by renderSafeHTML
template.HTML(reviewedHTML)
```

Or suppress selected rules for an entire detector fixture:

```go
// bastion:ignore-file secrets,RULE-DESER-001 -- test signatures only
```

Everything after `--` is a human reason and is never read as a rule ID.

`all` is supported for generated files, though excluding the generated path is
usually clearer.

## Self-host the API

Docker is the shortest supported setup:

```bash
POSTGRES_PASSWORD='replace-with-a-database-password' \
BASTION_API_KEY='replace-with-a-long-random-api-key' \
docker compose -f deployments/docker/docker-compose.yml up --build
```

Start a scan:

```bash
curl -X POST http://localhost:8080/api/v1/scans \
  -H 'X-API-Key: replace-with-a-long-random-api-key' \
  -H 'Content-Type: application/json' \
  -d '{"repository_url":"https://github.com/BintangDiLangit/bastion","branch":"main"}'
```

Use the returned `scan_id`:

```bash
curl -H 'X-API-Key: replace-with-a-long-random-api-key' \
  http://localhost:8080/api/v1/scans/SCAN_ID

curl -H 'X-API-Key: replace-with-a-long-random-api-key' \
  http://localhost:8080/api/v1/scans/SCAN_ID/vulnerabilities

curl -H 'X-API-Key: replace-with-a-long-random-api-key' \
  http://localhost:8080/api/v1/scans/SCAN_ID/delta
```

The delta endpoint automatically uses the repository's previous completed scan.
See [API documentation](docs/API.md).

## Development

```bash
make test
make build-cli
make build-mcp
make scan
```

Important paths:

```text
cmd/bastion/      local scanner
cmd/bastion-mcp/  MCP stdio server
cmd/bastion-api/  HTTP API
internal/scanner/ rule engine
internal/service/ persisted scan lifecycle and delta
docs/             API, deployment, CI, and demo guides
```

## Current boundaries

- Detection is deterministic pattern-based analysis, not proof that code is
  exploitable.
- Private repository credentials are not accepted by the API.
- API scans execute in-process; use CLI or MCP for local development.
- Hosted service, UI, automatic fixes, webhook comments, and a published
  GitHub Action are not shipped.

These boundaries are deliberate: the repository documents only behavior it
actually provides.

## Documentation

- [Developer guide](docs/USER_GUIDE.md)
- [API](docs/API.md)
- [CI integration](docs/CICD.md)
- [Deployment](docs/DEPLOYMENT.md)
- [Architecture](docs/ARCHITECTURE.md)
- [Video demo script](docs/DEMO.md)

## License

MIT. See [LICENSE](LICENSE).

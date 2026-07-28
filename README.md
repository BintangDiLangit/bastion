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

Supported source languages: Go, Python, JavaScript, TypeScript, Java, PHP, and
Ruby.

## Try it in 60 seconds

Requires Go 1.25 or newer.

```bash
git clone https://github.com/BintangDiLangit/bastion.git
cd bastion
go run ./cmd/cli scan .
```

Build a reusable binary:

```bash
make build-cli
./bin/csa scan /path/to/project
```

Useful commands:

```bash
# Keep a machine-readable report
./bin/csa scan . --format json --output bastion.json

# Produce a GitHub-compatible SARIF report
./bin/csa scan . --format sarif --output bastion.sarif

# Select rules or exclude paths
./bin/csa scan . --rules sql_injection,xss,secrets \
  --exclude vendor,node_modules

# Do not fail the command when a critical finding exists
./bin/csa scan . --fail-on-critical=false
```

Run `./bin/csa rules` to see the rules implemented by your installed version.

## Connect an AI coding tool with MCP

```bash
make build-mcp
```

Add this server to an MCP client and replace both absolute paths:

```json
{
  "mcpServers": {
    "bastion": {
      "command": "/absolute/path/to/bastion/bin/bastion-mcp",
      "args": ["-root", "/absolute/path/to/project"]
    }
  }
}
```

Ask the agent: **“Run `bastion_scan` on this project and explain only new
critical or high findings.”**

The MCP server is read-only. It accepts relative paths inside `-root`, rejects
path and symlink escapes, and limits scan size. Pass fingerprints from a prior
result as `baseline_fingerprints` to receive new findings, resolved
fingerprints, and an unchanged count.

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
cmd/cli/          local scanner
cmd/mcp/          MCP stdio server
cmd/api/          HTTP API
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

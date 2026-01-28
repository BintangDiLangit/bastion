# 🔒 Code Security Auditor

An automated code review and security auditing system built with Go and Google ADK for intelligent vulnerability detection, optimization suggestions, and comprehensive security reporting.

[![Go Version](https://img.shields.io/badge/Go-1.25.6-blue.svg)](https://golang.org)
[![License](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)

## Features

- **Automated Security Scanning** - Detect SQL injection, XSS, hardcoded secrets, vulnerable dependencies, and more
- **AI-Powered Analysis** - Use Google Gemini for intelligent vulnerability analysis and remediation suggestions
- **Multi-Language Support** - Analyze Go, Python, JavaScript, TypeScript, Java, PHP, Ruby, and more
- **GitHub/GitLab Integration** - Automatic PR comments and check runs
- **Multiple Report Formats** - JSON, PDF, HTML, Markdown, and SARIF
- **REST API** - Integrate security scanning into your CI/CD pipeline
- **CLI Tool** - Run scans locally from the command line
- **Background Workers** - Queue-based processing for large repositories

## Quick Start

### Prerequisites

- Go 1.25.6 or later
- PostgreSQL 14+
- Redis 7+
- Docker (optional, for containerized deployment)

### Installation

```bash
# Clone the repository
git clone https://github.com/your-org/code-security-auditor.git
cd code-security-auditor

# Run setup script
./scripts/setup.sh

# Or manually:
go mod download
make build
```

### CLI Usage

```bash
# Scan current directory
./bin/csa scan .

# Scan with specific rules
./bin/csa scan . --rules sql_injection,xss,secrets

# Output in SARIF format
./bin/csa scan . --format sarif --output results.sarif

# List available rules
./bin/csa rules

# Get help
./bin/csa --help
```

### API Server

```bash
# Start with Docker Compose
docker-compose -f deployments/docker/docker-compose.yml up -d

# Or run directly
make run-api

# API is available at http://localhost:8080
```

## Configuration

Configuration can be provided via:
1. Config file (`configs/config.yaml`)
2. Environment variables (prefixed with `CSA_`)
3. Command-line flags

Key configuration options:

```yaml
server:
  port: 8080
  
database:
  host: localhost
  port: 5432
  
redis:
  host: localhost
  port: 6379
  
agent:
  api_key: "your-google-ai-api-key"
  model: "gemini-2.0-flash"
```

See [configs/config.yaml](configs/config.yaml) for full configuration options.

## API Reference

### Endpoints

| Method | Endpoint | Description |
|--------|----------|-------------|
| POST | `/api/v1/scans` | Start a new scan |
| GET | `/api/v1/scans/:id` | Get scan details |
| GET | `/api/v1/scans/:id/vulnerabilities` | Get scan vulnerabilities |
| POST | `/api/v1/reports` | Generate a report |
| GET | `/api/v1/reports/:id/download` | Download a report |
| POST | `/api/v1/webhooks/github` | GitHub webhook endpoint |
| POST | `/api/v1/webhooks/gitlab` | GitLab webhook endpoint |

### Example: Start a Scan

```bash
curl -X POST http://localhost:8080/api/v1/scans \
  -H "X-API-Key: your-api-key" \
  -H "Content-Type: application/json" \
  -d '{
    "repository_url": "https://github.com/user/repo",
    "branch": "main"
  }'
```

See [docs/API.md](docs/API.md) for complete API documentation.

## Security Rules

Built-in security rules:

| Rule ID | Description | Severity |
|---------|-------------|----------|
| `sql_injection` | SQL injection vulnerabilities | Critical |
| `xss` | Cross-site scripting | High |
| `secrets` | Hardcoded secrets and credentials | Critical |
| `dependency` | Vulnerable dependencies | High |
| `command_injection` | Command injection | Critical |
| `path_traversal` | Path traversal attacks | High |

See [configs/rules.yaml](configs/rules.yaml) for rule configuration.

## Architecture

```
┌─────────────────┐     ┌─────────────────┐
│   API Server    │────▶│   PostgreSQL    │
└────────┬────────┘     └─────────────────┘
         │
         │              ┌─────────────────┐
         ├─────────────▶│     Redis       │
         │              └────────┬────────┘
         │                       │
┌────────▼────────┐     ┌────────▼────────┐
│    Workers      │────▶│   Scanner       │
└────────┬────────┘     └────────┬────────┘
         │                       │
         │              ┌────────▼────────┐
         └─────────────▶│   AI Agent      │
                        │   (Gemini)      │
                        └─────────────────┘
```

See [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) for detailed architecture documentation.

## Development

### Project Structure

```
code-security-auditor/
├── cmd/                    # Entry points
│   ├── api/               # API server
│   ├── worker/            # Background worker
│   └── cli/               # CLI tool
├── internal/              # Internal packages
│   ├── api/               # HTTP handlers
│   ├── scanner/           # Code scanner
│   ├── agent/             # AI agent
│   ├── models/            # Data models
│   └── ...
├── pkg/                   # Public packages
├── configs/               # Configuration files
├── deployments/           # Deployment configs
└── docs/                  # Documentation
```

### Running Tests

```bash
# Run all tests
make test

# Run with coverage
make coverage

# Run linter
make lint
```

### Building

```bash
# Build all binaries
make build

# Build specific binary
make build-api
make build-worker
make build-cli

# Build Docker images
make docker
```

## Contributing

1. Fork the repository
2. Create your feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Acknowledgments

- [Gin Web Framework](https://github.com/gin-gonic/gin)
- [go-git](https://github.com/go-git/go-git)
- [Google Generative AI](https://ai.google.dev/)
- [Asynq](https://github.com/hibiken/asynq)

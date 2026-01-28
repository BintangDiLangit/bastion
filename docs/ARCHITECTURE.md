# Architecture Documentation

## Overview

Code Security Auditor is designed as a modular, scalable system following clean architecture principles. The system consists of multiple components that work together to provide comprehensive security scanning capabilities.

## System Architecture

```
                                    ┌──────────────────────────────────────┐
                                    │           External Services          │
                                    ├──────────────────────────────────────┤
                                    │  GitHub  │  GitLab  │  Google AI     │
                                    └────┬─────┴────┬─────┴────┬───────────┘
                                         │          │          │
┌────────────────────────────────────────┼──────────┼──────────┼────────────────┐
│                                        │          │          │                │
│    ┌─────────────────┐                 │          │          │                │
│    │   CLI Client    │                 │          │          │                │
│    └────────┬────────┘                 │          │          │                │
│             │                          │          │          │                │
│    ┌────────▼────────┐    ┌────────────▼──────────▼────┐     │                │
│    │   API Server    │◀──▶│      Webhook Handler       │     │                │
│    │   (Gin HTTP)    │    └────────────────────────────┘     │                │
│    └────────┬────────┘                                       │                │
│             │                                                │                │
│    ┌────────▼────────┐                                       │                │
│    │   Job Queue     │◀──────────────────────────────────────┤                │
│    │   (Asynq)       │                                       │                │
│    └────────┬────────┘                                       │                │
│             │                                                │                │
│    ┌────────▼────────┐    ┌─────────────────┐    ┌──────────▼──────────┐     │
│    │    Workers      │───▶│    Scanner      │───▶│    AI Agent         │     │
│    │  (Background)   │    │    Engine       │    │    (Gemini)         │     │
│    └────────┬────────┘    └────────┬────────┘    └─────────────────────┘     │
│             │                      │                                          │
│             │             ┌────────▼────────┐                                │
│             │             │  Rule Engine    │                                │
│             │             └─────────────────┘                                │
│             │                                                                │
│    ┌────────▼────────┐    ┌─────────────────┐                                │
│    │   Reporter      │───▶│  PDF/HTML/JSON  │                                │
│    │   Generator     │    │  Generation     │                                │
│    └─────────────────┘    └─────────────────┘                                │
│                                                                              │
│    ┌─────────────────────────────────────────────────────────────────┐      │
│    │                      Data Layer                                   │      │
│    ├──────────────────────────┬──────────────────────────────────────┤      │
│    │       PostgreSQL         │              Redis                    │      │
│    │   (Persistent Storage)   │     (Cache, Queue, Sessions)         │      │
│    └──────────────────────────┴──────────────────────────────────────┘      │
│                                                                              │
└──────────────────────────────────────────────────────────────────────────────┘
```

## Components

### 1. API Server (`cmd/api`)

The HTTP API server handles all external requests.

**Responsibilities:**
- REST API endpoints
- Authentication and authorization
- Request validation
- Rate limiting
- Webhook handling

**Key Technologies:**
- Gin web framework
- JWT/API key authentication
- Structured logging

### 2. Background Workers (`cmd/worker`)

Async job processing for long-running tasks.

**Responsibilities:**
- Repository scanning
- Report generation
- Webhook processing
- Cleanup tasks

**Key Technologies:**
- Asynq (Redis-based queue)
- Concurrent workers

### 3. CLI Tool (`cmd/cli`)

Command-line interface for local scanning.

**Responsibilities:**
- Local directory scanning
- CI/CD integration
- Output formatting

**Key Technologies:**
- Cobra CLI framework
- Multiple output formats

### 4. Scanner Engine (`internal/scanner`)

Core scanning functionality.

**Components:**

```
scanner/
├── manager.go      # Orchestration
├── git.go          # Git operations
├── parser.go       # Code parsing
├── analyzer.go     # Static analysis
├── metrics.go      # Code metrics
└── rules/          # Detection rules
    ├── rules.go           # Rule engine
    ├── sql_injection.go   # SQL injection
    ├── xss.go             # XSS detection
    ├── secrets.go         # Secret detection
    └── dependency.go      # Dependency check
```

**Scanning Pipeline:**

```
1. Clone/Access Repository
        │
        ▼
2. Parse Files (AST)
        │
        ▼
3. Apply Rules
        │
        ▼
4. Collect Vulnerabilities
        │
        ▼
5. Calculate Metrics
        │
        ▼
6. Generate Report
```

### 5. AI Agent (`internal/agent`)

Integration with Google Generative AI.

**Capabilities:**
- Vulnerability analysis
- Remediation suggestions
- Code review
- Security summaries

**Components:**
- Client wrapper
- Prompt engineering
- Response parsing
- Custom tools

### 6. Reporter (`internal/reporter`)

Report generation in multiple formats.

**Supported Formats:**
- JSON (machine-readable)
- PDF (executive reports)
- HTML (interactive)
- Markdown (documentation)
- SARIF (IDE integration)

### 7. Data Layer

**PostgreSQL:**
- Repository metadata
- Scan history
- Vulnerabilities
- Reports
- API keys

**Redis:**
- Job queue
- Caching
- Rate limiting
- Session storage
- Real-time progress

## Data Models

### Core Entities

```
┌─────────────────┐     ┌─────────────────┐
│   Repository    │────▶│      Scan       │
└─────────────────┘     └────────┬────────┘
                                 │
                        ┌────────▼────────┐
                        │  Vulnerability  │
                        └────────┬────────┘
                                 │
                        ┌────────▼────────┐
                        │     Report      │
                        └─────────────────┘
```

### Entity Relationships

- **Repository** → has many **Scans**
- **Scan** → has many **Vulnerabilities**
- **Scan** → has many **Reports**
- **Vulnerability** → belongs to **Scan**

## Security Architecture

### Authentication

1. **API Keys**
   - Hashed storage (SHA-256)
   - Scoped permissions
   - Rate limiting per key

2. **Webhook Signatures**
   - HMAC-SHA256 verification
   - Timestamp validation

### Authorization

- Role-based access control (RBAC)
- Scoped API keys
- Resource-level permissions

### Data Protection

- Secrets masked in reports
- Encrypted storage for tokens
- TLS for all communications

## Scalability

### Horizontal Scaling

```
                    ┌──────────────┐
                    │ Load Balancer│
                    └──────┬───────┘
                           │
          ┌────────────────┼────────────────┐
          │                │                │
    ┌─────▼─────┐    ┌─────▼─────┐    ┌─────▼─────┐
    │ API Pod 1 │    │ API Pod 2 │    │ API Pod 3 │
    └───────────┘    └───────────┘    └───────────┘
          │                │                │
          └────────────────┼────────────────┘
                           │
                    ┌──────▼───────┐
                    │    Redis     │
                    │   (Queue)    │
                    └──────┬───────┘
                           │
          ┌────────────────┼────────────────┐
          │                │                │
    ┌─────▼─────┐    ┌─────▼─────┐    ┌─────▼─────┐
    │ Worker 1  │    │ Worker 2  │    │ Worker 3  │
    └───────────┘    └───────────┘    └───────────┘
```

### Performance Optimizations

1. **Caching**
   - Repository metadata
   - Scan results
   - Rule configurations

2. **Parallel Processing**
   - Concurrent file scanning
   - Parallel rule execution
   - Batch database operations

3. **Queue Management**
   - Priority queues
   - Retry mechanisms
   - Dead letter queues

## Deployment Options

### Docker Compose (Development)

```yaml
services:
  api:      # API server
  worker:   # Background workers
  postgres: # Database
  redis:    # Cache/Queue
```

### Kubernetes (Production)

```
k8s/
├── namespace.yaml
├── configmap.yaml
├── secret.yaml
├── api-deployment.yaml
├── worker-deployment.yaml
├── postgres-statefulset.yaml
├── redis-deployment.yaml
├── service.yaml
└── ingress.yaml
```

## Monitoring

### Metrics

- Request latency
- Scan duration
- Queue depth
- Error rates
- Resource utilization

### Logging

- Structured JSON logs
- Request tracing
- Error tracking

### Health Checks

- `/health` - Overall health
- `/health/live` - Liveness probe
- `/health/ready` - Readiness probe

## Extension Points

### Custom Rules

```go
type CustomRule struct {
    *rules.BaseRule
}

func (r *CustomRule) Check(ctx context.Context, file *scanner.ParsedFile) ([]models.Vulnerability, error) {
    // Custom detection logic
}
```

### Custom Report Formats

```go
type CustomReporter interface {
    Generate(data ReportData) (*GeneratedReport, error)
}
```

### Custom Integrations

- Additional Git providers
- Notification channels
- External vulnerability databases

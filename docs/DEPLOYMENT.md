# Deployment Guide

This guide covers the deployment of the Code Security Auditor in production environments.

## Prerequisites

- **Docker** (v20.10+) & **Docker Compose** (v2.0+)
- **PostgreSQL** (v15+) - if running external DB
- **Redis** (v7+) - if running external Redis
- **Google Cloud Project** (for ADK features)

## Installation Steps

### 1. Clone Repository
```bash
git clone https://github.com/your-org/code-security-auditor.git
cd code-security-auditor
```

### 2. Configure Environment
Copy the example environment file:
```bash
cp .env.example .env
```

Edit `.env` and set your secrets:
- `DATABASE_URL`: Connection string for Postgres.
- `REDIS_URL`: Connection string for Redis.
- `ADK_API_KEY`: Your Google GenAI/ADK key.
- `GITHUB_PRIVATE_KEY_PATH`: Path to GitHub PEM file (if using GitHub App).

### 3. Build & Run (Docker Compose)
To start the full stack (API, Worker, DB, Redis):
```bash
docker compose -f deployments/docker/docker-compose.yml up -d --build
```

### 4. Verify Deployment
Check service status:
```bash
docker compose -f deployments/docker/docker-compose.yml ps
```

Check API health:
```bash
curl http://localhost:8080/health
# {"status":"ok","version":"1.0.0"}
```

## Kubernetes Deployment

*(Coming Soon)* - Helm charts are in development.

## Monitoring

### Metrics
The API exposes Prometheus-compatible metrics at `/metrics`:
- `scan_duration_seconds`: Histogram of scan times.
- `http_requests_total`: Counter of API requests.
- `vulnerabilities_detected`: Counter by severity.

### Logging
Logs are structured JSON sent to `stdout`/`stderr`.
Recommended aggregation: ELK Stack, Datadog, or CloudWatch.

## Backup Strategy

### Database
- Perform daily `pg_dump` backups.
- Enable WAL archiving for Point-in-Time Recovery (PITR).

### Configuration
- Backup `.env` and any key files (e.g., GitHub PEM).
- **Do not** backup the `configs/` directory if it contains ephemeral data; strictly config files should be version controlled.

## Maintenance

### Updates
1. Pull latest code.
2. Rebuild images: `docker compose build`.
3. Apply migrations (auto-applied on startup currently).
4. Restart services: `docker compose up -d`.

### Cleanup
The `worker` automatically cleans up temporary git clones.
Manually monitor disk usage of `/tmp` or configured `GIT_TEMP_DIR` volumes.

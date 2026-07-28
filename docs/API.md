# Bastion API

Status: alpha. Five scan endpoints are supported.

Set `CSA_SERVER_API_KEY` (Docker maps `BASTION_API_KEY` to it). Send the exact
value using either:

```http
X-API-Key: your-key
```

or:

```http
Authorization: Bearer your-key
```

## Create scan

```http
POST /api/v1/scans
Content-Type: application/json
```

```json
{
  "repository_url": "https://github.com/owner/repository",
  "branch": "main",
  "commit_sha": "",
  "scan_type": "full"
}
```

Only HTTPS repositories on configured `git.supported_hosts` are accepted.
Embedded URL credentials are rejected. The scan runs asynchronously inside the
API process.

Response: `202 Accepted`

```json
{
  "scan_id": "123e4567-e89b-12d3-a456-426614174000",
  "status": "pending",
  "message": "scan started"
}
```

## Get scan

```http
GET /api/v1/scans/:id
```

Statuses: `pending`, `running`, `completed`, `failed`, `cancelled`.

## List findings

```http
GET /api/v1/scans/:id/vulnerabilities?limit=50&offset=0
```

`limit` is capped at 200. Findings include stable `fingerprint` values.

## Compare scans

```http
GET /api/v1/scans/:id/delta
```

Default baseline: repository's previous completed scan. Explicit baseline:

```http
GET /api/v1/scans/:id/delta?baseline_scan_id=:baseline_id
```

Response groups full findings under `new` and `resolved`; `unchanged` is a
count. Suppressed and false-positive findings do not affect comparison.

## Cancel scan

```http
POST /api/v1/scans/:id/cancel
```

Only pending or running scans can be cancelled.

## Health

```http
GET /health
GET /health/live
GET /health/ready
```

Health endpoints require no API key.

## Run with Docker

```bash
POSTGRES_PASSWORD='replace-me' \
BASTION_API_KEY='replace-with-a-long-random-key' \
docker compose -f deployments/docker/docker-compose.yml up --build
```

Report, webhook, repository-management, and AI endpoints are not exposed until
their implementations meet the same persistence and security guarantees.

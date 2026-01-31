# API Documentation

The Code Security Auditor API provides a comprehensive interface for managing repositories, triggering security scans, and retrieving analysis reports.

## Authentication

All API requests must include the `X-API-Key` header.

```bash
curl -H "X-API-Key: your-api-key" https://api.security-auditor.com/v1/health
```

### Headers

- `Content-Type`: `application/json`
- `X-API-Key`: Required for authentication
- `X-Request-ID`: Optional unique request identifier

## Rate Limiting

The API implements rate limiting to ensure fair usage.
- Limit: 100 requests per minute per API key.
- Response Headers:
    - `X-RateLimit-Limit`: 100
    - `X-RateLimit-Remaining`: 99
    - `X-RateLimit-Reset`: 1678892345

## Endpoints

### Repositories

#### List Repositories
`GET /v1/repositories`

Returns a list of monitored repositories.

**Parameters:**
- `page`: Page number (default: 1)
- `limit`: Items per page (default: 20)

**Response:**
```json
{
  "data": [
    {
      "id": "123e4567-e89b-12d3-a456-426614174000",
      "url": "https://github.com/user/repo",
      "name": "repo",
      "status": "active"
    }
  ],
  "meta": {
    "total": 50,
    "page": 1
  }
}
```

#### Add Repository
`POST /v1/repositories`

**Payload:**
```json
{
  "url": "https://github.com/user/repo",
  "branch": "main" // Optional, defaults to main/master
}
```

### Scans

#### Trigger Scan
`POST /v1/scans`

**Payload:**
```json
{
  "repository_id": "123e4567-e89b-12d3-a456-426614174000",
  "branch": "feature/security-update", // Optional
  "scan_type": "full" // full, quick, diff
}
```

**Response:**
```json
{
  "id": "scan-uuid",
  "status": "queued",
  "queued_at": "2023-10-27T10:00:00Z"
}
```

#### Get Scan Results
`GET /v1/scans/:id`

**Response:**
```json
{
  "id": "scan-uuid",
  "status": "completed",
  "findings_summary": {
    "critical": 1,
    "high": 2,
    "medium": 5,
    "low": 0
  },
  "completed_at": "2023-10-27T10:05:00Z"
}
```

### Vulnerabilities

#### List Vulnerabilities
`GET /v1/vulnerabilities`

**Parameters:**
- `severity`: critical, high, medium, low
- `status`: open, fixed, dismissed
- `repository_id`: Filter by repo

#### Fix Vulnerability with AI
`POST /v1/vulnerabilities/:id/fix`

Request an AI-generated fix for a specific finding.

**Response:**
```json
{
  "suggestion": "Use parameterized query...",
  "code_diff": "diff --git a/main.go b/main.go\n...",
  "explanation": "This change prevents SQL injection..."
}
```

### Webhooks

Configure webhooks to receive real-time updates.

#### Supported Events
- `scan.completed`: Triggered when a scan finishes.
- `scan.failed`: Triggered when a scan fails.
- `finding.detected`: Triggered when a new critical finding is detected.

**Payload Format:**
```json
{
  "event": "scan.completed",
  "payload": {
    "scan_id": "scan-uuid",
    "repository_id": "repo-uuid",
    "status": "completed",
    "summary": { ... }
  },
  "timestamp": "2023-10-27T10:05:00Z"
}
```

## Error Codes

| Code | Description |
|------|-------------|
| 400  | Bad Request - Invalid payload or parameters |
| 401  | Unauthorized - Invalid API Key |
| 403  | Forbidden - Insufficient permissions |
| 404  | Not Found - Resource does not exist |
| 429  | Too Many Requests - Rate limit exceeded |
| 500  | Internal Server Error |

## SDK Examples

### Python

```python
import requests

API_URL = "https://api.security-auditor.com/v1"
HEADERS = {"X-API-Key": "your-key"}

def trigger_scan(repo_id):
    resp = requests.post(f"{API_URL}/scans", json={"repository_id": repo_id}, headers=HEADERS)
    return resp.json()

print(trigger_scan("repo-uuid"))
```

### Go

```go
package main

import (
	"bytes"
	"encoding/json"
	"net/http"
)

func main() {
	client := &http.Client{}
	req, _ := http.NewRequest("POST", "https://api.security-auditor.com/v1/scans", nil)
	req.Header.Set("X-API-Key", "your-key")
	client.Do(req)
}
```

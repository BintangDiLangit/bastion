# API Documentation

## Overview

The Code Security Auditor API provides programmatic access to security scanning functionality. All API endpoints require authentication via API key.

## Base URL

```
http://localhost:8080/api/v1
```

## Authentication

All API requests (except health checks) require authentication via API key:

```bash
# Via X-API-Key header
curl -H "X-API-Key: your-api-key" http://localhost:8080/api/v1/scans

# Via Authorization header
curl -H "Authorization: Bearer your-api-key" http://localhost:8080/api/v1/scans
```

## Rate Limiting

- **Default limit**: 100 requests per minute
- **Burst**: 10 requests

Rate limit headers:
- `X-RateLimit-Limit`: Maximum requests per window
- `X-RateLimit-Remaining`: Remaining requests
- `X-RateLimit-Reset`: Unix timestamp when limit resets

## Endpoints

### Health Check

#### GET /health

Check API health status.

**Response:**
```json
{
  "status": "healthy",
  "version": "1.0.0",
  "uptime": "2h30m",
  "timestamp": "2024-01-15T10:30:00Z",
  "checks": {
    "database": "healthy",
    "redis": "healthy"
  }
}
```

### Repositories

#### POST /api/v1/repositories

Register a new repository for scanning.

**Request:**
```json
{
  "url": "https://github.com/owner/repo",
  "default_branch": "main",
  "private": false,
  "access_token": "optional-access-token"
}
```

**Response:** `201 Created`
```json
{
  "id": "550e8400-e29b-41d4-a716-446655440000",
  "name": "repo",
  "full_name": "owner/repo",
  "url": "https://github.com/owner/repo",
  "provider": "github",
  "default_branch": "main",
  "created_at": "2024-01-15T10:30:00Z"
}
```

#### GET /api/v1/repositories

List all repositories.

**Query Parameters:**
- `limit` (int): Max results (default: 20, max: 100)
- `offset` (int): Pagination offset
- `provider` (string): Filter by provider (github, gitlab)

**Response:** `200 OK`
```json
{
  "data": [...],
  "limit": 20,
  "offset": 0
}
```

#### GET /api/v1/repositories/:id

Get repository details.

#### DELETE /api/v1/repositories/:id

Delete a repository.

#### GET /api/v1/repositories/:id/scans

List scans for a repository.

#### GET /api/v1/repositories/:id/stats

Get repository statistics.

### Scans

#### POST /api/v1/scans

Start a new security scan.

**Request:**
```json
{
  "repository_url": "https://github.com/owner/repo",
  "branch": "main",
  "commit_sha": "abc123",
  "scan_type": "full",
  "options": {
    "rules": ["sql_injection", "xss"],
    "exclude_paths": ["vendor/"]
  }
}
```

**Response:** `202 Accepted`
```json
{
  "scan_id": "550e8400-e29b-41d4-a716-446655440000",
  "status": "pending",
  "message": "Scan queued successfully"
}
```

#### GET /api/v1/scans/:id

Get scan details.

**Response:** `200 OK`
```json
{
  "id": "550e8400-e29b-41d4-a716-446655440000",
  "repository_id": "...",
  "status": "completed",
  "type": "full",
  "branch": "main",
  "commit_sha": "abc123",
  "started_at": "2024-01-15T10:30:00Z",
  "completed_at": "2024-01-15T10:35:00Z",
  "duration_ms": 300000,
  "files_scanned": 150,
  "lines_scanned": 25000
}
```

#### GET /api/v1/scans/:id/progress

Get scan progress (for running scans).

**Response:** `200 OK`
```json
{
  "scan_id": "...",
  "status": "running",
  "phase": "analyzing",
  "progress": 45.5,
  "files_processed": 68,
  "total_files": 150,
  "current_file": "src/api/handlers.go"
}
```

#### POST /api/v1/scans/:id/cancel

Cancel a running scan.

#### GET /api/v1/scans/:id/vulnerabilities

Get vulnerabilities found in a scan.

**Query Parameters:**
- `severity` (string): Filter by severity (critical, high, medium, low, info)
- `category` (string): Filter by category
- `limit` (int): Max results
- `offset` (int): Pagination offset

**Response:** `200 OK`
```json
{
  "data": [
    {
      "id": "...",
      "rule_id": "sql_injection",
      "title": "SQL Injection",
      "description": "...",
      "severity": "critical",
      "category": "injection",
      "file_path": "src/db/queries.go",
      "line_start": 45,
      "line_end": 45,
      "code_snippet": "...",
      "remediation": "...",
      "confidence": 0.85
    }
  ],
  "limit": 50,
  "offset": 0
}
```

#### GET /api/v1/scans/:id/summary

Get scan summary.

**Response:** `200 OK`
```json
{
  "scan_id": "...",
  "total_vulnerabilities": 15,
  "critical": 2,
  "high": 5,
  "medium": 6,
  "low": 2,
  "info": 0,
  "files_scanned": 150,
  "lines_scanned": 25000,
  "duration_ms": 300000
}
```

### Vulnerabilities

#### GET /api/v1/vulnerabilities/:id

Get vulnerability details.

#### PATCH /api/v1/vulnerabilities/:id

Update vulnerability (e.g., mark as false positive).

**Request:**
```json
{
  "false_positive": true,
  "notes": "This is a test file"
}
```

#### POST /api/v1/vulnerabilities/:id/analyze

Analyze vulnerability with AI.

**Response:** `200 OK`
```json
{
  "explanation": "...",
  "risk_assessment": "...",
  "exploit_scenario": "...",
  "recommendations": ["...", "..."],
  "confidence_score": 0.9
}
```

### Reports

#### POST /api/v1/reports

Generate a report.

**Request:**
```json
{
  "scan_id": "550e8400-e29b-41d4-a716-446655440000",
  "format": "pdf",
  "include_ai_analysis": true,
  "send_to_github": false
}
```

**Response:** `202 Accepted`
```json
{
  "report_id": "...",
  "status": "generating",
  "message": "Report generation started"
}
```

#### GET /api/v1/reports/:id

Get report details.

#### GET /api/v1/reports/:id/download

Download report file.

#### GET /api/v1/reports

List reports.

### Rules

#### GET /api/v1/rules

List available security rules.

**Response:** `200 OK`
```json
{
  "data": [
    {
      "id": "sql_injection",
      "name": "SQL Injection",
      "description": "...",
      "severity": "critical",
      "category": "injection",
      "languages": ["go", "python", "javascript"],
      "enabled": true
    }
  ],
  "count": 10
}
```

#### GET /api/v1/rules/:id

Get rule details.

### Webhooks

#### POST /api/v1/webhooks/github

GitHub webhook endpoint for automated scanning.

**Headers:**
- `X-GitHub-Event`: Event type (push, pull_request)
- `X-Hub-Signature-256`: HMAC signature

#### POST /api/v1/webhooks/gitlab

GitLab webhook endpoint.

**Headers:**
- `X-Gitlab-Event`: Event type
- `X-Gitlab-Token`: Webhook token

## Error Responses

All errors return a consistent format:

```json
{
  "error": "Error Type",
  "message": "Human-readable error message",
  "details": "Additional details (optional)"
}
```

### Common Error Codes

| Status Code | Error | Description |
|-------------|-------|-------------|
| 400 | Bad Request | Invalid request body or parameters |
| 401 | Unauthorized | Missing or invalid API key |
| 403 | Forbidden | Insufficient permissions |
| 404 | Not Found | Resource not found |
| 429 | Too Many Requests | Rate limit exceeded |
| 500 | Internal Server Error | Server error |

## Pagination

List endpoints support pagination:

```bash
GET /api/v1/scans?limit=20&offset=40
```

Response includes pagination metadata:

```json
{
  "data": [...],
  "limit": 20,
  "offset": 40
}
```

## Webhooks

### Setting Up GitHub Webhooks

1. Go to your repository settings → Webhooks
2. Add webhook URL: `https://your-server.com/api/v1/webhooks/github`
3. Content type: `application/json`
4. Secret: Your configured webhook secret
5. Events: Push, Pull requests

### Setting Up GitLab Webhooks

1. Go to your project settings → Webhooks
2. URL: `https://your-server.com/api/v1/webhooks/gitlab`
3. Secret token: Your configured webhook token
4. Triggers: Push events, Merge request events

# User Guide

Welcome to the Code Security Auditor! This guide will help you secure your codebase using our automated scanning tools.

## Getting Started

### 1. Account Setup
Currently, user management is handled via the admin console or direct database creation. Ensure you have your `API_KEY` ready.

### 2. Register a Repository
To start scanning, you must register your git repository.

```bash
curl -X POST https://api.security-auditor.com/v1/repositories \
  -H "X-API-Key: YOUR_KEY" \
  -d '{"url":"https://github.com/my-org/my-project"}'
```

## Workflows

### Triggering a Manual Scan
You can trigger a scan at any time, for example before a release.

```bash
# Full Scan
curl -X POST https://api.security-auditor.com/v1/scans \
  -H "X-API-Key: YOUR_KEY" \
  -d '{"repository_id":"REPO_ID", "scan_type":"full"}'
```

### CI/CD Integration
Integrate security scans into your GitHub Actions pipeline.

```yaml
steps:
  - name: Trigger Security Scan
    run: |
      curl -X POST $AUDITOR_URL/v1/scans \
        -H "X-API-Key: ${{ secrets.AUDITOR_KEY }}" \
        -d "{\"repository_id\":\"$REPO_ID\", \"branch\":\"${{ github.ref_name }}\"}"
```

## Understanding Reports

Reports classify findings by severity:

- **🔴 Critical**: Immediate action required (e.g., Hardcoded Keys, SQL Injection).
- **🟠 High**: Fix in next release (e.g., XSS, Logic errors).
- **🟡 Medium**: Schedule a fix (e.g., Weak crypto config).
- **🟢 Low/Info**: Best practices (e.g., TODO comments).

### AI Fix Suggestions
For supported findings, the report will include an AI-generated patch.
Always review AI suggestions before applying them, as they may lack full context of your business logic.

## Managing False Positives

If a finding is incorrect:
1. **Dismiss**: detailed in the UI or via API (`PUT /v1/vulnerabilities/:id/dismiss`).
2. **exclude**: Add the file or pattern to your repository's `.security-ignore` file (planned feature).

## Best Practices

1. **Scan on PR**: Catch issues before they merge to main.
2. **Review Highs**: Don't ignore High severity issues; they often chain into Criticals.
3. **Secret Rotation**: If the scanner finds a secret (API Key, Password), **rotate it immediately**. The secret is compromised simply by being in the git history.
4. **Keep Scanners Updated**: We update rules frequently. Ensure your instance stays current.

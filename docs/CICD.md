# CI/CD Integration Guide

The Code Security Auditor can be integrated into your CI/CD pipelines to ensure every commit and pull request is secure.

## GitHub Actions

We provide a dedicated GitHub Action that runs the scanner in a Docker container.

### Usage

Add the following workflow to your repository at `.github/workflows/security.yml`:

```yaml
name: Security Scan
on: [push, pull_request]

jobs:
  security:
    name: Code Security Auditor
    runs-on: ubuntu-latest
    steps:
      - name: Checkout Code
        uses: actions/checkout@v3

      - name: Run Security Scan
        uses: code-security-auditor/action@v1
        with:
          api-key: ${{ secrets.SECURITY_AUDITOR_API_KEY }}
          fail-on-critical: true
          scan-type: full
```

### Inputs

| Input | Description | Required | Default |
|-------|-------------|----------|---------|
| `api-key` | Your API Key for reporting results. | Yes | - |
| `fail-on-critical` | Fail the build if critical/high issues are found. | No | `true` |
| `scan-type` | Type of scan to perform (`full`, `quick`). | No | `full` |

### Outputs

| Output | Description |
|--------|-------------|
| `report-path` | Path to the generated JSON/SARIF report. |

## GitLab CI

Use our Docker image to run scans in your GitLab CI pipeline.

```yaml
security_scan:
  stage: test
  image: 
    name: code-security-auditor/scanner:latest
    entrypoint: [""]
  script:
    - /bin/scanner-cli scan . --api-key $SECURITY_AUDITOR_API_KEY --fail-on-critical
  rules:
    - if: $CI_MERGE_REQUEST_ID
    - if: $CI_COMMIT_BRANCH == "main"
```

## Jenkins

Integrate using a Docker pipeline agent.

```groovy
pipeline {
    agent {
        docker { image 'code-security-auditor/scanner:latest' }
    }
    stages {
        stage('Security Scan') {
            steps {
                sh '/bin/scanner-cli scan . --api-key $SECURITY_AUDITOR_API_KEY --fail-on-critical'
            }
        }
    }
}
```

## Troubleshooting

### Build Failures
If the build fails with `Exit Code 1`, it means critical or high severity vulnerabilities were detected. Check the console output for details.

### Authentication Errors
Ensure `SECURITY_AUDITOR_API_KEY` is set in your repository's secrets/variables.

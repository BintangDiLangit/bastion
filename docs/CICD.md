# CI integration

Build and run the CLI directly. No API key or hosted service is required.

## GitHub Actions

```yaml
name: Bastion

on:
  pull_request:
  push:
    branches: [main]

permissions:
  contents: read
  security-events: write

jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - name: Check out project
        uses: actions/checkout@v4
        with:
          path: project
      - name: Check out Bastion
        uses: actions/checkout@v4
        with:
          repository: BintangDiLangit/bastion
          path: bastion
          # Pin a release tag or commit for reproducible security checks.
          ref: main
      - uses: actions/setup-go@v5
        with:
          go-version-file: bastion/go.mod
          cache: true
      - name: Build Bastion
        working-directory: bastion
        run: go build -o /tmp/bastion ./cmd/cli
      - name: Scan
        run: /tmp/bastion scan project --format sarif --output bastion.sarif
      - name: Upload SARIF
        if: always()
        uses: github/codeql-action/upload-sarif@v3
        with:
          sarif_file: bastion.sarif
```

Replace `ref: main` with a release tag or commit before relying on this as a
required security check. A release-binary workflow can replace the build once
releases exist.

## GitLab CI

```yaml
bastion:
  image: golang:1.25
  script:
    - git clone --depth 1 https://github.com/BintangDiLangit/bastion.git /tmp/bastion-src
    - go build -C /tmp/bastion-src -o /tmp/bastion ./cmd/cli
    - /tmp/bastion scan . --format json --output bastion.json
  artifacts:
    when: always
    paths: [bastion.json]
```

For reproducible builds, pin the clone to a commit or release tag.

## Exit behavior

`scan` fails when a critical finding exists by default. Use
`--fail-on-critical=false` when CI should publish a report without blocking.

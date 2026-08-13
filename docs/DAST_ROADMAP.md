# Bastion DAST Roadmap

## Status

SAST (static source-code analysis) ships today. DAST — testing a **running**
application at a deployed URL — is a future phase. The seam already exists:
`scanner.TargetLiveURL` is a declared target type whose `ScanTarget` arm returns
`"live-URL (DAST) scanning is not implemented yet"`. Nothing else needs to move
for the engine to drop in.

## Scope (phase 2)

- **Input:** an authenticated live URL per app (staging by default), configured
  as `source: { type: live_url, url, ... }` in `bastion.yaml`.
- **Techniques, in order of delivery:**
  1. Passive hygiene — TLS configuration, security headers, cookie flags.
  2. Authenticated crawl — discover routes behind a session.
  3. Safe active probes — reflected-input checks, unauthenticated-endpoint
     access, obvious misconfigurations.
- **Explicitly out of scope for v1:** destructive tests, load/DoS, business-logic
  exploitation, full fuzzing.

## Architecture plug-in point

```
scanner.ScanTarget(ctx, scanID, Target{Type: TargetLiveURL, URL: ...}, opts)
    └── case TargetLiveURL:  →  internal/scanner/dast.Engine (future)
```

The DAST engine returns the **same** `*scanner.ScanResult` (`Vulnerabilities` +
`Metrics`) that SAST returns, so the report renderer, the CLI `report` command,
and the engagement config all work unchanged. Findings reuse
`models.Vulnerability`, so CWE / CVSS / References already flow into reports.

## Config addition (future)

```yaml
projects:
  - name: avora
    client: "Avora Inc."
    source:
      type: live_url
      url: https://staging.avora.example
      # auth handled by an env-referenced secret, never inline
```

## Rules of engagement (safety)

- Explicit, per-project written authorization and a scope allowlist before any
  live request is sent.
- Staging environment by default; production only with separate sign-off.
- Rate limiting and an audit log of every request issued.
- Secrets (session tokens, API keys) come from environment variables, never the
  config file.

## Milestones

1. `dast.Engine` interface + passive checks (headers / TLS).
2. Authenticated crawl.
3. Safe active probes.
4. Report integration (already shares the renderer — mostly wiring).

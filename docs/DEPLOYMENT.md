# API deployment

The API stores scan history in PostgreSQL and scans public HTTPS repositories.
PostgreSQL is the only dependency.

> The API is alpha software. Scans run inside the API process without container
> isolation. Deploy only in a trusted environment with network and resource
> controls.

## Start

Requirements: Docker with Compose v2.

```bash
git clone https://github.com/BintangDiLangit/bastion.git
cd bastion

POSTGRES_PASSWORD='replace-with-a-database-password' \
BASTION_API_KEY='replace-with-a-long-random-api-key' \
docker compose -f deployments/docker/docker-compose.yml up -d --build
```

Optional host port variables: `BASTION_PORT` and `POSTGRES_PORT`.

## Verify

```bash
curl http://localhost:8080/health/live
curl http://localhost:8080/health/ready
docker compose -f deployments/docker/docker-compose.yml logs api
```

Health endpoints are public. Every `/api/v1` request requires the exact API key
in `X-API-Key` or `Authorization: Bearer`.

## Stop

```bash
docker compose -f deployments/docker/docker-compose.yml down
```

Add `-v` only when you intentionally want to delete the PostgreSQL data.

## Production minimums

- Terminate TLS before the API.
- Keep the PostgreSQL port private; the published port is for local development.
- Set `git.supported_hosts`. An empty allowlist is rejected, not treated as a
  wildcard, and only `https` and `ssh` clone URLs are accepted.
- Set CPU, memory, process, and request limits outside Bastion.
- Back up PostgreSQL and test restoration.
- Rotate the API key as a secret, never commit it.

There is currently no Kubernetes chart, `/metrics` endpoint, background worker,
or automatic backup facility.

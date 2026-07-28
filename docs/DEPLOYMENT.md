# API deployment

The API stores scan history in PostgreSQL and scans public HTTPS repositories.
Redis is included in the current Compose stack but is not part of the scan
execution path.

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

Optional host port variables: `BASTION_PORT`, `POSTGRES_PORT`, and `REDIS_PORT`.

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

Add `-v` only when you intentionally want to delete PostgreSQL and Redis data.

## Production minimums

- Terminate TLS before the API.
- Keep PostgreSQL and Redis ports private; the published ports are for local
  development.
- Restrict outbound Git access to configured supported hosts.
- Set CPU, memory, process, and request limits outside Bastion.
- Back up PostgreSQL and test restoration.
- Rotate the API key as a secret, never commit it.

There is currently no Kubernetes chart, `/metrics` endpoint, distributed
worker, or automatic backup facility.

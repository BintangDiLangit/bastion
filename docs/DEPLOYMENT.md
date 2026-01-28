# Deployment Guide

## Table of Contents

1. [Prerequisites](#prerequisites)
2. [Local Development](#local-development)
3. [Docker Deployment](#docker-deployment)
4. [Kubernetes Deployment](#kubernetes-deployment)
5. [Configuration](#configuration)
6. [Monitoring](#monitoring)
7. [Troubleshooting](#troubleshooting)

## Prerequisites

### Required Services

- **PostgreSQL 14+**: Primary database
- **Redis 7+**: Cache, queue, and session storage
- **Git**: For repository cloning

### Optional Services

- **Google AI API Key**: For AI-powered analysis
- **GitHub Token**: For GitHub integration
- **GitLab Token**: For GitLab integration

## Local Development

### Quick Start

```bash
# Clone the repository
git clone https://github.com/your-org/code-security-auditor.git
cd code-security-auditor

# Run setup script
./scripts/setup.sh

# Start infrastructure
docker-compose -f deployments/docker/docker-compose.yml up -d postgres redis

# Run migrations
make migrate

# Start the API server
make run-api

# In another terminal, start workers
make run-worker
```

### Environment Variables

Create a `.env` file:

```bash
# Database
CSA_DATABASE_HOST=localhost
CSA_DATABASE_PORT=5432
CSA_DATABASE_USER=postgres
CSA_DATABASE_PASSWORD=your-password
CSA_DATABASE_DATABASE=code_security_auditor

# Redis
CSA_REDIS_HOST=localhost
CSA_REDIS_PORT=6379

# Server
CSA_SERVER_PORT=8080
CSA_SERVER_MODE=debug

# AI (optional)
CSA_AGENT_API_KEY=your-google-ai-api-key

# GitHub (optional)
CSA_REPORTER_GITHUB_TOKEN=your-github-token
```

## Docker Deployment

### Using Docker Compose

```bash
# Build and start all services
docker-compose -f deployments/docker/docker-compose.yml up -d

# View logs
docker-compose -f deployments/docker/docker-compose.yml logs -f

# Scale workers
docker-compose -f deployments/docker/docker-compose.yml up -d --scale worker=3

# Stop services
docker-compose -f deployments/docker/docker-compose.yml down
```

### Building Individual Images

```bash
# Build API image
docker build --target api -t csa-api:latest -f deployments/docker/Dockerfile .

# Build worker image
docker build --target worker -t csa-worker:latest -f deployments/docker/Dockerfile .

# Build CLI image
docker build --target cli -t csa-cli:latest -f deployments/docker/Dockerfile .
```

### Running CLI with Docker

```bash
# Scan a local directory
docker run --rm -v $(pwd):/workspace csa-cli:latest scan /workspace

# With custom output
docker run --rm -v $(pwd):/workspace -v $(pwd)/reports:/reports \
  csa-cli:latest scan /workspace --output /reports/results.json
```

## Kubernetes Deployment

### Prerequisites

- Kubernetes cluster (1.25+)
- kubectl configured
- Helm (optional)

### Namespace and Secrets

```bash
# Create namespace
kubectl create namespace csa

# Create secrets
kubectl create secret generic csa-secrets \
  --namespace=csa \
  --from-literal=db-password=your-db-password \
  --from-literal=google-ai-key=your-ai-key \
  --from-literal=github-token=your-github-token
```

### Apply Manifests

```bash
# Create all resources
kubectl apply -f deployments/k8s/

# Check status
kubectl get pods -n csa

# View logs
kubectl logs -n csa -l app=csa-api -f
```

### Example Kubernetes Manifests

**ConfigMap:**
```yaml
apiVersion: v1
kind: ConfigMap
metadata:
  name: csa-config
  namespace: csa
data:
  config.yaml: |
    server:
      host: "0.0.0.0"
      port: 8080
    database:
      host: "postgres-service"
      port: 5432
    redis:
      host: "redis-service"
      port: 6379
```

**Deployment:**
```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: csa-api
  namespace: csa
spec:
  replicas: 3
  selector:
    matchLabels:
      app: csa-api
  template:
    metadata:
      labels:
        app: csa-api
    spec:
      containers:
      - name: api
        image: csa-api:latest
        ports:
        - containerPort: 8080
        envFrom:
        - configMapRef:
            name: csa-env
        - secretRef:
            name: csa-secrets
        resources:
          requests:
            memory: "256Mi"
            cpu: "200m"
          limits:
            memory: "512Mi"
            cpu: "500m"
        livenessProbe:
          httpGet:
            path: /health/live
            port: 8080
          initialDelaySeconds: 10
          periodSeconds: 30
        readinessProbe:
          httpGet:
            path: /health/ready
            port: 8080
          initialDelaySeconds: 5
          periodSeconds: 10
```

**Service:**
```yaml
apiVersion: v1
kind: Service
metadata:
  name: csa-api
  namespace: csa
spec:
  selector:
    app: csa-api
  ports:
  - port: 80
    targetPort: 8080
  type: ClusterIP
```

**Ingress:**
```yaml
apiVersion: networking.k8s.io/v1
kind: Ingress
metadata:
  name: csa-ingress
  namespace: csa
  annotations:
    nginx.ingress.kubernetes.io/rate-limit: "100"
spec:
  rules:
  - host: security.example.com
    http:
      paths:
      - path: /
        pathType: Prefix
        backend:
          service:
            name: csa-api
            port:
              number: 80
```

## Configuration

### Configuration Hierarchy

1. Environment variables (highest priority)
2. Config file
3. Default values

### Key Configuration Options

| Environment Variable | Description | Default |
|---------------------|-------------|---------|
| `CSA_SERVER_PORT` | API server port | 8080 |
| `CSA_SERVER_MODE` | Server mode (debug/release) | release |
| `CSA_DATABASE_HOST` | PostgreSQL host | localhost |
| `CSA_DATABASE_PORT` | PostgreSQL port | 5432 |
| `CSA_REDIS_HOST` | Redis host | localhost |
| `CSA_REDIS_PORT` | Redis port | 6379 |
| `CSA_AGENT_API_KEY` | Google AI API key | - |
| `CSA_SCANNER_TIMEOUT` | Scan timeout | 30m |

### SSL/TLS Configuration

For production, use a reverse proxy (nginx, Traefik) for TLS termination.

```nginx
server {
    listen 443 ssl;
    server_name security.example.com;

    ssl_certificate /etc/ssl/certs/cert.pem;
    ssl_certificate_key /etc/ssl/private/key.pem;

    location / {
        proxy_pass http://localhost:8080;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
    }
}
```

## Monitoring

### Health Endpoints

- `GET /health` - Full health status
- `GET /health/live` - Liveness probe
- `GET /health/ready` - Readiness probe

### Prometheus Metrics

Expose metrics endpoint:

```yaml
server:
  metrics_enabled: true
  metrics_path: /metrics
```

### Logging

Configure JSON logging for production:

```yaml
logger:
  level: info
  format: json
  output: stdout
```

## Troubleshooting

### Common Issues

**Database Connection Failed:**
```bash
# Check PostgreSQL is running
docker-compose ps postgres

# Check connection
PGPASSWORD=postgres psql -h localhost -U postgres -d code_security_auditor
```

**Redis Connection Failed:**
```bash
# Check Redis is running
docker-compose ps redis

# Test connection
redis-cli ping
```

**Scan Timeout:**
- Increase `CSA_SCANNER_TIMEOUT`
- Reduce repository size with `--exclude`
- Scale up workers

**Memory Issues:**
- Increase container memory limits
- Reduce concurrent workers
- Enable swap

### Debug Mode

Enable debug logging:

```bash
export CSA_LOGGER_LEVEL=debug
export CSA_SERVER_MODE=debug
```

### Getting Help

- Check logs: `docker-compose logs -f`
- API health: `curl localhost:8080/health`
- Open an issue on GitHub

# Build stage
FROM golang:1.25-alpine AS builder

# Install build dependencies
RUN apk add --no-cache git ca-certificates tzdata

# Set working directory
WORKDIR /app

# Copy go mod files
COPY go.mod go.sum ./

# Download dependencies
RUN go mod download

# Copy source code
COPY . .

# Build the applications
RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -ldflags="-w -s" -o /bin/api ./cmd/api
RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -ldflags="-w -s" -o /bin/worker ./cmd/worker
RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -ldflags="-w -s" -o /bin/csa ./cmd/cli

# Final stage - API
FROM alpine:3.19 AS api

# Install runtime dependencies
RUN apk add --no-cache ca-certificates tzdata git

# Create non-root user
RUN adduser -D -g '' appuser

# Copy binary
COPY --from=builder /bin/api /usr/local/bin/api

# Copy configs
COPY --from=builder /app/configs /etc/code-security-auditor/

# Create directories
RUN mkdir -p /tmp/code-security-auditor/repos \
    && mkdir -p /tmp/code-security-auditor/reports \
    && chown -R appuser:appuser /tmp/code-security-auditor

# Switch to non-root user
USER appuser

# Set working directory
WORKDIR /app

# Expose port
EXPOSE 8080

# Health check
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD wget --no-verbose --tries=1 --spider http://localhost:8080/health || exit 1

# Run
ENTRYPOINT ["api"]

# Final stage - Worker
FROM alpine:3.19 AS worker

# Install runtime dependencies
RUN apk add --no-cache ca-certificates tzdata git

# Create non-root user
RUN adduser -D -g '' appuser

# Copy binary
COPY --from=builder /bin/worker /usr/local/bin/worker

# Copy configs
COPY --from=builder /app/configs /etc/code-security-auditor/

# Create directories
RUN mkdir -p /tmp/code-security-auditor/repos \
    && mkdir -p /tmp/code-security-auditor/reports \
    && chown -R appuser:appuser /tmp/code-security-auditor

# Switch to non-root user
USER appuser

# Set working directory
WORKDIR /app

# Run
ENTRYPOINT ["worker"]

# Final stage - CLI
FROM alpine:3.19 AS cli

# Install runtime dependencies
RUN apk add --no-cache ca-certificates tzdata git

# Copy binary
COPY --from=builder /bin/csa /usr/local/bin/csa

# Set working directory
WORKDIR /workspace

# Run
ENTRYPOINT ["csa"]
CMD ["--help"]

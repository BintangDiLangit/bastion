# Bastion Makefile

GOCMD=go
GOBUILD=$(GOCMD) build
GOCLEAN=$(GOCMD) clean
GOTEST=$(GOCMD) test
GOMOD=$(GOCMD) mod
GOFMT=$(GOCMD) fmt
GOVET=$(GOCMD) vet

# Binary names
BINARY_API=bin/api
BINARY_CLI=bin/bastion
BINARY_MCP=bin/bastion-mcp

CMD_DIR=./cmd
BIN_DIR=./bin

LDFLAGS=-ldflags "-w -s"
BUILD_FLAGS=-trimpath

.PHONY: all build build-api build-cli build-mcp clean test coverage lint fmt vet deps \
	run-api run-cli scan docker docker-up docker-down docker-logs \
	migrate migrate-create migrate-reset setup tools help

## Default target
all: clean deps lint test build

## Build all binaries
build: build-api build-cli build-mcp

## Build API server
build-api:
	@echo "Building API server..."
	@mkdir -p $(BIN_DIR)
	$(GOBUILD) $(BUILD_FLAGS) $(LDFLAGS) -o $(BINARY_API) $(CMD_DIR)/api

## Build CLI
build-cli:
	@echo "Building CLI..."
	@mkdir -p $(BIN_DIR)
	$(GOBUILD) $(BUILD_FLAGS) $(LDFLAGS) -o $(BINARY_CLI) $(CMD_DIR)/cli

## Build MCP server
build-mcp:
	@echo "Building MCP server..."
	@mkdir -p $(BIN_DIR)
	$(GOBUILD) $(BUILD_FLAGS) $(LDFLAGS) -o $(BINARY_MCP) $(CMD_DIR)/mcp

## Clean build artifacts
clean:
	@echo "Cleaning..."
	$(GOCLEAN)
	rm -rf $(BIN_DIR)

## Run tests
test:
	@echo "Running tests..."
	$(GOTEST) -race -cover ./...

## Run tests with coverage report
coverage:
	@echo "Running tests with coverage..."
	$(GOTEST) -race -coverprofile=coverage.out ./...
	$(GOCMD) tool cover -html=coverage.out -o coverage.html
	@echo "Coverage report generated: coverage.html"

## Run linter
lint:
	@echo "Running linter..."
	@if command -v golangci-lint >/dev/null 2>&1; then \
		golangci-lint run ./...; \
	else \
		echo "golangci-lint not installed. Run: go install github.com/golangci/golangci-lint/cmd/golangci-lint@latest"; \
	fi

## Format code
fmt:
	@echo "Formatting code..."
	$(GOFMT) ./...

## Run go vet
vet:
	@echo "Running go vet..."
	$(GOVET) ./...

## Download dependencies
deps:
	@echo "Downloading dependencies..."
	$(GOMOD) download
	$(GOMOD) tidy

## Run API server
run-api: build-api
	@echo "Running API server..."
	$(BINARY_API)

## Run CLI
run-cli: build-cli
	@echo "Running CLI..."
	$(BINARY_CLI) $(ARGS)

## Scan current directory (shortcut)
scan: build-cli
	$(BINARY_CLI) scan .

## Build Docker images
docker:
	@echo "Building Docker images..."
	docker compose -f deployments/docker/docker-compose.yml build

## Start Docker services
docker-up:
	@echo "Starting Docker services..."
	docker compose -f deployments/docker/docker-compose.yml up -d

## Stop Docker services
docker-down:
	@echo "Stopping Docker services..."
	docker compose -f deployments/docker/docker-compose.yml down

## View Docker logs
docker-logs:
	docker compose -f deployments/docker/docker-compose.yml logs -f

## Run database migrations
migrate:
	@echo "Running migrations..."
	./scripts/migrate.sh up

## Create new migration
migrate-create:
	@echo "Creating migration..."
	./scripts/migrate.sh create $(NAME)

## Reset database
migrate-reset:
	@echo "Resetting database..."
	./scripts/migrate.sh reset

## Setup development environment
setup:
	@echo "Setting up development environment..."
	./scripts/setup.sh

## Install development tools
tools:
	@echo "Installing development tools..."
	go install github.com/golangci/golangci-lint/cmd/golangci-lint@latest

## Show help
help:
	@echo "Bastion - Available targets:"
	@echo ""
	@echo "  Build:"
	@echo "    build         Build all binaries"
	@echo "    build-api     Build API server"
	@echo "    build-cli     Build CLI tool"
	@echo "    build-mcp     Build MCP server"
	@echo "    clean         Remove build artifacts"
	@echo ""
	@echo "  Test & Quality:"
	@echo "    test          Run tests"
	@echo "    coverage      Run tests with coverage report"
	@echo "    lint          Run linter"
	@echo "    fmt           Format code"
	@echo "    vet           Run go vet"
	@echo ""
	@echo "  Run:"
	@echo "    run-api       Run API server"
	@echo "    run-cli       Run CLI (use ARGS=\"...\" for arguments)"
	@echo "    scan          Scan current directory"
	@echo ""
	@echo "  Docker:"
	@echo "    docker        Build Docker images"
	@echo "    docker-up     Start Docker services"
	@echo "    docker-down   Stop Docker services"
	@echo "    docker-logs   View Docker logs"
	@echo ""
	@echo "  Database:"
	@echo "    migrate       Run database migrations"
	@echo "    migrate-create NAME=name  Create new migration"
	@echo "    migrate-reset Reset database"
	@echo ""
	@echo "  Other:"
	@echo "    deps          Download dependencies"
	@echo "    setup         Setup development environment"
	@echo "    tools         Install development tools"
	@echo "    help          Show this help"

# Code Security Auditor Makefile

# Go parameters
GOCMD=go
GOBUILD=$(GOCMD) build
GOCLEAN=$(GOCMD) clean
GOTEST=$(GOCMD) test
GOGET=$(GOCMD) get
GOMOD=$(GOCMD) mod
GOFMT=$(GOCMD) fmt
GOVET=$(GOCMD) vet

# Binary names
BINARY_API=bin/api
BINARY_WORKER=bin/worker
BINARY_CLI=bin/csa

# Directories
CMD_DIR=./cmd
PKG_DIR=./pkg
INTERNAL_DIR=./internal
BIN_DIR=./bin

# Build flags
LDFLAGS=-ldflags "-w -s"
BUILD_FLAGS=-trimpath

# Version
VERSION?=$(shell git describe --tags --always --dirty 2>/dev/null || echo "dev")
BUILD_TIME=$(shell date -u '+%Y-%m-%d_%H:%M:%S')

.PHONY: all build clean test coverage lint fmt vet deps run-api run-worker run-cli docker help

## Default target
all: clean deps lint test build

## Build all binaries
build: build-api build-worker build-cli

## Build API server
build-api:
	@echo "Building API server..."
	@mkdir -p $(BIN_DIR)
	$(GOBUILD) $(BUILD_FLAGS) $(LDFLAGS) -o $(BINARY_API) $(CMD_DIR)/api

## Build worker
build-worker:
	@echo "Building worker..."
	@mkdir -p $(BIN_DIR)
	$(GOBUILD) $(BUILD_FLAGS) $(LDFLAGS) -o $(BINARY_WORKER) $(CMD_DIR)/worker

## Build CLI
build-cli:
	@echo "Building CLI..."
	@mkdir -p $(BIN_DIR)
	$(GOBUILD) $(BUILD_FLAGS) $(LDFLAGS) -o $(BINARY_CLI) $(CMD_DIR)/cli

## Clean build artifacts
clean:
	@echo "Cleaning..."
	$(GOCLEAN)
	rm -rf $(BIN_DIR)

## Run tests
test:
	@echo "Running tests..."
	$(GOTEST) -v -race -cover ./...

## Run tests with coverage report
coverage:
	@echo "Running tests with coverage..."
	$(GOTEST) -v -race -coverprofile=coverage.out ./...
	$(GOCMD) tool cover -html=coverage.out -o coverage.html
	@echo "Coverage report generated: coverage.html"

## Run linter
lint:
	@echo "Running linter..."
	@if command -v golangci-lint &> /dev/null; then \
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

## Run worker
run-worker: build-worker
	@echo "Running worker..."
	$(BINARY_WORKER)

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
	docker-compose -f deployments/docker/docker-compose.yml build

## Start Docker services
docker-up:
	@echo "Starting Docker services..."
	docker-compose -f deployments/docker/docker-compose.yml up -d

## Stop Docker services
docker-down:
	@echo "Stopping Docker services..."
	docker-compose -f deployments/docker/docker-compose.yml down

## View Docker logs
docker-logs:
	docker-compose -f deployments/docker/docker-compose.yml logs -f

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

## Generate mocks for testing
mocks:
	@echo "Generating mocks..."
	@if command -v mockgen &> /dev/null; then \
		go generate ./...; \
	else \
		echo "mockgen not installed. Run: go install github.com/golang/mock/mockgen@latest"; \
	fi

## Install development tools
tools:
	@echo "Installing development tools..."
	go install github.com/golangci/golangci-lint/cmd/golangci-lint@latest
	go install github.com/golang/mock/mockgen@latest

## Show help
help:
	@echo "Code Security Auditor - Available targets:"
	@echo ""
	@echo "  Build:"
	@echo "    build         Build all binaries"
	@echo "    build-api     Build API server"
	@echo "    build-worker  Build background worker"
	@echo "    build-cli     Build CLI tool"
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
	@echo "    run-worker    Run background worker"
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

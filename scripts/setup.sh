#!/bin/bash

# Code Security Auditor Setup Script
# This script sets up the development environment

set -e

echo "🔧 Setting up Code Security Auditor..."

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Check Go version
check_go() {
    if ! command -v go &> /dev/null; then
        echo -e "${RED}Error: Go is not installed${NC}"
        echo "Please install Go 1.21 or later from https://golang.org/dl/"
        exit 1
    fi

    GO_VERSION=$(go version | awk '{print $3}' | sed 's/go//')
    echo -e "${GREEN}✓ Go version: $GO_VERSION${NC}"
}

# Check Docker
check_docker() {
    if ! command -v docker &> /dev/null; then
        echo -e "${YELLOW}Warning: Docker is not installed${NC}"
        echo "Docker is optional but recommended for running PostgreSQL and Redis"
    else
        echo -e "${GREEN}✓ Docker is available${NC}"
    fi
}

# Check Docker Compose
check_docker_compose() {
    if ! command -v docker-compose &> /dev/null && ! docker compose version &> /dev/null; then
        echo -e "${YELLOW}Warning: Docker Compose is not installed${NC}"
    else
        echo -e "${GREEN}✓ Docker Compose is available${NC}"
    fi
}

# Install Go dependencies
install_deps() {
    echo "📦 Installing Go dependencies..."
    go mod download
    go mod tidy
    echo -e "${GREEN}✓ Dependencies installed${NC}"
}

# Setup configuration
setup_config() {
    if [ ! -f "configs/config.yaml" ]; then
        echo "📝 Creating configuration file..."
        cp configs/config.yaml.example configs/config.yaml 2>/dev/null || cp configs/config.yaml configs/config.yaml
        echo -e "${YELLOW}! Please edit configs/config.yaml with your settings${NC}"
    else
        echo -e "${GREEN}✓ Configuration file exists${NC}"
    fi
}

# Setup environment file
setup_env() {
    if [ ! -f ".env" ]; then
        echo "📝 Creating .env file..."
        cat > .env << EOF
# Database
CSA_DATABASE_HOST=localhost
CSA_DATABASE_PORT=5432
CSA_DATABASE_USER=postgres
CSA_DATABASE_PASSWORD=postgres
CSA_DATABASE_DATABASE=code_security_auditor

# Redis
CSA_REDIS_HOST=localhost
CSA_REDIS_PORT=6379

# Google AI (for AI-powered analysis)
CSA_AGENT_API_KEY=

# GitHub (for PR integration)
CSA_REPORTER_GITHUB_TOKEN=

# Server
CSA_SERVER_PORT=8080
CSA_SERVER_MODE=debug
EOF
        echo -e "${YELLOW}! Please edit .env with your settings${NC}"
    else
        echo -e "${GREEN}✓ .env file exists${NC}"
    fi
}

# Create required directories
create_dirs() {
    echo "📁 Creating directories..."
    mkdir -p /tmp/code-security-auditor/repos
    mkdir -p /tmp/code-security-auditor/reports
    mkdir -p logs
    echo -e "${GREEN}✓ Directories created${NC}"
}

# Start infrastructure with Docker
start_infra() {
    if command -v docker &> /dev/null; then
        read -p "Start PostgreSQL and Redis with Docker? (y/n) " -n 1 -r
        echo
        if [[ $REPLY =~ ^[Yy]$ ]]; then
            echo "🐳 Starting Docker containers..."
            docker-compose -f deployments/docker/docker-compose.yml up -d postgres redis
            echo -e "${GREEN}✓ Infrastructure started${NC}"
            echo "Waiting for services to be ready..."
            sleep 5
        fi
    fi
}

# Run database migrations
run_migrations() {
    echo "🗄️ Running database migrations..."
    # Migrations are run automatically on app start
    echo -e "${GREEN}✓ Migrations will run on application start${NC}"
}

# Build the application
build_app() {
    echo "🔨 Building application..."
    make build 2>/dev/null || go build -o bin/csa ./cmd/cli
    echo -e "${GREEN}✓ Application built${NC}"
}

# Print completion message
print_complete() {
    echo ""
    echo -e "${GREEN}✅ Setup complete!${NC}"
    echo ""
    echo "Next steps:"
    echo "  1. Edit configs/config.yaml with your settings"
    echo "  2. Edit .env with your environment variables"
    echo "  3. Start the infrastructure: docker-compose up -d"
    echo "  4. Run the API server: make run-api"
    echo "  5. Or use the CLI: ./bin/csa scan /path/to/code"
    echo ""
    echo "For more information, see README.md"
}

# Main
main() {
    check_go
    check_docker
    check_docker_compose
    install_deps
    setup_config
    setup_env
    create_dirs
    start_infra
    run_migrations
    build_app
    print_complete
}

main "$@"

#!/bin/bash

# Database Migration Script
# Usage: ./scripts/migrate.sh [up|down|status|create name]

set -e

# Load environment variables
if [ -f .env ]; then
    export $(cat .env | grep -v '^#' | xargs)
fi

# Default values
DB_HOST=${CSA_DATABASE_HOST:-localhost}
DB_PORT=${CSA_DATABASE_PORT:-5432}
DB_USER=${CSA_DATABASE_USER:-postgres}
DB_PASSWORD=${CSA_DATABASE_PASSWORD:-postgres}
DB_NAME=${CSA_DATABASE_DATABASE:-code_security_auditor}

MIGRATIONS_DIR="internal/database/migrations"

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

# Check if psql is available
check_psql() {
    if ! command -v psql &> /dev/null; then
        echo -e "${RED}Error: psql is not installed${NC}"
        echo "Please install PostgreSQL client"
        exit 1
    fi
}

# Run SQL file
run_sql_file() {
    local file=$1
    PGPASSWORD=$DB_PASSWORD psql -h $DB_HOST -p $DB_PORT -U $DB_USER -d $DB_NAME -f "$file"
}

# Run SQL command
run_sql() {
    local sql=$1
    PGPASSWORD=$DB_PASSWORD psql -h $DB_HOST -p $DB_PORT -U $DB_USER -d $DB_NAME -c "$sql"
}

# Create migrations table if not exists
create_migrations_table() {
    run_sql "CREATE TABLE IF NOT EXISTS schema_migrations (
        version VARCHAR(255) PRIMARY KEY,
        applied_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
    );"
}

# Get applied migrations
get_applied_migrations() {
    PGPASSWORD=$DB_PASSWORD psql -h $DB_HOST -p $DB_PORT -U $DB_USER -d $DB_NAME -t -c \
        "SELECT version FROM schema_migrations ORDER BY version;" 2>/dev/null | tr -d ' '
}

# Run migrations up
migrate_up() {
    echo "Running migrations..."
    create_migrations_table

    applied=$(get_applied_migrations)

    for file in $(ls $MIGRATIONS_DIR/*.sql 2>/dev/null | sort); do
        version=$(basename "$file")
        
        if echo "$applied" | grep -q "^${version}$"; then
            echo -e "${YELLOW}Skipping $version (already applied)${NC}"
            continue
        fi

        echo -e "${GREEN}Applying $version...${NC}"
        run_sql_file "$file"
        run_sql "INSERT INTO schema_migrations (version) VALUES ('$version');"
        echo -e "${GREEN}✓ Applied $version${NC}"
    done

    echo -e "${GREEN}✅ Migrations complete${NC}"
}

# Show migration status
migrate_status() {
    echo "Migration Status:"
    echo "================="
    
    create_migrations_table
    applied=$(get_applied_migrations)

    for file in $(ls $MIGRATIONS_DIR/*.sql 2>/dev/null | sort); do
        version=$(basename "$file")
        
        if echo "$applied" | grep -q "^${version}$"; then
            echo -e "${GREEN}[✓] $version${NC}"
        else
            echo -e "${YELLOW}[ ] $version${NC}"
        fi
    done
}

# Create new migration
create_migration() {
    local name=$1
    if [ -z "$name" ]; then
        echo -e "${RED}Error: Migration name required${NC}"
        echo "Usage: ./migrate.sh create <name>"
        exit 1
    fi

    # Generate timestamp
    timestamp=$(date +%Y%m%d%H%M%S)
    filename="${timestamp}_${name}.sql"
    filepath="$MIGRATIONS_DIR/$filename"

    cat > "$filepath" << EOF
-- Migration: $name
-- Created: $(date -u +"%Y-%m-%d %H:%M:%S UTC")

-- Write your SQL migration here

-- Example:
-- CREATE TABLE IF NOT EXISTS example (
--     id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
--     name VARCHAR(255) NOT NULL,
--     created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
-- );
EOF

    echo -e "${GREEN}Created migration: $filepath${NC}"
}

# Reset database (drop and recreate)
migrate_reset() {
    echo -e "${YELLOW}⚠️  This will drop the database and recreate it!${NC}"
    read -p "Are you sure? (y/n) " -n 1 -r
    echo
    if [[ ! $REPLY =~ ^[Yy]$ ]]; then
        echo "Cancelled"
        exit 0
    fi

    echo "Dropping database..."
    PGPASSWORD=$DB_PASSWORD psql -h $DB_HOST -p $DB_PORT -U $DB_USER -c "DROP DATABASE IF EXISTS $DB_NAME;"
    
    echo "Creating database..."
    PGPASSWORD=$DB_PASSWORD psql -h $DB_HOST -p $DB_PORT -U $DB_USER -c "CREATE DATABASE $DB_NAME;"
    
    echo "Running migrations..."
    migrate_up
}

# Main
main() {
    check_psql

    case "${1:-up}" in
        up)
            migrate_up
            ;;
        down)
            echo -e "${YELLOW}Down migrations not implemented. Use reset instead.${NC}"
            ;;
        status)
            migrate_status
            ;;
        create)
            create_migration "$2"
            ;;
        reset)
            migrate_reset
            ;;
        *)
            echo "Usage: $0 [up|down|status|create <name>|reset]"
            exit 1
            ;;
    esac
}

main "$@"

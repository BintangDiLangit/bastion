-- Initial database schema for Code Security Auditor
-- Version: 1.0.0
-- Author: Code Security Auditor Team

-- Enable required extensions
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";
CREATE EXTENSION IF NOT EXISTS "pgcrypto";

-- ============================================================================
-- REPOSITORIES TABLE
-- Stores information about registered Git repositories
-- ============================================================================
CREATE TABLE IF NOT EXISTS repositories (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name VARCHAR(255) NOT NULL,
    url TEXT NOT NULL,
    owner VARCHAR(255),
    default_branch VARCHAR(100) DEFAULT 'main',
    last_scanned_at TIMESTAMP WITH TIME ZONE,
    is_active BOOLEAN DEFAULT true,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    
    -- Additional fields for comprehensive repository management
    full_name VARCHAR(512) NOT NULL,
    clone_url TEXT NOT NULL,
    provider VARCHAR(50) NOT NULL DEFAULT 'github', -- github, gitlab, bitbucket
    private BOOLEAN NOT NULL DEFAULT false,
    description TEXT,
    language VARCHAR(100),
    
    -- Webhook configuration
    webhook_id VARCHAR(255),
    webhook_secret VARCHAR(255),
    
    -- Settings and metadata
    settings JSONB NOT NULL DEFAULT '{}',
    last_scan_id UUID,
    total_scans INTEGER NOT NULL DEFAULT 0,
    
    -- Constraints
    CONSTRAINT repositories_url_unique UNIQUE (url),
    CONSTRAINT repositories_full_name_unique UNIQUE (full_name)
);

-- ============================================================================
-- SCANS TABLE
-- Stores information about security scans performed on repositories
-- ============================================================================
CREATE TABLE IF NOT EXISTS scans (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    repository_id UUID NOT NULL REFERENCES repositories(id) ON DELETE CASCADE,
    commit_sha VARCHAR(40) NOT NULL,
    branch VARCHAR(255),
    status VARCHAR(50) NOT NULL DEFAULT 'pending', -- pending, running, completed, failed, cancelled
    triggered_by VARCHAR(100), -- webhook, manual, scheduled, pr
    started_at TIMESTAMP WITH TIME ZONE,
    completed_at TIMESTAMP WITH TIME ZONE,
    total_files_scanned INT DEFAULT 0,
    total_vulnerabilities INT DEFAULT 0,
    critical_count INT DEFAULT 0,
    high_count INT DEFAULT 0,
    medium_count INT DEFAULT 0,
    low_count INT DEFAULT 0,
    error_message TEXT,
    metadata JSONB NOT NULL DEFAULT '{}',
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    
    -- Additional scan information
    type VARCHAR(50) NOT NULL DEFAULT 'full', -- full, incremental, pr
    pr_number INTEGER,
    duration_ms BIGINT,
    lines_scanned INTEGER NOT NULL DEFAULT 0,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    
    -- Analysis results
    code_quality_score DECIMAL(5,2),
    security_score DECIMAL(5,2),
    agent_summary TEXT,
    agent_analysis JSONB
);

-- ============================================================================
-- VULNERABILITIES TABLE
-- Stores detected security vulnerabilities
-- ============================================================================
CREATE TABLE IF NOT EXISTS vulnerabilities (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    scan_id UUID NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
    rule_id VARCHAR(100) NOT NULL,
    severity VARCHAR(20) NOT NULL, -- critical, high, medium, low, info
    category VARCHAR(100), -- sql_injection, xss, secrets, dependency, etc.
    file_path TEXT NOT NULL,
    line_number INT,
    column_number INT,
    code_snippet TEXT,
    description TEXT NOT NULL,
    recommendation TEXT,
    cwe_id VARCHAR(20),
    cvss_score DECIMAL(3,1),
    is_false_positive BOOLEAN DEFAULT false,
    agent_analysis JSONB, -- ADK analysis result
    fixed_at TIMESTAMP WITH TIME ZONE,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    
    -- Extended vulnerability information
    title VARCHAR(500) NOT NULL,
    line_start INTEGER NOT NULL,
    line_end INTEGER NOT NULL,
    column_start INTEGER,
    column_end INTEGER,
    remediation TEXT,
    reference_data JSONB NOT NULL DEFAULT '[]',
    metadata JSONB NOT NULL DEFAULT '{}',
    confidence DECIMAL(3,2) NOT NULL DEFAULT 0.80,
    suppressed BOOLEAN NOT NULL DEFAULT false,
    suppressed_by VARCHAR(255),
    suppressed_at TIMESTAMP WITH TIME ZONE,
    suppression_reason TEXT
);

-- ============================================================================
-- CODE PATTERNS TABLE
-- Stores detected code patterns for machine learning and trend analysis
-- ============================================================================
CREATE TABLE IF NOT EXISTS code_patterns (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    repository_id UUID REFERENCES repositories(id) ON DELETE CASCADE,
    pattern_type VARCHAR(100) NOT NULL,
    pattern_data JSONB NOT NULL,
    frequency INT DEFAULT 1,
    last_seen_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    
    -- Pattern classification
    language VARCHAR(50),
    category VARCHAR(100),
    risk_level VARCHAR(20), -- low, medium, high
    is_security_relevant BOOLEAN DEFAULT false
);

-- ============================================================================
-- SCAN REPORTS TABLE
-- Stores generated scan reports
-- ============================================================================
CREATE TABLE IF NOT EXISTS scan_reports (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    scan_id UUID NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
    repository_id UUID NOT NULL REFERENCES repositories(id) ON DELETE CASCADE,
    report_type VARCHAR(50) NOT NULL, -- pdf, json, html, sarif, markdown
    file_path TEXT,
    file_size BIGINT NOT NULL DEFAULT 0,
    generated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    
    -- Report metadata
    status VARCHAR(20) NOT NULL DEFAULT 'pending', -- pending, generating, completed, failed
    summary JSONB NOT NULL DEFAULT '{}',
    expires_at TIMESTAMP WITH TIME ZONE,
    download_count INTEGER NOT NULL DEFAULT 0,
    last_downloaded_at TIMESTAMP WITH TIME ZONE,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

-- ============================================================================
-- WEBHOOK EVENTS TABLE
-- Stores incoming webhook events for audit and retry purposes
-- ============================================================================
CREATE TABLE IF NOT EXISTS webhook_events (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    source VARCHAR(50) NOT NULL, -- github, gitlab, bitbucket
    event_type VARCHAR(100) NOT NULL,
    repository_url TEXT,
    payload JSONB NOT NULL,
    processed BOOLEAN DEFAULT false,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    
    -- Processing information
    repository_id UUID REFERENCES repositories(id) ON DELETE SET NULL,
    processed_at TIMESTAMP WITH TIME ZONE,
    error_message TEXT,
    retry_count INTEGER NOT NULL DEFAULT 0,
    next_retry_at TIMESTAMP WITH TIME ZONE
);

-- ============================================================================
-- API KEYS TABLE
-- Stores API keys for authentication
-- ============================================================================
CREATE TABLE IF NOT EXISTS api_keys (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name VARCHAR(255) NOT NULL,
    key_hash VARCHAR(64) NOT NULL UNIQUE,
    prefix VARCHAR(8) NOT NULL,
    scopes TEXT[] NOT NULL DEFAULT '{}',
    rate_limit INTEGER NOT NULL DEFAULT 1000, -- requests per hour
    expires_at TIMESTAMP WITH TIME ZONE,
    last_used_at TIMESTAMP WITH TIME ZONE,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    revoked_at TIMESTAMP WITH TIME ZONE,
    
    -- Key owner information
    owner_id VARCHAR(255),
    owner_type VARCHAR(50), -- user, service, integration
    description TEXT,
    metadata JSONB NOT NULL DEFAULT '{}'
);

-- ============================================================================
-- USERS TABLE (optional, for multi-user support)
-- ============================================================================
CREATE TABLE IF NOT EXISTS users (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    email VARCHAR(255) NOT NULL UNIQUE,
    name VARCHAR(255),
    avatar_url TEXT,
    provider VARCHAR(50) NOT NULL DEFAULT 'github', -- github, gitlab, email
    provider_id VARCHAR(255),
    role VARCHAR(50) NOT NULL DEFAULT 'user', -- admin, user, readonly
    settings JSONB NOT NULL DEFAULT '{}',
    last_login_at TIMESTAMP WITH TIME ZONE,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

-- ============================================================================
-- REPOSITORY ACCESS TABLE
-- Stores user access to repositories
-- ============================================================================
CREATE TABLE IF NOT EXISTS repository_access (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    repository_id UUID NOT NULL REFERENCES repositories(id) ON DELETE CASCADE,
    role VARCHAR(50) NOT NULL DEFAULT 'viewer', -- admin, maintainer, viewer
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    
    CONSTRAINT repository_access_unique UNIQUE (user_id, repository_id)
);

-- ============================================================================
-- SCAN SCHEDULES TABLE
-- Stores scheduled scan configurations
-- ============================================================================
CREATE TABLE IF NOT EXISTS scan_schedules (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    repository_id UUID NOT NULL REFERENCES repositories(id) ON DELETE CASCADE,
    cron_expression VARCHAR(100) NOT NULL,
    branch VARCHAR(255) DEFAULT 'main',
    enabled BOOLEAN NOT NULL DEFAULT true,
    last_run_at TIMESTAMP WITH TIME ZONE,
    next_run_at TIMESTAMP WITH TIME ZONE,
    scan_options JSONB NOT NULL DEFAULT '{}',
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

-- ============================================================================
-- NOTIFICATIONS TABLE
-- Stores notification configurations and history
-- ============================================================================
CREATE TABLE IF NOT EXISTS notifications (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    repository_id UUID REFERENCES repositories(id) ON DELETE CASCADE,
    type VARCHAR(50) NOT NULL, -- email, slack, webhook, github_pr
    destination TEXT NOT NULL, -- email address, webhook URL, channel
    trigger_on VARCHAR(50)[] NOT NULL DEFAULT '{scan_completed}',
    min_severity VARCHAR(20) DEFAULT 'medium',
    enabled BOOLEAN NOT NULL DEFAULT true,
    settings JSONB NOT NULL DEFAULT '{}',
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

-- ============================================================================
-- NOTIFICATION HISTORY TABLE
-- ============================================================================
CREATE TABLE IF NOT EXISTS notification_history (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    notification_id UUID NOT NULL REFERENCES notifications(id) ON DELETE CASCADE,
    scan_id UUID REFERENCES scans(id) ON DELETE SET NULL,
    status VARCHAR(20) NOT NULL, -- sent, failed, pending
    payload JSONB,
    error_message TEXT,
    sent_at TIMESTAMP WITH TIME ZONE,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

-- ============================================================================
-- SUPPRESSION RULES TABLE
-- Stores rules for suppressing specific vulnerabilities
-- ============================================================================
CREATE TABLE IF NOT EXISTS suppression_rules (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    repository_id UUID REFERENCES repositories(id) ON DELETE CASCADE,
    rule_id VARCHAR(100),
    file_pattern TEXT,
    reason TEXT NOT NULL,
    expires_at TIMESTAMP WITH TIME ZONE,
    created_by VARCHAR(255),
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    
    -- Scope of suppression
    severity VARCHAR(20),
    category VARCHAR(100),
    is_global BOOLEAN NOT NULL DEFAULT false
);

-- ============================================================================
-- INDEXES
-- ============================================================================

-- Repositories indexes
CREATE INDEX IF NOT EXISTS idx_repositories_provider ON repositories(provider);
CREATE INDEX IF NOT EXISTS idx_repositories_full_name ON repositories(full_name);
CREATE INDEX IF NOT EXISTS idx_repositories_last_scanned_at ON repositories(last_scanned_at);
CREATE INDEX IF NOT EXISTS idx_repositories_is_active ON repositories(is_active);
CREATE INDEX IF NOT EXISTS idx_repositories_owner ON repositories(owner);

-- Scans indexes
CREATE INDEX IF NOT EXISTS idx_scans_repository_id ON scans(repository_id);
CREATE INDEX IF NOT EXISTS idx_scans_status ON scans(status);
CREATE INDEX IF NOT EXISTS idx_scans_created_at ON scans(created_at DESC);
CREATE INDEX IF NOT EXISTS idx_scans_branch ON scans(branch);
CREATE INDEX IF NOT EXISTS idx_scans_commit_sha ON scans(commit_sha);
CREATE INDEX IF NOT EXISTS idx_scans_triggered_by ON scans(triggered_by);
CREATE INDEX IF NOT EXISTS idx_scans_repo_status ON scans(repository_id, status);

-- Vulnerabilities indexes
CREATE INDEX IF NOT EXISTS idx_vulnerabilities_scan_id ON vulnerabilities(scan_id);
CREATE INDEX IF NOT EXISTS idx_vulnerabilities_severity ON vulnerabilities(severity);
CREATE INDEX IF NOT EXISTS idx_vulnerabilities_category ON vulnerabilities(category);
CREATE INDEX IF NOT EXISTS idx_vulnerabilities_rule_id ON vulnerabilities(rule_id);
CREATE INDEX IF NOT EXISTS idx_vulnerabilities_file_path ON vulnerabilities(file_path);
CREATE INDEX IF NOT EXISTS idx_vulnerabilities_is_false_positive ON vulnerabilities(is_false_positive);
CREATE INDEX IF NOT EXISTS idx_vulnerabilities_suppressed ON vulnerabilities(suppressed);
CREATE INDEX IF NOT EXISTS idx_vulnerabilities_cwe_id ON vulnerabilities(cwe_id);

-- Reports indexes
CREATE INDEX IF NOT EXISTS idx_scan_reports_scan_id ON scan_reports(scan_id);
CREATE INDEX IF NOT EXISTS idx_scan_reports_repository_id ON scan_reports(repository_id);
CREATE INDEX IF NOT EXISTS idx_scan_reports_status ON scan_reports(status);
CREATE INDEX IF NOT EXISTS idx_scan_reports_report_type ON scan_reports(report_type);

-- API Keys indexes
CREATE INDEX IF NOT EXISTS idx_api_keys_prefix ON api_keys(prefix);
CREATE INDEX IF NOT EXISTS idx_api_keys_key_hash ON api_keys(key_hash);
CREATE INDEX IF NOT EXISTS idx_api_keys_owner_id ON api_keys(owner_id);

-- Webhook events indexes
CREATE INDEX IF NOT EXISTS idx_webhook_events_repository_id ON webhook_events(repository_id);
CREATE INDEX IF NOT EXISTS idx_webhook_events_processed ON webhook_events(processed);
CREATE INDEX IF NOT EXISTS idx_webhook_events_created_at ON webhook_events(created_at DESC);
CREATE INDEX IF NOT EXISTS idx_webhook_events_source ON webhook_events(source);

-- Code patterns indexes
CREATE INDEX IF NOT EXISTS idx_code_patterns_repository_id ON code_patterns(repository_id);
CREATE INDEX IF NOT EXISTS idx_code_patterns_pattern_type ON code_patterns(pattern_type);
CREATE INDEX IF NOT EXISTS idx_code_patterns_language ON code_patterns(language);

-- Users indexes
CREATE INDEX IF NOT EXISTS idx_users_email ON users(email);
CREATE INDEX IF NOT EXISTS idx_users_provider ON users(provider);

-- Scan schedules indexes
CREATE INDEX IF NOT EXISTS idx_scan_schedules_repository_id ON scan_schedules(repository_id);
CREATE INDEX IF NOT EXISTS idx_scan_schedules_next_run_at ON scan_schedules(next_run_at) WHERE enabled = true;

-- Notifications indexes
CREATE INDEX IF NOT EXISTS idx_notifications_repository_id ON notifications(repository_id);
CREATE INDEX IF NOT EXISTS idx_notifications_type ON notifications(type);

-- Suppression rules indexes
CREATE INDEX IF NOT EXISTS idx_suppression_rules_repository_id ON suppression_rules(repository_id);
CREATE INDEX IF NOT EXISTS idx_suppression_rules_rule_id ON suppression_rules(rule_id);

-- ============================================================================
-- TRIGGERS
-- ============================================================================

-- Function to update updated_at timestamp
CREATE OR REPLACE FUNCTION update_updated_at_column()
RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at = CURRENT_TIMESTAMP;
    RETURN NEW;
END;
$$ language 'plpgsql';

-- Apply triggers to tables with updated_at
DROP TRIGGER IF EXISTS update_repositories_updated_at ON repositories;
CREATE TRIGGER update_repositories_updated_at
    BEFORE UPDATE ON repositories
    FOR EACH ROW
    EXECUTE FUNCTION update_updated_at_column();

DROP TRIGGER IF EXISTS update_scans_updated_at ON scans;
CREATE TRIGGER update_scans_updated_at
    BEFORE UPDATE ON scans
    FOR EACH ROW
    EXECUTE FUNCTION update_updated_at_column();

DROP TRIGGER IF EXISTS update_users_updated_at ON users;
CREATE TRIGGER update_users_updated_at
    BEFORE UPDATE ON users
    FOR EACH ROW
    EXECUTE FUNCTION update_updated_at_column();

DROP TRIGGER IF EXISTS update_scan_schedules_updated_at ON scan_schedules;
CREATE TRIGGER update_scan_schedules_updated_at
    BEFORE UPDATE ON scan_schedules
    FOR EACH ROW
    EXECUTE FUNCTION update_updated_at_column();

DROP TRIGGER IF EXISTS update_notifications_updated_at ON notifications;
CREATE TRIGGER update_notifications_updated_at
    BEFORE UPDATE ON notifications
    FOR EACH ROW
    EXECUTE FUNCTION update_updated_at_column();

-- Function to update repository scan counts
CREATE OR REPLACE FUNCTION update_repository_scan_stats()
RETURNS TRIGGER AS $$
BEGIN
    IF TG_OP = 'INSERT' THEN
        UPDATE repositories
        SET total_scans = total_scans + 1,
            last_scan_id = NEW.id,
            last_scanned_at = COALESCE(NEW.completed_at, NEW.created_at)
        WHERE id = NEW.repository_id;
    ELSIF TG_OP = 'UPDATE' AND NEW.status = 'completed' AND OLD.status != 'completed' THEN
        UPDATE repositories
        SET last_scanned_at = NEW.completed_at
        WHERE id = NEW.repository_id;
    END IF;
    RETURN NEW;
END;
$$ language 'plpgsql';

DROP TRIGGER IF EXISTS update_repository_scan_stats ON scans;
CREATE TRIGGER update_repository_scan_stats
    AFTER INSERT OR UPDATE ON scans
    FOR EACH ROW
    EXECUTE FUNCTION update_repository_scan_stats();

-- Function to update vulnerability counts on scan
CREATE OR REPLACE FUNCTION update_scan_vulnerability_counts()
RETURNS TRIGGER AS $$
BEGIN
    IF TG_OP = 'INSERT' THEN
        UPDATE scans
        SET total_vulnerabilities = total_vulnerabilities + 1,
            critical_count = critical_count + CASE WHEN NEW.severity = 'critical' THEN 1 ELSE 0 END,
            high_count = high_count + CASE WHEN NEW.severity = 'high' THEN 1 ELSE 0 END,
            medium_count = medium_count + CASE WHEN NEW.severity = 'medium' THEN 1 ELSE 0 END,
            low_count = low_count + CASE WHEN NEW.severity = 'low' THEN 1 ELSE 0 END
        WHERE id = NEW.scan_id;
    ELSIF TG_OP = 'DELETE' THEN
        UPDATE scans
        SET total_vulnerabilities = total_vulnerabilities - 1,
            critical_count = critical_count - CASE WHEN OLD.severity = 'critical' THEN 1 ELSE 0 END,
            high_count = high_count - CASE WHEN OLD.severity = 'high' THEN 1 ELSE 0 END,
            medium_count = medium_count - CASE WHEN OLD.severity = 'medium' THEN 1 ELSE 0 END,
            low_count = low_count - CASE WHEN OLD.severity = 'low' THEN 1 ELSE 0 END
        WHERE id = OLD.scan_id;
    END IF;
    RETURN COALESCE(NEW, OLD);
END;
$$ language 'plpgsql';

DROP TRIGGER IF EXISTS update_scan_vulnerability_counts ON vulnerabilities;
CREATE TRIGGER update_scan_vulnerability_counts
    AFTER INSERT OR DELETE ON vulnerabilities
    FOR EACH ROW
    EXECUTE FUNCTION update_scan_vulnerability_counts();

-- ============================================================================
-- VIEWS
-- ============================================================================

-- View for repository scan summary
CREATE OR REPLACE VIEW repository_scan_summary AS
SELECT 
    r.id AS repository_id,
    r.full_name,
    r.provider,
    r.total_scans,
    r.last_scanned_at,
    s.id AS last_scan_id,
    s.status AS last_scan_status,
    s.total_vulnerabilities AS last_scan_vulnerabilities,
    s.critical_count AS last_scan_critical,
    s.high_count AS last_scan_high,
    s.security_score AS last_scan_security_score
FROM repositories r
LEFT JOIN scans s ON s.id = r.last_scan_id;

-- View for vulnerability statistics
CREATE OR REPLACE VIEW vulnerability_statistics AS
SELECT 
    s.repository_id,
    DATE_TRUNC('day', v.created_at) AS date,
    v.severity,
    v.category,
    COUNT(*) AS count,
    COUNT(*) FILTER (WHERE v.is_false_positive = true) AS false_positive_count,
    COUNT(*) FILTER (WHERE v.suppressed = true) AS suppressed_count,
    COUNT(*) FILTER (WHERE v.fixed_at IS NOT NULL) AS fixed_count
FROM vulnerabilities v
JOIN scans s ON s.id = v.scan_id
GROUP BY s.repository_id, DATE_TRUNC('day', v.created_at), v.severity, v.category;

-- ============================================================================
-- INITIAL DATA (optional)
-- ============================================================================

-- Insert default suppression rules patterns (can be customized)
-- These are examples and should be adjusted based on your needs
INSERT INTO suppression_rules (rule_id, file_pattern, reason, is_global, created_by)
VALUES 
    ('secrets', '**/test/**', 'Test files may contain mock secrets', true, 'system'),
    ('secrets', '**/*_test.go', 'Test files may contain mock secrets', true, 'system'),
    ('secrets', '**/fixtures/**', 'Fixture files may contain mock data', true, 'system')
ON CONFLICT DO NOTHING;

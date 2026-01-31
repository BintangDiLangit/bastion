-- Dependency Scanning Schema
-- Version: 2.0.0
-- Adds tables for dependency scanning functionality

-- ============================================================================
-- DEPENDENCY_SCANS TABLE
-- Stores dependency scan results linked to main scans
-- ============================================================================
CREATE TABLE IF NOT EXISTS dependency_scans (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    scan_id UUID NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
    total_dependencies INT NOT NULL DEFAULT 0,
    direct_dependencies INT NOT NULL DEFAULT 0,
    transitive_dependencies INT NOT NULL DEFAULT 0,
    vulnerable_packages INT NOT NULL DEFAULT 0,
    total_vulnerabilities INT NOT NULL DEFAULT 0,
    critical_count INT DEFAULT 0,
    high_count INT DEFAULT 0,
    medium_count INT DEFAULT 0,
    low_count INT DEFAULT 0,
    license_issues_count INT DEFAULT 0,
    risk_score DECIMAL(3,1),
    sbom_path TEXT,
    sbom_format VARCHAR(50), -- cyclonedx, spdx
    completed_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    
    CONSTRAINT dependency_scans_scan_id_fkey FOREIGN KEY (scan_id) REFERENCES scans(id) ON DELETE CASCADE
);

-- ============================================================================
-- DEPENDENCIES TABLE
-- Stores individual dependencies found in scans
-- ============================================================================
CREATE TABLE IF NOT EXISTS dependencies (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    dependency_scan_id UUID NOT NULL REFERENCES dependency_scans(id) ON DELETE CASCADE,
    name VARCHAR(255) NOT NULL,
    version VARCHAR(100) NOT NULL,
    version_constraint VARCHAR(100), -- e.g., "^1.2.3", ">=2.0.0"
    package_manager VARCHAR(50) NOT NULL, -- npm, pip, go, maven, etc.
    language VARCHAR(50), -- javascript, python, go, java, etc.
    is_direct BOOLEAN DEFAULT false,
    is_transitive BOOLEAN DEFAULT false,
    parent_dependency VARCHAR(255), -- Name of parent if transitive
    license VARCHAR(100),
    repository TEXT,
    homepage TEXT,
    deprecated BOOLEAN DEFAULT false,
    metadata JSONB DEFAULT '{}',
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    
    CONSTRAINT dependencies_scan_id_fkey FOREIGN KEY (dependency_scan_id) REFERENCES dependency_scans(id) ON DELETE CASCADE
);

-- ============================================================================
-- DEPENDENCY_VULNERABILITIES TABLE
-- Stores vulnerability information for dependencies
-- ============================================================================
CREATE TABLE IF NOT EXISTS dependency_vulnerabilities (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    dependency_id UUID NOT NULL REFERENCES dependencies(id) ON DELETE CASCADE,
    cve_id VARCHAR(50), -- CVE identifier (e.g., CVE-2023-1234)
    ghsa_id VARCHAR(50), -- GitHub Security Advisory ID
    source VARCHAR(50) NOT NULL, -- OSV, NVD, GitHub, Snyk
    severity VARCHAR(20) NOT NULL, -- critical, high, medium, low
    cvss_score DECIMAL(3,1),
    cvss_vector TEXT,
    summary TEXT,
    details TEXT,
    affected_versions TEXT, -- JSON array of affected versions
    patched_versions TEXT, -- JSON array of patched versions
    fixed_in VARCHAR(100), -- Specific fixed version
    published_at TIMESTAMP WITH TIME ZONE,
    modified_at TIMESTAMP WITH TIME ZONE,
    epss_score DECIMAL(5,4), -- Exploit Prediction Scoring System
    exploit_available BOOLEAN DEFAULT false,
    references JSONB DEFAULT '[]', -- Array of reference URLs
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    
    CONSTRAINT dependency_vulns_dependency_id_fkey FOREIGN KEY (dependency_id) REFERENCES dependencies(id) ON DELETE CASCADE
);

-- ============================================================================
-- LICENSE_ISSUES TABLE
-- Stores license compliance issues found in dependencies
-- ============================================================================
CREATE TABLE IF NOT EXISTS license_issues (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    dependency_scan_id UUID NOT NULL REFERENCES dependency_scans(id) ON DELETE CASCADE,
    dependency_id UUID NOT NULL REFERENCES dependencies(id) ON DELETE CASCADE,
    license VARCHAR(100) NOT NULL,
    issue_type VARCHAR(50) NOT NULL, -- forbidden, incompatible, needs_review, missing, ambiguous
    severity VARCHAR(20), -- critical, high, medium, low
    explanation TEXT,
    recommendation TEXT,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    
    CONSTRAINT license_issues_scan_id_fkey FOREIGN KEY (dependency_scan_id) REFERENCES dependency_scans(id) ON DELETE CASCADE,
    CONSTRAINT license_issues_dependency_id_fkey FOREIGN KEY (dependency_id) REFERENCES dependencies(id) ON DELETE CASCADE
);

-- ============================================================================
-- DEPENDENCY_RECOMMENDATIONS TABLE
-- Stores AI-generated recommendations for dependency remediation
-- ============================================================================
CREATE TABLE IF NOT EXISTS dependency_recommendations (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    dependency_scan_id UUID NOT NULL REFERENCES dependency_scans(id) ON DELETE CASCADE,
    dependency_id UUID REFERENCES dependencies(id) ON DELETE SET NULL,
    recommendation_type VARCHAR(50) NOT NULL, -- upgrade, replace, remove, accept, monitor
    action TEXT NOT NULL,
    target_version VARCHAR(100),
    priority INT NOT NULL DEFAULT 0,
    effort VARCHAR(20), -- low, medium, high
    impact TEXT, -- severe, moderate, limited, minimal
    details TEXT,
    timeline VARCHAR(100), -- e.g., "ASAP", "Within 1 week"
    ai_analysis JSONB DEFAULT '{}', -- Full ADK analysis result
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    
    CONSTRAINT dep_recs_scan_id_fkey FOREIGN KEY (dependency_scan_id) REFERENCES dependency_scans(id) ON DELETE CASCADE,
    CONSTRAINT dep_recs_dependency_id_fkey FOREIGN KEY (dependency_id) REFERENCES dependencies(id) ON DELETE SET NULL
);

-- ============================================================================
-- INDEXES FOR PERFORMANCE
-- ============================================================================

-- Dependency scans indexes
CREATE INDEX IF NOT EXISTS idx_dep_scans_scan_id ON dependency_scans(scan_id);
CREATE INDEX IF NOT EXISTS idx_dep_scans_created_at ON dependency_scans(created_at DESC);
CREATE INDEX IF NOT EXISTS idx_dep_scans_risk_score ON dependency_scans(risk_score DESC);

-- Dependencies indexes
CREATE INDEX IF NOT EXISTS idx_dependencies_scan_id ON dependencies(dependency_scan_id);
CREATE INDEX IF NOT EXISTS idx_dependencies_name ON dependencies(name);
CREATE INDEX IF NOT EXISTS idx_dependencies_package_manager ON dependencies(package_manager);
CREATE INDEX IF NOT EXISTS idx_dependencies_is_direct ON dependencies(is_direct);

-- Dependency vulnerabilities indexes
CREATE INDEX IF NOT EXISTS idx_dep_vulns_dependency_id ON dependency_vulnerabilities(dependency_id);
CREATE INDEX IF NOT EXISTS idx_dep_vulns_severity ON dependency_vulnerabilities(severity);
CREATE INDEX IF NOT EXISTS idx_dep_vulns_cve_id ON dependency_vulnerabilities(cve_id);
CREATE INDEX IF NOT EXISTS idx_dep_vulns_source ON dependency_vulnerabilities(source);
CREATE INDEX IF NOT EXISTS idx_dep_vulns_cvss_score ON dependency_vulnerabilities(cvss_score DESC);

-- License issues indexes
CREATE INDEX IF NOT EXISTS idx_license_issues_scan_id ON license_issues(dependency_scan_id);
CREATE INDEX IF NOT EXISTS idx_license_issues_dependency_id ON license_issues(dependency_id);
CREATE INDEX IF NOT EXISTS idx_license_issues_type ON license_issues(issue_type);

-- Dependency recommendations indexes
CREATE INDEX IF NOT EXISTS idx_dep_recs_scan_id ON dependency_recommendations(dependency_scan_id);
CREATE INDEX IF NOT EXISTS idx_dep_recs_dependency_id ON dependency_recommendations(dependency_id);
CREATE INDEX IF NOT EXISTS idx_dep_recs_priority ON dependency_recommendations(priority);
CREATE INDEX IF NOT EXISTS idx_dep_recs_type ON dependency_recommendations(recommendation_type);

-- ============================================================================
-- TRIGGERS FOR AUTOMATIC TIMESTAMP UPDATES
-- ============================================================================

-- Function to update updated_at timestamp
CREATE OR REPLACE FUNCTION update_updated_at_column()
RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at = CURRENT_TIMESTAMP;
    RETURN NEW;
END;
$$ language 'plpgsql';

-- Note: Most tables use created_at only, but if needed, add triggers:
-- CREATE TRIGGER update_dependency_scans_updated_at BEFORE UPDATE ON dependency_scans
--     FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();

-- ============================================================================
-- COMMENTS FOR DOCUMENTATION
-- ============================================================================

COMMENT ON TABLE dependency_scans IS 'Stores high-level results of dependency security scans';
COMMENT ON TABLE dependencies IS 'Stores individual dependencies found in repositories';
COMMENT ON TABLE dependency_vulnerabilities IS 'Stores vulnerability information linked to dependencies';
COMMENT ON TABLE license_issues IS 'Stores license compliance issues found in dependencies';
COMMENT ON TABLE dependency_recommendations IS 'Stores AI-generated remediation recommendations';

COMMENT ON COLUMN dependency_vulnerabilities.epss_score IS 'Exploit Prediction Scoring System (0.0-1.0) - likelihood of exploitation';
COMMENT ON COLUMN dependency_vulnerabilities.exploit_available IS 'Whether a public exploit exists for this vulnerability';
COMMENT ON COLUMN dependency_recommendations.ai_analysis IS 'Full JSON response from ADK analysis including reasoning and context';

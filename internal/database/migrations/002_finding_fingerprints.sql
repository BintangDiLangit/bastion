ALTER TABLE vulnerabilities
    ADD COLUMN IF NOT EXISTS fingerprint VARCHAR(32);

UPDATE vulnerabilities
SET fingerprint = SUBSTRING(
    ENCODE(DIGEST(rule_id || CHR(31) || file_path || CHR(31) || COALESCE(code_snippet, ''), 'sha256'), 'hex'),
    1,
    32
)
WHERE fingerprint IS NULL;

ALTER TABLE vulnerabilities
    ALTER COLUMN fingerprint SET NOT NULL;

CREATE INDEX IF NOT EXISTS idx_vulnerabilities_fingerprint
    ON vulnerabilities(fingerprint);

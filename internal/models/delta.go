package models

import "github.com/google/uuid"

// ScanDelta compares findings between two completed scans.
type ScanDelta struct {
	ScanID         uuid.UUID       `json:"scan_id"`
	BaselineScanID *uuid.UUID      `json:"baseline_scan_id,omitempty"`
	New            []Vulnerability `json:"new"`
	Resolved       []Vulnerability `json:"resolved"`
	Unchanged      int             `json:"unchanged"`
}

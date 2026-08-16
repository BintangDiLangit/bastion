package main

import (
	"encoding/json"
	"testing"
)

// A clean scan is the common case and used to be the broken one: a nil slice
// marshals to null, and an endLine of 0 is below startLine. Both make the SARIF
// invalid, and the documented CI recipe pipes it straight to upload-sarif.
func TestSARIFIsSchemaValid(t *testing.T) {
	for _, test := range []struct {
		name  string
		input ScanOutput
	}{
		{"clean scan", ScanOutput{Vulnerabilities: []VulnOutput{}}},
		{"finding without an end line", ScanOutput{Vulnerabilities: []VulnOutput{
			{RuleID: "xss", FilePath: "a.js", LineStart: 42},
		}}},
	} {
		t.Run(test.name, func(t *testing.T) {
			data, err := toSARIF(test.input)
			if err != nil {
				t.Fatal(err)
			}

			var doc struct {
				Runs []struct {
					Results *[]struct {
						Locations []struct {
							PhysicalLocation struct {
								Region map[string]int `json:"region"`
							} `json:"physicalLocation"`
						} `json:"locations"`
					} `json:"results"`
				} `json:"runs"`
			}
			if err := json.Unmarshal(data, &doc); err != nil {
				t.Fatal(err)
			}

			if doc.Runs[0].Results == nil {
				t.Fatal(`"results" is null; must be an array`)
			}
			for _, result := range *doc.Runs[0].Results {
				region := result.Locations[0].PhysicalLocation.Region
				if region["startLine"] < 1 {
					t.Errorf("startLine = %d, must be >= 1", region["startLine"])
				}
				if end, ok := region["endLine"]; ok && end < region["startLine"] {
					t.Errorf("endLine %d < startLine %d", end, region["startLine"])
				}
			}
		})
	}
}

// The flag is named --fail-on-critical and every doc promises exactly that.
// Failing on high as well pushed users to --fail-on-critical=false, which
// turns the gate off entirely.
func TestShouldFail(t *testing.T) {
	for _, test := range []struct {
		name    string
		summary ScanSummary
		flag    bool
		want    bool
	}{
		{"critical with flag on", ScanSummary{Critical: 1}, true, true},
		{"high only does not fail", ScanSummary{High: 3}, true, false},
		{"clean", ScanSummary{}, true, false},
		{"critical with flag off", ScanSummary{Critical: 1}, false, false},
	} {
		t.Run(test.name, func(t *testing.T) {
			if got := shouldFail(test.summary, test.flag); got != test.want {
				t.Errorf("shouldFail(%+v, %v) = %v, want %v", test.summary, test.flag, got, test.want)
			}
		})
	}
}

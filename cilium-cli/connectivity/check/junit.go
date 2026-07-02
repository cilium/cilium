// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package check

import (
	"cmp"
	"errors"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"time"

	"github.com/cilium/cilium/cilium-cli/connectivity/internal/junit"
	"github.com/cilium/cilium/tools/testowners/codeowners"
)

const MetadataDelimiter = ";metadata;"

// NewJUnitCollector factory function that returns JUnitCollector.
func NewJUnitCollector(junitProperties map[string]string, junitFile string, codeowners *codeowners.Ruleset) *JUnitCollector {
	properties := []junit.Property{
		{Name: "Args", Value: strings.Join(os.Args[3:], "|")},
	}
	if codeowners != nil {
		if workflowOwners, err := codeowners.WorkflowOwners(false); err == nil {
			for _, o := range workflowOwners {
				properties = append(properties, junit.Property{Name: "owner", Value: o})
			}
		}
	}

	return &JUnitCollector{
		testSuite: &junit.TestSuite{
			Name:    "connectivity test",
			Package: "cilium",
			Properties: &junit.Properties{
				Properties: properties,
			},
		},
		junitFile: junitFile,
	}
}

type JUnitCollector struct {
	testSuite *junit.TestSuite
	junitFile string
}

// Collect collects ConnectivityTest instance test results.
// The method is not thread safe.
func (j *JUnitCollector) Collect(ct *ConnectivityTest) {
	if j.junitFile == "" || len(ct.tests) == 0 {
		return
	}

	// Timestamp of the TestSuite is the first test's start time
	if j.testSuite.Timestamp == "" {
		j.testSuite.Timestamp = ct.tests[0].startTime.Format(time.RFC3339)
	}
	for _, t := range ct.tests {
		test := &junit.TestCase{
			Name:      t.Name(),
			Classname: "connectivity test",
			Status:    "passed",
			Time:      t.completionTime.Sub(t.startTime).Seconds(),
		}
		j.testSuite.Tests++
		j.testSuite.Time += test.Time

		if ct.params.LogCodeOwners {
			scenarios := t.Scenarios()
			owners := make(map[string]struct{})
			for _, s := range scenarios {
				codeOwners, err := ct.CodeOwners.Owners(false, s)
				if err != nil {
					ct.Logf("Failed to find CODEOWNERS for junit test case: %s", err)
				}
				for _, o := range codeOwners {
					owners[o] = struct{}{}
				}
			}
			properties := make([]junit.Property, 0, len(owners))
			for o := range owners {
				properties = append(properties, junit.Property{
					Name:  "owner",
					Value: o,
				})
			}
			slices.SortFunc(properties,
				func(a, b junit.Property) int {
					return cmp.Compare(a.Value, b.Value)
				})
			test.Properties = &junit.Properties{Properties: properties}
		}

		if t.skipped {
			test.Status = "skipped"
			test.Skipped = &junit.Skipped{Message: t.Name() + " skipped"}
			j.testSuite.Skipped++
			test.Time = 0
		} else if t.failed {
			test.Status = "failed"
			test.Failure = &junit.Failure{Message: t.Name() + " failed", FailureMessages: t.FailureMessages(), Type: "failure"}
			j.testSuite.Failures++
			msgs := []string{}
			for _, a := range t.failedActions() {
				msgs = append(msgs, a.String())
			}
			test.Failure.Value = strings.Join(msgs, "\n")
		}

		j.testSuite.TestCases = append(j.testSuite.TestCases, test)
	}
}

// Write writes collected JUnit results into a single report file.
//
// The report is written to a temporary file in the same directory and then
// atomically renamed into place. This ensures readers (e.g. CI artifact upload)
// never observe a truncated report if the process is interrupted mid-write.
func (j *JUnitCollector) Write() error {
	if j.testSuite.Tests == 0 {
		return nil
	}

	suites := junit.TestSuites{
		Tests:      j.testSuite.Tests,
		Disabled:   j.testSuite.Skipped,
		Failures:   j.testSuite.Failures,
		Time:       j.testSuite.Time,
		TestSuites: []*junit.TestSuite{j.testSuite},
	}

	// Write to a temporary file in the same directory as the destination so the
	// final rename is atomic (same filesystem).
	f, err := os.CreateTemp(filepath.Dir(j.junitFile), filepath.Base(j.junitFile)+".tmp-*")
	if err != nil {
		return err
	}
	tmpName := f.Name()
	// Remove the temporary file on any error path before the rename.
	defer func() { _ = os.Remove(tmpName) }()

	// os.CreateTemp creates the file with mode 0600, but the report must stay
	// readable by other users, e.g. the CI artifact upload which runs outside
	// the container that produced the file.
	if err := f.Chmod(0o644); err != nil {
		_ = f.Close()
		return err
	}

	if err := suites.WriteReport(f); err != nil {
		_ = f.Close()
		return err
	}

	// Flush to stable storage and close before renaming into place.
	if err := f.Sync(); err != nil {
		return errors.Join(err, f.Close())
	}
	if err := f.Close(); err != nil {
		return err
	}

	return os.Rename(tmpName, j.junitFile)
}

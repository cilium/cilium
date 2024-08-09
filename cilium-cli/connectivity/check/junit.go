// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package check

import (
	"errors"
	"os"
	"strings"

	"github.com/cilium/cilium/cilium-cli/connectivity/internal/junit"
)

// NewJUnitCollector factory function that returns JUnitCollector.
func NewJUnitCollector(junitProperties map[string]string, junitFile string) *JUnitCollector {
	properties := []junit.Property{
		{Name: "Args", Value: strings.Join(os.Args[3:], "|")},
	}
	for key, val := range junitProperties {
		properties = append(properties, junit.Property{Name: key, Value: val})
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
		j.testSuite.Timestamp = ct.tests[0].startTime.Format("2006-01-02T15:04:05")
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

		if t.skipped {
			test.Status = "skipped"
			test.Skipped = &junit.Skipped{Message: t.Name() + " skipped"}
			j.testSuite.Skipped++
			test.Time = 0
		} else if t.failed {
			test.Status = "failed"
			test.Failure = &junit.Failure{Message: t.Name() + " failed", Type: "failure"}
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
	f, err := os.Create(j.junitFile)
	if err != nil {
		return err
	}

	if err := suites.WriteReport(f); err != nil {
		if e := f.Close(); e != nil {
			return errors.Join(err, e)
		}
		return err
	}

	return f.Close()
}

// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package junit

import (
	"bytes"
	"testing"

	"github.com/stretchr/testify/assert"
)

var suitesText = `<?xml version="1.0" encoding="UTF-8"?>
  <testsuites tests="3" disabled="1" errors="0" failures="1" time="14.7">
      <testsuite name="testSuite" id="0" package="test" tests="3" errors="0" failures="1" skipped="1" time="14.7" timestamp="2023-05-08T11:24:14">
          <testcase name="test1" classname="test" status="passed" time="7.7"></testcase>
          <testcase name="test2" classname="test" status="skipped" time="0">
              <skipped message="test2 skipped"></skipped>
          </testcase>
          <testcase name="test3" classname="test" status="failed" time="7">
              <failure message="test3 failed" type="failure">failure &gt; expected</failure>
          </testcase>
      </testsuite>
  </testsuites>`

var suites = TestSuites{
	Tests:    3,
	Disabled: 1,
	Failures: 1,
	Time:     14.7,
	TestSuites: []*TestSuite{
		{
			Name:      "testSuite",
			Package:   "test",
			Tests:     3,
			Skipped:   1,
			Failures:  1,
			Time:      14.7,
			Timestamp: "2023-05-08T11:24:14",
			TestCases: []*TestCase{
				{Name: "test1", Classname: "test", Status: "passed", Time: 7.7},
				{Name: "test2", Classname: "test", Status: "skipped", Time: 0,
					Skipped: &Skipped{Message: "test2 skipped"}},
				{Name: "test3", Classname: "test", Status: "failed", Time: 7,
					Failure: &Failure{Message: "test3 failed", Type: "failure", Value: "failure > expected"}},
			},
		},
	},
}

func TestWriteReport(t *testing.T) {
	buf := &bytes.Buffer{}
	assert.NoError(t, suites.WriteReport(buf))
	assert.Equal(t, suitesText, buf.String())
}

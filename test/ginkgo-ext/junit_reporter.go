// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package ginkgoext

/*

JUnit XML Reporter for Ginkgo

For usage instructions: http://onsi.github.io/ginkgo/#generating_junit_xml_output

Reference file:
https://github.com/onsi/ginkgo/blob/39febac9157b63aeba74d843d6b1c30990f3d7ed/reporters/junit_reporter.go
Junit Reference:
https://www.ibm.com/support/knowledgecenter/en/SSQ2R2_9.1.1/com.ibm.rsar.analysis.codereview.cobol.doc/topics/cac_useresults_junit.html
*/

import (
	"encoding/xml"
	"fmt"
	"math"
	"os"
	"strings"

	"github.com/onsi/ginkgo/config"
	"github.com/onsi/ginkgo/types"
)

// JUnitTestSuite main struct to report all test in Junit Format
type JUnitTestSuite struct {
	XMLName   xml.Name        `xml:"testsuite"`
	TestCases []JUnitTestCase `xml:"testcase"`
	Name      string          `xml:"name,attr"`
	Tests     int             `xml:"tests,attr"`
	Failures  int             `xml:"failures,attr"`
	Errors    int             `xml:"errors,attr"`
	Time      float64         `xml:"time,attr"`
}

// JUnitTestCase test case struct to report in Junit Format.
type JUnitTestCase struct {
	Name           string               `xml:"name,attr"`
	ClassName      string               `xml:"classname,attr"`
	FailureMessage *JUnitFailureMessage `xml:"failure,omitempty"`
	Skipped        *JUnitSkipped        `xml:"skipped,omitempty"`
	Time           float64              `xml:"time,attr"`
	SystemErr      string               `xml:"system-err,omitempty"`
	SystemOut      string               `xml:"system-out,omitempty"`
}

// JUnitFailureMessage failure message struct
type JUnitFailureMessage struct {
	Type    string `xml:"type,attr"`
	Message string `xml:",chardata"`
}

// JUnitSkipped skipped struct to report XML
type JUnitSkipped struct {
	XMLName xml.Name `xml:"skipped"`
}

// JUnitReporter struct that uses ginkgo to report
type JUnitReporter struct {
	suite         JUnitTestSuite
	filename      string
	testSuiteName string
}

// NewJUnitReporter creates a new JUnit XML reporter.  The XML will be stored in the passed in filename.
func NewJUnitReporter(filename string) *JUnitReporter {
	return &JUnitReporter{
		filename: filename,
	}
}

// SpecSuiteWillBegin create the main JUnitTestSuite based on Ginkgo parameters
func (reporter *JUnitReporter) SpecSuiteWillBegin(config config.GinkgoConfigType, summary *types.SuiteSummary) {
	reporter.suite = JUnitTestSuite{
		Name:      summary.SuiteDescription,
		TestCases: []JUnitTestCase{},
	}
	reporter.testSuiteName = summary.SuiteDescription
}

// SpecWillRun needed by ginkgo. Not used.
func (reporter *JUnitReporter) SpecWillRun(specSummary *types.SpecSummary) {
}

// BeforeSuiteDidRun Beforesuite report function
func (reporter *JUnitReporter) BeforeSuiteDidRun(setupSummary *types.SetupSummary) {
	reporter.handleSetupSummary("BeforeSuite", setupSummary)
}

// AfterSuiteDidRun ginkgo.Aftersuite report function
func (reporter *JUnitReporter) AfterSuiteDidRun(setupSummary *types.SetupSummary) {
	reporter.handleSetupSummary("AfterSuite", setupSummary)
}

func failureMessage(failure types.SpecFailure) string {
	return fmt.Sprintf("%s\n%s\n%s", failure.ComponentCodeLocation.String(), failure.Message, failure.Location.String())
}

func (reporter *JUnitReporter) handleSetupSummary(name string, setupSummary *types.SetupSummary) {
	if setupSummary.State != types.SpecStatePassed {
		testCase := JUnitTestCase{
			Name:      name,
			ClassName: reporter.testSuiteName,
		}

		testCase.FailureMessage = &JUnitFailureMessage{
			Type:    reporter.failureTypeForState(setupSummary.State),
			Message: failureMessage(setupSummary.Failure),
		}
		testCase.SystemErr = setupSummary.CapturedOutput
		testCase.Time = setupSummary.RunTime.Seconds()
		reporter.suite.TestCases = append(reporter.suite.TestCases, testCase)
	}
}

// SpecDidComplete reports the test results in a JUTestCase struct
func (reporter *JUnitReporter) SpecDidComplete(specSummary *types.SpecSummary) {
	testCase := JUnitTestCase{
		Name:      strings.Join(specSummary.ComponentTexts[1:], " "),
		ClassName: reporter.testSuiteName,
	}
	if specSummary.State == types.SpecStateFailed || specSummary.State == types.SpecStateTimedOut || specSummary.State == types.SpecStatePanicked {
		testCase.FailureMessage = &JUnitFailureMessage{
			Type:    reporter.failureTypeForState(specSummary.State),
			Message: failureMessage(specSummary.Failure),
		}
		checks, output := reportChecks(specSummary.CapturedOutput)
		testCase.SystemErr = checks
		testCase.SystemOut = output
	}
	if specSummary.State == types.SpecStateSkipped || specSummary.State == types.SpecStatePending {
		testCase.Skipped = &JUnitSkipped{}
	}
	testCase.Time = specSummary.RunTime.Seconds()
	reporter.suite.TestCases = append(reporter.suite.TestCases, testCase)
}

// SpecSuiteDidEnd summary information to Suite summary in the xml report
func (reporter *JUnitReporter) SpecSuiteDidEnd(summary *types.SuiteSummary) {
	reporter.suite.Tests = summary.NumberOfSpecsThatWillBeRun
	reporter.suite.Time = math.Trunc(summary.RunTime.Seconds() * 1000 / 1000)
	reporter.suite.Failures = summary.NumberOfFailedSpecs
	reporter.suite.Errors = 0
	file, err := os.Create(reporter.filename)
	if err != nil {
		fmt.Printf("Failed to create JUnit report file: %s\n\t%s", reporter.filename, err.Error())
	}
	defer file.Close()
	file.WriteString(xml.Header)
	encoder := xml.NewEncoder(file)
	encoder.Indent("  ", "    ")
	err = encoder.Encode(reporter.suite)
	if err != nil {
		fmt.Printf("Failed to generate JUnit report\n\t%s", err.Error())
	}
}

func (reporter *JUnitReporter) failureTypeForState(state types.SpecState) string {
	switch state {
	case types.SpecStateFailed:
		return "Failure"
	case types.SpecStateTimedOut:
		return "Timeout"
	case types.SpecStatePanicked:
		return "Panic"
	default:
		return "Unknown"
	}
}

// reportChecks filters the given string from the stdout and subtract the
// information that is within the <Checks></Checks> labels. It'll return the
// given output as first result, and the check output in the second string.
func reportChecks(output string) (string, string) {
	var checks string
	var stdout string
	var dest = "stdout"

	for _, line := range strings.Split(output, "\n") {
		if line == "<Checks>" {
			dest = "checks"
			continue
		}

		if line == "</Checks>" {
			dest = "stdout"
			continue
		}
		switch dest {
		case "stdout":
			stdout += line + "\n"
			continue
		case "checks":
			checks += line + "\n"
			continue
		}
	}
	return stdout, checks
}

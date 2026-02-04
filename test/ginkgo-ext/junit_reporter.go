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
	"regexp"
	"strings"

	"github.com/onsi/ginkgo/config"
	"github.com/onsi/ginkgo/types"

	"github.com/cilium/cilium/tools/testowners/codeowners"
)

// JUnitProperty represents a property in the JUnit XML
type JUnitProperty struct {
	Name  string `xml:"name,attr"`
	Value string `xml:"value,attr"`
}

// JUnitProperties represents the properties section in JUnit XML
type JUnitProperties struct {
	XMLName    xml.Name        `xml:"properties"`
	Properties []JUnitProperty `xml:"property"`
}

// JUnitTestSuite main struct to report all test in Junit Format
type JUnitTestSuite struct {
	XMLName    xml.Name         `xml:"testsuite"`
	Properties *JUnitProperties `xml:"properties,omitempty"`
	TestCases  []JUnitTestCase  `xml:"testcase"`
	Name       string           `xml:"name,attr"`
	Tests      int              `xml:"tests,attr"`
	Failures   int              `xml:"failures,attr"`
	Errors     int              `xml:"errors,attr"`
	Time       float64          `xml:"time,attr"`
}

// JUnitTestCase test case struct to report in Junit Format.
type JUnitTestCase struct {
	Name           string               `xml:"name,attr"`
	ClassName      string               `xml:"classname,attr"`
	Properties     *JUnitProperties     `xml:"properties,omitempty"`
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
}

// extractTestOwnerPrefix extracts the test owner from the test name pattern
func (reporter *JUnitReporter) extractTestOwnerPrefix(testName string) string {
	if testName == "" {
		return ""
	}

	testName = strings.TrimPrefix(testName, "[Top Level] ")

	// Look for test class patterns like "K8sAgentPolicyTest", "K8sDatapathServicesTest", etc.
	// These typically end with "Test" and are at the beginning of the test name
	parts := strings.Fields(testName)
	if len(parts) > 0 {
		firstPart := parts[0]
		// Check if it looks like a test class name (ends with "Test")
		if strings.HasSuffix(firstPart, "Test") ||
			strings.HasSuffix(firstPart, "DatapathConfig") ||
			strings.HasPrefix(firstPart, "RuntimeAgent") {
			return firstPart
		}
	}

	// Fallback: look for any word ending with "Test" in the test name
	re := regexp.MustCompile(`\b\w+Test(s)?(Extended)?\b`)
	matches := re.FindAllString(testName, -1)
	if len(matches) > 0 {
		return matches[0]
	}

	return ""
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

// AddProperty adds a property to a specific test case
func (testCase *JUnitTestCase) AddProperty(name, value string) {
	if testCase.Properties == nil {
		testCase.Properties = &JUnitProperties{
			Properties: []JUnitProperty{},
		}
	}
	testCase.Properties.Properties = append(testCase.Properties.Properties, JUnitProperty{
		Name:  name,
		Value: value,
	})
}

type scenario struct {
	name     string
	filePath string
}

func (s scenario) Name() string {
	return s.name
}

func (s scenario) FilePath() string {
	return s.filePath
}

// SpecDidComplete reports the test results in a JUTestCase struct
func (reporter *JUnitReporter) SpecDidComplete(specSummary *types.SpecSummary) {
	testCase := JUnitTestCase{
		Name:      strings.Join(specSummary.ComponentTexts[1:], " "),
		ClassName: reporter.testSuiteName,
	}

	// Extract owner from the full test name for individual test cases
	fullTestName := strings.Join(specSummary.ComponentTexts, " ")
	testPrefixName := reporter.extractTestOwnerPrefix(fullTestName)
	filePath := reporter.mapTestToCODEOWNER(testPrefixName)
	if filePath == "" {
		panic(fmt.Sprintf("filePath not found for test %s", fullTestName))
	}

	owners, err := codeowners.Load([]string{})
	if err != nil {
		panic(fmt.Sprintf("failed to load owners: %s", err))
	}
	s := scenario{
		name:     testPrefixName,
		filePath: filePath,
	}
	codeOwners, err := owners.Owners(false, &s)
	if err != nil {
		panic(fmt.Sprintf("failed to find owners: %s", err))
	}
	for _, o := range codeOwners {
		testCase.AddProperty("owner", o)
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
	var checks strings.Builder
	var stdout strings.Builder
	var dest = "stdout"

	for line := range strings.SplitSeq(output, "\n") {
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
			stdout.WriteString(line + "\n")
			continue
		case "checks":
			checks.WriteString(line + "\n")
			continue
		}
	}
	return stdout.String(), checks.String()
}

// mapTestToCODEOWNER maps the test prefix to the corresponding filename
// where the test is defined.
// If no mapping is found, it returns an empty string.
func (reporter *JUnitReporter) mapTestToCODEOWNER(prefix string) string {
	switch prefix {
	case "K8sAgentChaosTest":
		return "test/k8s/chaos.go"
	case "K8sAgentFQDNTest":
		return "test/k8s/fqdn.go"
	case "RuntimeAgentFQDNPolicies":
		return "test/runtime/fqdn.go"
	case "K8sAgentHubbleTest":
		return "test/k8s/hubble.go"
	case "K8sAgentPolicyTest":
		return "test/k8s/net_policies.go"
	case "K8sPolicyTestExtended":
		return "test/k8s/net_policies.go"
	case "RuntimeAgentPolicies":
		return "test/runtime/net_policies.go"
	case "K8sDatapathBandwidthTest":
		return "test/k8s/bandwidth.go"
	case "K8sDatapathConfig":
		return "test/k8s/datapath_configuration.go"
	case "RuntimeDatapathMonitorTest":
		return "test/runtime/monitor.go"
	case "K8sDatapathLRPTests":
		return "test/k8s/lrp.go"
	case "K8sDatapathServicesTest":
		return "test/k8s/services.go"
	case "K8sSpecificMACAddressTests":
		return "test/k8s/pod_mac_address.go"
	}
	return ""
}

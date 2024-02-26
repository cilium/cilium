// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package junit

import (
	"encoding/xml"
	"fmt"
	"io"
)

// TestSuites represents collection of test suites.
type TestSuites struct {
	XMLName xml.Name `xml:"testsuites"`

	Tests    int     `xml:"tests,attr"`
	Disabled int     `xml:"disabled,attr"`
	Errors   int     `xml:"errors,attr"`
	Failures int     `xml:"failures,attr"`
	Time     float64 `xml:"time,attr"`

	TestSuites []*TestSuite `xml:"testsuite"`
}

// WriteReport writes Junit XML output to a writer interface.
func (ts *TestSuites) WriteReport(w io.Writer) error {
	if _, err := fmt.Fprint(w, xml.Header); err != nil {
		return err
	}

	encoder := xml.NewEncoder(w)
	encoder.Indent("  ", "    ")
	return encoder.Encode(ts)
}

// TestSuite represents collection of test cases.
type TestSuite struct {
	XMLName xml.Name `xml:"testsuite"`

	Name      string  `xml:"name,attr"`
	ID        int     `xml:"id,attr"`
	Package   string  `xml:"package,attr"`
	Tests     int     `xml:"tests,attr"`
	Disabled  int     `xml:"disabled,attr,omitempty"`
	Errors    int     `xml:"errors,attr"`
	Failures  int     `xml:"failures,attr"`
	Skipped   int     `xml:"skipped,attr,omitempty"`
	Time      float64 `xml:"time,attr"`
	Timestamp string  `xml:"timestamp,attr"`
	Hostname  string  `xml:"hostname,attr,omitempty"`

	Properties *Properties `xml:"properties,omitempty"`

	TestCases []*TestCase `xml:"testcase"`

	SystemOut string `xml:"system-out,omitempty"`
	SystemErr string `xml:"system-err,omitempty"`
}

// Properties represents additional information of a test suite.
type Properties struct {
	Properties []Property `xml:"property"`
}

// Property represents a property in Properties.
type Property struct {
	XMLName xml.Name `xml:"property"`

	Name  string `xml:"name,attr"`
	Value string `xml:"value,attr"`
}

// TestCase represents a single test case within a test suite.
type TestCase struct {
	XMLName xml.Name `xml:"testcase"`

	Name      string  `xml:"name,attr"`
	Classname string  `xml:"classname,attr"`
	Status    string  `xml:"status,attr,omitempty"`
	Time      float64 `xml:"time,attr"`

	Skipped *Skipped `xml:"skipped,omitempty"`
	Error   *Error   `xml:"error,omitempty"`
	Failure *Failure `xml:"failure,omitempty"`

	SystemOut string `xml:"system-out,omitempty"`
	SystemErr string `xml:"system-err,omitempty"`
}

// Skipped represents a skipped information in a test case.
type Skipped struct {
	XMLName xml.Name `xml:"skipped"`

	Message string `xml:"message,attr,omitempty"`
}

// Error represents an error information in a test case.
type Error struct {
	XMLName xml.Name `xml:"error"`

	Message string `xml:"message,attr,omitempty"`
	Type    string `xml:"type,attr"`

	Value string `xml:",chardata"`
}

// Failure represents a failure information in a test case.
type Failure struct {
	XMLName xml.Name `xml:"failure"`

	Message string `xml:"message,attr,omitempty"`
	Type    string `xml:"type,attr"`

	Value string `xml:",chardata"`
}

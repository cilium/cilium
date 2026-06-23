// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package check

import (
	"encoding/xml"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/cilium/cilium/cilium-cli/connectivity/internal/junit"
)

func TestRecordInfrastructureFailureWriteReport(t *testing.T) {
	dir := t.TempDir()
	junitFile := filepath.Join(dir, "report.xml")

	collector := NewJUnitCollector(nil, junitFile, nil)
	setupErr := errors.New("timeout reached waiting for deployment cilium-test-1/client to become ready (last error: pods not ready)")
	collector.RecordInfrastructureFailure(setupErr)

	require.NoError(t, collector.Write())

	data, err := os.ReadFile(junitFile)
	require.NoError(t, err)

	var suites junit.TestSuites
	require.NoError(t, xml.Unmarshal(data, &suites))

	assert.Equal(t, 1, suites.Tests)
	assert.Equal(t, 1, suites.Failures)
	require.Len(t, suites.TestSuites, 1)
	require.Len(t, suites.TestSuites[0].TestCases, 1)

	testCase := suites.TestSuites[0].TestCases[0]
	assert.Equal(t, InfrastructureProvisioningTestName, testCase.Name)
	assert.Equal(t, "connectivity test", testCase.Classname)
	assert.Equal(t, "failed", testCase.Status)
	require.NotNil(t, testCase.Failure)
	assert.Equal(t, InfrastructureProvisioningTestName+" failed", testCase.Failure.Message)
	assert.Equal(t, setupErr.Error(), testCase.Failure.Value)
	assert.NotEmpty(t, suites.TestSuites[0].Timestamp)
}

func TestRecordInfrastructureFailureNoOp(t *testing.T) {
	collector := NewJUnitCollector(nil, "", nil)
	collector.RecordInfrastructureFailure(errors.New("setup failed"))
	assert.Equal(t, 0, collector.testSuite.Tests)
}

func TestWriteWithoutCollectOrInfrastructureFailure(t *testing.T) {
	dir := t.TempDir()
	junitFile := filepath.Join(dir, "report.xml")

	collector := NewJUnitCollector(nil, junitFile, nil)
	require.NoError(t, collector.Write())

	_, err := os.Stat(junitFile)
	assert.True(t, os.IsNotExist(err))
}

func TestInfrastructureFailureXMLHeader(t *testing.T) {
	dir := t.TempDir()
	junitFile := filepath.Join(dir, "report.xml")

	collector := NewJUnitCollector(nil, junitFile, nil)
	collector.RecordInfrastructureFailure(errors.New("deployment failed"))
	require.NoError(t, collector.Write())

	data, err := os.ReadFile(junitFile)
	require.NoError(t, err)
	assert.True(t, strings.HasPrefix(string(data), xml.Header))
}

func TestInfrastructureFailureMatchesGoldenShape(t *testing.T) {
	golden, err := os.ReadFile("testdata/infrastructure-provisioning-failure.xml")
	require.NoError(t, err)

	var goldenSuites junit.TestSuites
	require.NoError(t, xml.Unmarshal(golden, &goldenSuites))

	dir := t.TempDir()
	junitFile := filepath.Join(dir, "report.xml")
	setupErr := errors.New("timeout reached waiting for deployment cilium-test-1/client to become ready (last error: pods not ready)")

	collector := NewJUnitCollector(nil, junitFile, nil)
	collector.RecordInfrastructureFailure(setupErr)
	require.NoError(t, collector.Write())

	generated, err := os.ReadFile(junitFile)
	require.NoError(t, err)

	var generatedSuites junit.TestSuites
	require.NoError(t, xml.Unmarshal(generated, &generatedSuites))

	assert.Equal(t, goldenSuites.Tests, generatedSuites.Tests)
	assert.Equal(t, goldenSuites.Failures, generatedSuites.Failures)
	require.Len(t, generatedSuites.TestSuites, 1)
	require.Len(t, generatedSuites.TestSuites[0].TestCases, 1)

	testCase := generatedSuites.TestSuites[0].TestCases[0]
	goldenCase := goldenSuites.TestSuites[0].TestCases[0]
	assert.Equal(t, goldenCase.Name, testCase.Name)
	assert.Equal(t, goldenCase.Classname, testCase.Classname)
	assert.Equal(t, goldenCase.Status, testCase.Status)
	require.NotNil(t, testCase.Failure)
	assert.Equal(t, goldenCase.Failure.Message, testCase.Failure.Message)
	assert.Equal(t, setupErr.Error(), testCase.Failure.Value)
}

func TestWriteNilCollector(t *testing.T) {
	var collector *JUnitCollector
	require.NoError(t, collector.Write())
	collector.RecordInfrastructureFailure(errors.New("setup failed"))
}

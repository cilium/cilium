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

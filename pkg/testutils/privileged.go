// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package testutils

import (
	"os"
	"strings"
	"testing"
)

const (
	privilegedEnv            = "PRIVILEGED_TESTS"
	integrationEnv           = "INTEGRATION_TESTS"
	gatewayAPIConformanceEnv = "GATEWAY_API_CONFORMANCE_TESTS"

	requiredTestPrefix      = "TestPrivileged"
	requiredBenchmarkPrefix = "BenchmarkPrivileged"
)

func PrivilegedTest(tb testing.TB) {
	tb.Helper()
	testName := tb.Name()

	// Check if test name has the required prefix
	switch v := tb.(type) {
	case *testing.T:
		if !hasPrivilegedPrefix(testName, requiredTestPrefix) {
			tb.Fatalf("Privileged tests must have prefix '%s' in their name, got: %s", requiredTestPrefix, testName)
		}
	case *testing.B:
		if !hasPrivilegedPrefix(testName, requiredBenchmarkPrefix) {
			tb.Fatalf("Privileged benchmarks must have prefix '%s' in their name, got: %s", requiredBenchmarkPrefix, testName)
		}
	default:
		tb.Fatalf("Unknown testing type %v", v)
	}

	if os.Getenv(privilegedEnv) == "" {
		tb.Skipf("Set %s to run this test", privilegedEnv)
	}
}

// hasPrivilegedPrefix checks if the test/benchmark name has the TestPrivileged/BenchmarkPrivileged prefix.
// It handles both normal test functions "TestPrivileged*" and subtests that have
// a parent test name included like "TestPrivileged*/SubTest".
func hasPrivilegedPrefix(testName string, requiredPrefix string) bool {
	// Handle regular test function
	if strings.HasPrefix(testName, requiredPrefix) {
		return true
	}

	// Handle subtests (format: ParentTest/SubTest)
	parts := strings.Split(testName, "/")
	if len(parts) > 0 && strings.HasPrefix(parts[0], requiredPrefix) {
		return true
	}

	return false
}

func IsPrivileged() bool {
	return os.Getenv(privilegedEnv) != ""
}

// IntegrationTests returns true if integration tests are requested.
func IntegrationTests() bool {
	return os.Getenv(integrationEnv) != ""
}

// IntegrationTest only executes tb if integration tests are requested.
func IntegrationTest(tb testing.TB) {
	tb.Helper()

	if os.Getenv(integrationEnv) == "" {
		tb.Skipf("Set %s to run this test", integrationEnv)
	}
}

func GatewayAPIConformanceTest(tb testing.TB) {
	tb.Helper()

	if os.Getenv(gatewayAPIConformanceEnv) == "" {
		tb.Skipf("Set %s to run this test", gatewayAPIConformanceEnv)
	}
}

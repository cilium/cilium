// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package testutils

import (
	"os"
	"testing"
)

const (
	privilegedEnv            = "PRIVILEGED_TESTS"
	integrationEnv           = "INTEGRATION_TESTS"
	gatewayAPIConformanceEnv = "GATEWAY_API_CONFORMANCE_TESTS"
)

func PrivilegedTest(tb testing.TB) {
	tb.Helper()

	if os.Getenv(privilegedEnv) == "" {
		tb.Skipf("Set %s to run this test", privilegedEnv)
	}
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

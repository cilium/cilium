// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package testutils

import (
	"fmt"
	"os"
	"testing"

	check "github.com/cilium/checkmate"
)

const (
	privilegedEnv            = "PRIVILEGED_TESTS"
	integrationEnv           = "INTEGRATION_TESTS"
	gatewayAPIConformanceEnv = "GATEWAY_API_CONFORMANCE_TESTS"
)

func PrivilegedTest(tb testing.TB) {
	tb.Helper()

	if os.Getenv(privilegedEnv) == "" {
		tb.Skip(fmt.Sprintf("Set %s to run this test", privilegedEnv))
	}
}

// IntegrationTests returns true if integration tests are requested.
func IntegrationTests() bool {
	if os.Getenv(integrationEnv) != "" {
		return true
	}
	return false
}

// IntegrationTest only executes tb if integration tests are requested.
func IntegrationTest(tb testing.TB) {
	tb.Helper()

	if os.Getenv(integrationEnv) == "" {
		tb.Skip(fmt.Sprintf("Set %s to run this test", integrationEnv))
	}
}

// IntegrationCheck only executes c if integration tests are requested.
func IntegrationCheck(c *check.C) {
	if os.Getenv(integrationEnv) == "" {
		c.Skip(fmt.Sprintf("Set %s to run this test", integrationEnv))
	}
}

func GatewayAPIConformanceTest(tb testing.TB) {
	tb.Helper()

	if os.Getenv(gatewayAPIConformanceEnv) == "" {
		tb.Skip(fmt.Sprintf("Set %s to run this test", gatewayAPIConformanceEnv))
	}
}

// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package testutils

import (
	"fmt"
	"os"
	"testing"

	"gopkg.in/check.v1"
)

const (
	privilegedEnv            = "PRIVILEGED_TESTS"
	gatewayAPIConformanceEnv = "GATEWAY_API_CONFORMANCE_TESTS"
)

func PrivilegedTest(tb testing.TB) {
	tb.Helper()

	if os.Getenv(privilegedEnv) == "" {
		tb.Skip(fmt.Sprintf("Set %s to run this test", privilegedEnv))
	}
}

func PrivilegedCheck(c *check.C) {
	if os.Getenv(privilegedEnv) == "" {
		c.Skip(fmt.Sprintf("Set %s to run this test", privilegedEnv))
	}
}

func GatewayAPIConformanceTest(tb testing.TB) {
	tb.Helper()

	if os.Getenv(gatewayAPIConformanceEnv) == "" {
		tb.Skip(fmt.Sprintf("Set %s to run this test", gatewayAPIConformanceEnv))
	}
}

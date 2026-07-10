// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package testutils

import (
	"testing"

	"github.com/cilium/cilium/pkg/version"
	"github.com/cilium/cilium/pkg/versioncheck"
)

// SkipOnOldKernel skips the test if minVersion is lower than the detected kernel
// version. Parameter feature is mentioned as the reason in the Skip message.
func SkipOnOldKernel(tb testing.TB, minVersion, feature string) {
	tb.Helper()

	v, err := versioncheck.Version(minVersion)
	if err != nil {
		tb.Fatalf("Can't parse version %s: %s", minVersion, err)
	}

	kv, err := version.GetKernelVersion()
	if err != nil {
		tb.Fatalf("Can't get kernel version: %s", err)
	}

	if kv.LT(v) {
		tb.Skipf("Test requires at least kernel %s (missing feature %s)", minVersion, feature)
	}
}

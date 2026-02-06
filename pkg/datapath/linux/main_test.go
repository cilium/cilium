// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package linux_test

import (
	"testing"

	"github.com/cilium/cilium/pkg/testutils"
)

func TestMain(m *testing.M) {
	testutils.GoleakVerifyTestMain(m,
		// When IPSec is enabled, [linuxNodeHandler] attempts to register IPSec metrics.
		// Eventually, [metrics.withRegistry] spawns a goroutine to wait for the registry
		// promise to resolve, but given that it gets never resolved, is is leaked.
		testutils.GoleakIgnoreAnyFunction("github.com/cilium/cilium/pkg/metrics.withRegistry.func1"),
	)
}

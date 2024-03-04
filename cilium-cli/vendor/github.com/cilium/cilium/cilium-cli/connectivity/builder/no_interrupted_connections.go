// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package builder

import (
	"github.com/cilium/cilium/cilium-cli/connectivity/check"
	"github.com/cilium/cilium/cilium-cli/connectivity/tests"
)

type noInterruptedConnections struct{}

func (t noInterruptedConnections) build(ct *check.ConnectivityTest, _ map[string]string) {
	newTest("no-interrupted-connections", ct).
		WithCondition(func() bool { return ct.Params().IncludeConnDisruptTest }).
		WithScenarios(tests.NoInterruptedConnections())
}

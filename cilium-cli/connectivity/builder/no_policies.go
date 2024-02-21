// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package builder

import (
	"github.com/cilium/cilium-cli/connectivity/check"
	"github.com/cilium/cilium-cli/connectivity/tests"
)

type noPolicies struct{}

func (t noPolicies) build(ct *check.ConnectivityTest, _ map[string]string) {
	newTest("no-policies", ct).
		WithScenarios(
			tests.PodToPod(),
			tests.ClientToClient(),
			tests.PodToService(),
			tests.PodToHostPort(),
			tests.PodToWorld(tests.WithRetryAll()),
			tests.PodToHost(),
			tests.HostToPod(),
			tests.PodToExternalWorkload(),
			tests.PodToCIDR(tests.WithRetryAll()),
		)
}

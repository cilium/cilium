// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package builder

import (
	"github.com/cilium/cilium/cilium-cli/connectivity/check"
	tests2 "github.com/cilium/cilium/cilium-cli/connectivity/tests"
)

type noPolicies struct{}

func (t noPolicies) build(ct *check.ConnectivityTest, _ map[string]string) {
	newTest("no-policies", ct).
		WithScenarios(
			tests2.PodToPod(),
			tests2.ClientToClient(),
			tests2.PodToService(),
			tests2.PodToHostPort(),
			tests2.PodToWorld(tests2.WithRetryAll()),
			tests2.PodToHost(),
			tests2.HostToPod(),
			tests2.PodToExternalWorkload(),
			tests2.PodToCIDR(tests2.WithRetryAll()),
		)
}

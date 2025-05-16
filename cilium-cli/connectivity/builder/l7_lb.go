// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package builder

import (
	_ "embed"

	"github.com/cilium/cilium/cilium-cli/connectivity/check"
	"github.com/cilium/cilium/cilium-cli/connectivity/tests"
)

type l7LB struct{}

func (t l7LB) build(ct *check.ConnectivityTest, _ map[string]string) {
	newTest("l7-lb", ct).
		WithScenarios(
			tests.PodToL7Service("hair-pinning", ct.L7LBClientPods()), // hair-pinning to the same pod
			tests.PodToL7Service("", ct.ClientPods())).
		WithExpectations(func(_ *check.Action) (egress, ingress check.Result) {
			return check.ResultOK, check.ResultOK
		})
}

// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package builder

import (
	"github.com/cilium/cilium/cilium-cli/connectivity/check"
	"github.com/cilium/cilium/cilium-cli/connectivity/tests"
)

type serviceLoopback struct{}

func (t serviceLoopback) build(ct *check.ConnectivityTest, _ map[string]string) {
	newTest("pod-to-itself-via-service", ct).
		WithScenarios(tests.PodToItselfViaService()).
		WithExpectations(func(_ *check.Action) (egress, ingress check.Result) {
			return check.ResultOK, check.ResultNone
		})
}

// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package builder

import (
	"github.com/cilium/cilium/cilium-cli/connectivity/check"
	"github.com/cilium/cilium/cilium-cli/connectivity/tests"
	"github.com/cilium/cilium/cilium-cli/utils/features"
)

type clientToItself struct{}

func (t clientToItself) build(ct *check.ConnectivityTest, templates map[string]string) {
	newTest("client-to-itself", ct).
		WithCondition(func() bool {
			return !isSocketLBDisabled(ct)
		}).
		WithScenarios(
			tests.ClientToItself(),
		).
		WithExpectations(func(a *check.Action) (egress, ingress check.Result) {
			return check.ResultOK, check.ResultOK
		})
}

func isSocketLBDisabled(ct *check.ConnectivityTest) bool {
	socketLBDisabled, _ := ct.Features.MatchRequirements(features.RequireDisabled(features.KPRSocketLB))
	return socketLBDisabled
}

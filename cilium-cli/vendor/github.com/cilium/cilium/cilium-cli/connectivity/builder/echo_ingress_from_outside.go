// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package builder

import (
	"github.com/cilium/cilium-cli/utils/features"
	check2 "github.com/cilium/cilium/cilium-cli/connectivity/check"
	"github.com/cilium/cilium/cilium-cli/connectivity/tests"
)

type echoIngressFromOutside struct{}

func (t echoIngressFromOutside) build(ct *check2.ConnectivityTest, _ map[string]string) {
	newTest("echo-ingress-from-outside", ct).
		WithCondition(func() bool { return ct.Params().IncludeUnsafeTests }).
		WithCiliumPolicy(echoIngressFromOtherClientPolicyYAML).
		WithFeatureRequirements(features.RequireEnabled(features.NodeWithoutCilium)).
		WithIPRoutesFromOutsideToPodCIDRs().
		WithScenarios(tests.FromCIDRToPod()).
		WithExpectations(func(a *check2.Action) (egress, ingress check2.Result) {
			if a.Destination().HasLabel("kind", "echo") && !a.Source().HasLabel("other", "client") {
				// TCP handshake fails both in egress and ingress when
				// L3(/L4) policy drops at either location.
				return check2.ResultDropCurlTimeout, check2.ResultDropCurlTimeout
			}
			return check2.ResultOK, check2.ResultOK
		})
}

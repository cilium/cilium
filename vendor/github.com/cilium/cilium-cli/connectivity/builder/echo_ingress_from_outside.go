// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package builder

import (
	"github.com/cilium/cilium-cli/connectivity/check"
	"github.com/cilium/cilium-cli/connectivity/tests"
	"github.com/cilium/cilium-cli/utils/features"
)

type echoIngressFromOutside struct{}

func (t echoIngressFromOutside) build(ct *check.ConnectivityTest, _ map[string]string) {
	newTest("echo-ingress-from-outside", ct).
		WithCondition(func() bool { return ct.Params().IncludeUnsafeTests }).
		WithCiliumPolicy(echoIngressFromOtherClientPolicyYAML).
		WithFeatureRequirements(features.RequireEnabled(features.NodeWithoutCilium)).
		WithIPRoutesFromOutsideToPodCIDRs().
		WithScenarios(tests.FromCIDRToPod()).
		WithExpectations(func(a *check.Action) (egress, ingress check.Result) {
			if a.Destination().HasLabel("kind", "echo") && !a.Source().HasLabel("other", "client") {
				// TCP handshake fails both in egress and ingress when
				// L3(/L4) policy drops at either location.
				return check.ResultDropCurlTimeout, check.ResultDropCurlTimeout
			}
			return check.ResultOK, check.ResultOK
		})
}

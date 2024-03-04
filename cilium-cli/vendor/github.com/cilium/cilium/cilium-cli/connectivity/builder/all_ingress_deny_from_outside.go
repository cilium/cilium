// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package builder

import (
	"github.com/cilium/cilium-cli/utils/features"
	check2 "github.com/cilium/cilium/cilium-cli/connectivity/check"
	"github.com/cilium/cilium/cilium-cli/connectivity/tests"
)

type allIngressDenyFromOutside struct{}

func (t allIngressDenyFromOutside) build(ct *check2.ConnectivityTest, _ map[string]string) {
	newTest("all-ingress-deny-from-outside", ct).
		WithCondition(func() bool { return ct.Params().IncludeUnsafeTests }).
		WithCiliumPolicy(denyAllIngressPolicyYAML).
		WithFeatureRequirements(features.RequireEnabled(features.NodeWithoutCilium)).
		WithIPRoutesFromOutsideToPodCIDRs().
		WithScenarios(tests.FromCIDRToPod()).
		WithExpectations(func(a *check2.Action) (egress, ingress check2.Result) {
			if a.Destination().Address(features.GetIPFamily(ct.Params().ExternalOtherIP)) == ct.Params().ExternalOtherIP ||
				a.Destination().Address(features.GetIPFamily(ct.Params().ExternalIP)) == ct.Params().ExternalIP {
				return check2.ResultOK, check2.ResultNone
			}
			return check2.ResultDrop, check2.ResultDefaultDenyIngressDrop
		})
}

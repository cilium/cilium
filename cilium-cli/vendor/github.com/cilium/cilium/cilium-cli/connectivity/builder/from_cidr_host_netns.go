// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package builder

import (
	"github.com/cilium/cilium-cli/utils/features"
	check2 "github.com/cilium/cilium/cilium-cli/connectivity/check"
	"github.com/cilium/cilium/cilium-cli/connectivity/tests"
)

type fromCidrHostNetns struct{}

func (t fromCidrHostNetns) build(ct *check2.ConnectivityTest, templates map[string]string) {
	newTest("from-cidr-host-netns", ct).
		WithCondition(func() bool { return ct.Params().IncludeUnsafeTests }).
		WithFeatureRequirements(features.RequireEnabled(features.NodeWithoutCilium)).
		WithCiliumPolicy(templates["echoIngressFromCIDRYAML"]).
		WithIPRoutesFromOutsideToPodCIDRs().
		WithScenarios(tests.FromCIDRToPod()).
		WithExpectations(func(_ *check2.Action) (egress, ingress check2.Result) {
			return check2.ResultOK, check2.ResultNone
		})
}

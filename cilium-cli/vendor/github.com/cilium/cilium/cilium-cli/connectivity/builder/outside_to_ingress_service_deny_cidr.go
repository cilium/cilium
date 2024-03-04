// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package builder

import (
	"github.com/cilium/cilium-cli/utils/features"
	check2 "github.com/cilium/cilium/cilium-cli/connectivity/check"
	"github.com/cilium/cilium/cilium-cli/connectivity/tests"
)

type outsideToIngressServiceDenyCidr struct{}

func (t outsideToIngressServiceDenyCidr) build(ct *check2.ConnectivityTest, templates map[string]string) {
	newTest("outside-to-ingress-service-deny-cidr", ct).
		WithFeatureRequirements(
			features.RequireEnabled(features.IngressController),
			features.RequireEnabled(features.NodeWithoutCilium),
		).
		WithCiliumPolicy(templates["denyCIDRPolicyYAML"]).
		WithScenarios(tests.OutsideToIngressService()).
		WithExpectations(func(_ *check2.Action) (egress check2.Result, ingress check2.Result) {
			return check2.ResultDefaultDenyEgressDrop, check2.ResultNone
		})
}

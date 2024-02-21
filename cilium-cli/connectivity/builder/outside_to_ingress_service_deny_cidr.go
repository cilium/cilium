// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package builder

import (
	"github.com/cilium/cilium-cli/connectivity/check"
	"github.com/cilium/cilium-cli/connectivity/tests"
	"github.com/cilium/cilium-cli/utils/features"
)

type outsideToIngressServiceDenyCidr struct{}

func (t outsideToIngressServiceDenyCidr) build(ct *check.ConnectivityTest, templates map[string]string) {
	newTest("outside-to-ingress-service-deny-cidr", ct).
		WithFeatureRequirements(
			features.RequireEnabled(features.IngressController),
			features.RequireEnabled(features.NodeWithoutCilium),
		).
		WithCiliumPolicy(templates["denyCIDRPolicyYAML"]).
		WithScenarios(tests.OutsideToIngressService()).
		WithExpectations(func(_ *check.Action) (egress check.Result, ingress check.Result) {
			return check.ResultDefaultDenyEgressDrop, check.ResultNone
		})
}

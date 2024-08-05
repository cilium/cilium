// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package builder

import (
	"github.com/cilium/cilium/cilium-cli/connectivity/check"
	"github.com/cilium/cilium/cilium-cli/connectivity/tests"
	"github.com/cilium/cilium/cilium-cli/utils/features"
)

type outsideToIngressServiceDenyAllIngress struct{}

func (t outsideToIngressServiceDenyAllIngress) build(ct *check.ConnectivityTest, _ map[string]string) {
	newTest("outside-to-ingress-service-deny-all-ingress", ct).
		WithFeatureRequirements(
			features.RequireEnabled(features.IngressController),
			features.RequireEnabled(features.NodeWithoutCilium),
		).
		WithCiliumPolicy(denyAllIngressPolicyYAML).
		WithScenarios(tests.OutsideToIngressService()).
		WithExpectations(func(_ *check.Action) (egress check.Result, ingress check.Result) {
			return check.ResultDefaultDenyEgressDrop, check.ResultNone
		})
}

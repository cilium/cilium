// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package builder

import (
	"github.com/cilium/cilium-cli/utils/features"
	check2 "github.com/cilium/cilium/cilium-cli/connectivity/check"
	"github.com/cilium/cilium/cilium-cli/connectivity/tests"
)

type podToIngressServiceDenyAll struct{}

func (t podToIngressServiceDenyAll) build(ct *check2.ConnectivityTest, _ map[string]string) {
	newTest("pod-to-ingress-service-deny-all", ct).
		WithFeatureRequirements(features.RequireEnabled(features.IngressController)).
		WithCiliumPolicy(denyAllIngressPolicyYAML).
		WithScenarios(tests.PodToIngress()).
		WithExpectations(func(_ *check2.Action) (egress check2.Result, ingress check2.Result) {
			return check2.ResultDefaultDenyEgressDrop, check2.ResultNone
		})
}

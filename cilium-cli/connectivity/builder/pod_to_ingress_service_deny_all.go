// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package builder

import (
	"github.com/cilium/cilium-cli/connectivity/check"
	"github.com/cilium/cilium-cli/connectivity/tests"
	"github.com/cilium/cilium-cli/utils/features"
)

type podToIngressServiceDenyAll struct{}

func (t podToIngressServiceDenyAll) build(ct *check.ConnectivityTest, _ map[string]string) {
	newTest("pod-to-ingress-service-deny-all", ct).
		WithFeatureRequirements(features.RequireEnabled(features.IngressController)).
		WithCiliumPolicy(denyAllIngressPolicyYAML).
		WithScenarios(tests.PodToIngress()).
		WithExpectations(func(_ *check.Action) (egress check.Result, ingress check.Result) {
			return check.ResultDefaultDenyEgressDrop, check.ResultNone
		})
}

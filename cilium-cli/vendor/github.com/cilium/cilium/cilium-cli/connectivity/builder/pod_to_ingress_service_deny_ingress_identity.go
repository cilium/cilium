// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package builder

import (
	_ "embed"
	check2 "github.com/cilium/cilium/cilium-cli/connectivity/check"
	"github.com/cilium/cilium/cilium-cli/connectivity/tests"

	"github.com/cilium/cilium-cli/utils/features"
)

//go:embed manifests/deny-ingress-entity.yaml
var denyIngressIdentityPolicyYAML string

type podToIngressServiceDenyIngressIdentity struct{}

func (t podToIngressServiceDenyIngressIdentity) build(ct *check2.ConnectivityTest, _ map[string]string) {
	newTest("pod-to-ingress-service-deny-ingress-identity", ct).
		WithFeatureRequirements(features.RequireEnabled(features.IngressController)).
		WithCiliumPolicy(denyIngressIdentityPolicyYAML).
		WithScenarios(tests.PodToIngress()).
		WithExpectations(func(_ *check2.Action) (egress check2.Result, ingress check2.Result) {
			return check2.ResultDefaultDenyEgressDrop, check2.ResultNone
		})
}

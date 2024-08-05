// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package builder

import (
	_ "embed"

	"github.com/cilium/cilium/cilium-cli/connectivity/check"
	"github.com/cilium/cilium/cilium-cli/connectivity/tests"
	"github.com/cilium/cilium/cilium-cli/utils/features"
)

//go:embed manifests/deny-ingress-entity.yaml
var denyIngressIdentityPolicyYAML string

type podToIngressServiceDenyIngressIdentity struct{}

func (t podToIngressServiceDenyIngressIdentity) build(ct *check.ConnectivityTest, _ map[string]string) {
	newTest("pod-to-ingress-service-deny-ingress-identity", ct).
		WithFeatureRequirements(features.RequireEnabled(features.IngressController)).
		WithCiliumPolicy(denyIngressIdentityPolicyYAML).
		WithScenarios(tests.PodToIngress()).
		WithExpectations(func(_ *check.Action) (egress check.Result, ingress check.Result) {
			return check.ResultDefaultDenyEgressDrop, check.ResultNone
		})
}

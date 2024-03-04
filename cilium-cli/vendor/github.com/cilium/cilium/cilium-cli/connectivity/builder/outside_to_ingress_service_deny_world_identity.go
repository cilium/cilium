// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package builder

import (
	_ "embed"
	check2 "github.com/cilium/cilium/cilium-cli/connectivity/check"
	"github.com/cilium/cilium/cilium-cli/connectivity/tests"

	"github.com/cilium/cilium-cli/utils/features"
)

//go:embed manifests/deny-world-entity.yaml
var denyWorldIdentityPolicyYAML string

type outsideToIngressServiceDenyWorldIdentity struct{}

func (t outsideToIngressServiceDenyWorldIdentity) build(ct *check2.ConnectivityTest, _ map[string]string) {
	newTest("outside-to-ingress-service-deny-world-identity", ct).
		WithFeatureRequirements(
			features.RequireEnabled(features.IngressController),
			features.RequireEnabled(features.NodeWithoutCilium),
		).
		WithCiliumPolicy(denyWorldIdentityPolicyYAML).
		WithScenarios(tests.OutsideToIngressService()).
		WithExpectations(func(_ *check2.Action) (egress check2.Result, ingress check2.Result) {
			return check2.ResultDefaultDenyEgressDrop, check2.ResultNone
		})
}

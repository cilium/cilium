// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package builder

import (
	_ "embed"

	"github.com/cilium/cilium-cli/connectivity/check"
	"github.com/cilium/cilium-cli/connectivity/tests"
	"github.com/cilium/cilium-cli/utils/features"
)

//go:embed manifests/deny-world-entity.yaml
var denyWorldIdentityPolicyYAML string

type outsideToIngressServiceDenyWorldIdentity struct{}

func (t outsideToIngressServiceDenyWorldIdentity) build(ct *check.ConnectivityTest, _ map[string]string) {
	newTest("outside-to-ingress-service-deny-world-identity", ct).
		WithFeatureRequirements(
			features.RequireEnabled(features.IngressController),
			features.RequireEnabled(features.NodeWithoutCilium),
		).
		WithCiliumPolicy(denyWorldIdentityPolicyYAML).
		WithScenarios(tests.OutsideToIngressService()).
		WithExpectations(func(_ *check.Action) (egress check.Result, ingress check.Result) {
			return check.ResultDefaultDenyEgressDrop, check.ResultNone
		})
}

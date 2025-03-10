// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package builder

import (
	_ "embed"

	"github.com/cilium/cilium/cilium-cli/connectivity/check"
	"github.com/cilium/cilium/cilium-cli/connectivity/tests"
	"github.com/cilium/cilium/cilium-cli/utils/features"
)

//go:embed manifests/deny-world-entity.yaml
var denyWorldIdentityPolicyYAML string

type outsideToIngressService struct{}

func (t outsideToIngressService) build(ct *check.ConnectivityTest, templates map[string]string) {
	newTest("outside-to-ingress-service", ct).
		WithFeatureRequirements(
			features.RequireEnabled(features.IngressController),
			features.RequireEnabled(features.NodeWithoutCilium)).
		WithScenarios(tests.OutsideToIngressService())

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

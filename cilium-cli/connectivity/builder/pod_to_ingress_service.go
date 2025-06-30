// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package builder

import (
	_ "embed"
	"strings"

	"github.com/cilium/cilium/cilium-cli/connectivity/check"
	"github.com/cilium/cilium/cilium-cli/connectivity/tests"
	"github.com/cilium/cilium/cilium-cli/utils/features"
)

var (
	//go:embed manifests/allow-ingress-identity.yaml
	allowIngressIdentityPolicyYAML string

	//go:embed manifests/deny-ingress-backend.yaml
	denyIngressBackendPolicyYAML string

	//go:embed manifests/deny-ingress-entity.yaml
	denyIngressIdentityPolicyYAML string

	//go:embed manifests/deny-ingress-source-egress-other-node.yaml
	denyIngressSourceEgressOtherNodePolicyYML string
)

type podToIngressService struct{}

func (t podToIngressService) build(ct *check.ConnectivityTest, templates map[string]string) {
	// Test Ingress controller
	newTest("pod-to-ingress-service", ct).
		WithFeatureRequirements(features.RequireEnabled(features.IngressController)).
		WithScenarios(tests.PodToIngress())

	newTest("pod-to-ingress-service-allow-ingress-identity", ct).
		WithFeatureRequirements(features.RequireEnabled(features.IngressController)).
		WithCiliumPolicy(denyAllIngressPolicyYAML).
		WithCiliumPolicy(allowIngressIdentityPolicyYAML).
		WithScenarios(tests.PodToIngress())

	newTest("pod-to-ingress-service-deny-all", ct).
		WithFeatureRequirements(features.RequireEnabled(features.IngressController)).
		WithCiliumPolicy(denyAllIngressPolicyYAML).
		WithScenarios(tests.PodToIngress()).
		WithExpectations(func(_ *check.Action) (egress check.Result, ingress check.Result) {
			return check.ResultDefaultDenyEgressDrop, check.ResultNone
		})

	newTest("pod-to-ingress-service-deny-backend-service", ct).
		WithFeatureRequirements(features.RequireEnabled(features.IngressController)).
		WithCiliumPolicy(denyIngressBackendPolicyYAML).
		WithScenarios(tests.PodToIngress()).
		WithExpectations(func(_ *check.Action) (egress check.Result, ingress check.Result) {
			return check.ResultDefaultDenyEgressDrop, check.ResultNone
		})

	newTest("pod-to-ingress-service-deny-ingress-identity", ct).
		WithFeatureRequirements(features.RequireEnabled(features.IngressController)).
		WithCiliumPolicy(denyIngressIdentityPolicyYAML).
		WithScenarios(tests.PodToIngress()).
		WithExpectations(func(_ *check.Action) (egress check.Result, ingress check.Result) {
			return check.ResultDefaultDenyEgressDrop, check.ResultNone
		})

	newTest("pod-to-ingress-service-deny-source-egress-other-node", ct).
		WithCiliumVersion(">1.17.1 || >1.16.7 <1.17.0 || >1.15.14 <1.16.0").
		WithFeatureRequirements(features.RequireEnabled(features.IngressController)).
		WithCiliumPolicy(denyIngressSourceEgressOtherNodePolicyYML).
		WithCiliumPolicy(templates["clientEgressOnlyDNSPolicyYAML"]). // DNS resolution only
		WithScenarios(tests.PodToIngress()).
		WithExpectations(func(a *check.Action) (egress check.Result, ingress check.Result) {
			if strings.Contains(a.Destination().Name(), "cilium-ingress-same-node") {
				return check.ResultOK, check.ResultOK
			}
			return check.ResultDefaultDenyEgressDrop, check.ResultNone
		})
}

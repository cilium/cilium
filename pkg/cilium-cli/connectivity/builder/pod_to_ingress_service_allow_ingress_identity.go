// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package builder

import (
	_ "embed"

	"github.com/cilium/cilium-cli/utils/features"

	"github.com/cilium/cilium/pkg/cilium-cli/connectivity/check"
	"github.com/cilium/cilium/pkg/cilium-cli/connectivity/tests"
)

//go:embed manifests/allow-ingress-identity.yaml
var allowIngressIdentityPolicyYAML string

type podToIngressServiceAllowIngressIdentity struct{}

func (t podToIngressServiceAllowIngressIdentity) build(ct *check.ConnectivityTest, _ map[string]string) {
	newTest("pod-to-ingress-service-allow-ingress-identity", ct).
		WithFeatureRequirements(features.RequireEnabled(features.IngressController)).
		WithCiliumPolicy(denyAllIngressPolicyYAML).
		WithCiliumPolicy(allowIngressIdentityPolicyYAML).
		WithScenarios(tests.PodToIngress())
}

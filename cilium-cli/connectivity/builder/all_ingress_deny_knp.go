// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package builder

import (
	_ "embed"

	"github.com/cilium/cilium-cli/connectivity/check"
	"github.com/cilium/cilium-cli/connectivity/tests"
	"github.com/cilium/cilium-cli/utils/features"
)

//go:embed manifests/deny-all-ingress-knp.yaml
var denyAllIngressPolicyKNPYAML string

type allIngressDenyKnp struct{}

func (t allIngressDenyKnp) build(ct *check.ConnectivityTest, _ map[string]string) {
	// This policy denies all ingresses by default
	newTest("all-ingress-deny-knp", ct).
		WithK8SPolicy(denyAllIngressPolicyKNPYAML).
		WithScenarios(
			// Pod to Pod fails because there is no egress policy (so egress traffic originating from a pod is allowed),
			// but then at the destination there is ingress policy that denies the traffic.
			tests.PodToPod(),
			// Egress to world works because there is no egress policy (so egress traffic originating from a pod is allowed),
			// then when replies come back, they are considered as "replies" to the outbound connection.
			// so they are not subject to ingress policy.
			tests.PodToCIDR(tests.WithRetryAll()),
		).
		WithExpectations(func(a *check.Action) (egress, ingress check.Result) {
			if a.Destination().Address(features.GetIPFamily(ct.Params().ExternalOtherIP)) == ct.Params().ExternalOtherIP ||
				a.Destination().Address(features.GetIPFamily(ct.Params().ExternalIP)) == ct.Params().ExternalIP {
				return check.ResultOK, check.ResultNone
			}
			return check.ResultDrop, check.ResultDefaultDenyIngressDrop
		})
}

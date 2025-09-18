// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package builder

import (
	"github.com/cilium/cilium/cilium-cli/connectivity/check"
	"github.com/cilium/cilium/cilium-cli/connectivity/tests"
	"github.com/cilium/cilium/cilium-cli/utils/features"
)

type toCidrExternalKnp struct{}

func (t toCidrExternalKnp) build(ct *check.ConnectivityTest, templates map[string]string) {
	// This policy allows L3 traffic to ExternalCIDR/24 (including ExternalIP), with the
	// exception of ExternalOtherIP.
	newTest("to-cidr-external-knp", ct).
		WithK8SPolicy(templates["clientEgressToCIDRExternalPolicyKNPYAML"]).
		WithScenarios(
			tests.PodToCIDR(tests.WithRetryDestIP(ct.Params().ExternalIPv4)),
		).
		WithExpectations(func(a *check.Action) (egress, ingress check.Result) {
			if a.Destination().Address(features.IPFamilyV4) == ct.Params().ExternalOtherIPv4 ||
				a.Destination().Address(features.IPFamilyV6) == ct.Params().ExternalOtherIPv6 {
				// Expect packets for ExternalOtherIP to be dropped.
				return check.ResultDropCurlTimeout, check.ResultNone
			}
			return check.ResultOK, check.ResultNone
		})
}

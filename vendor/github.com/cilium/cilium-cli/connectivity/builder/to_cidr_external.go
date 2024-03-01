// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package builder

import (
	"github.com/cilium/cilium-cli/connectivity/check"
	"github.com/cilium/cilium-cli/connectivity/tests"
	"github.com/cilium/cilium-cli/utils/features"
)

type toCidrExternal struct{}

func (t toCidrExternal) build(ct *check.ConnectivityTest, templates map[string]string) {
	// This policy allows L3 traffic to ExternalCIDR/24 (including ExternalIP), with the
	// exception of ExternalOtherIP.
	newTest("to-cidr-external", ct).
		WithCiliumPolicy(templates["clientEgressToCIDRExternalPolicyYAML"]).
		WithScenarios(
			tests.PodToCIDR(tests.WithRetryDestIP(ct.Params().ExternalIP)),
		).
		WithExpectations(func(a *check.Action) (egress, ingress check.Result) {
			if a.Destination().Address(features.IPFamilyV4) == ct.Params().ExternalOtherIP {
				// Expect packets for ExternalOtherIP to be dropped.
				return check.ResultDropCurlTimeout, check.ResultNone
			}
			return check.ResultOK, check.ResultNone
		})
}

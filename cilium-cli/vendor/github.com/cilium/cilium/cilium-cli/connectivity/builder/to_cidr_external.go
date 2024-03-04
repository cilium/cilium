// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package builder

import (
	"github.com/cilium/cilium-cli/utils/features"
	check2 "github.com/cilium/cilium/cilium-cli/connectivity/check"
	tests2 "github.com/cilium/cilium/cilium-cli/connectivity/tests"
)

type toCidrExternal struct{}

func (t toCidrExternal) build(ct *check2.ConnectivityTest, templates map[string]string) {
	// This policy allows L3 traffic to ExternalCIDR/24 (including ExternalIP), with the
	// exception of ExternalOtherIP.
	newTest("to-cidr-external", ct).
		WithCiliumPolicy(templates["clientEgressToCIDRExternalPolicyYAML"]).
		WithScenarios(
			tests2.PodToCIDR(tests2.WithRetryDestIP(ct.Params().ExternalIP)),
		).
		WithExpectations(func(a *check2.Action) (egress, ingress check2.Result) {
			if a.Destination().Address(features.IPFamilyV4) == ct.Params().ExternalOtherIP {
				// Expect packets for ExternalOtherIP to be dropped.
				return check2.ResultDropCurlTimeout, check2.ResultNone
			}
			return check2.ResultOK, check2.ResultNone
		})
}

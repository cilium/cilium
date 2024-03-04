// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package builder

import (
	"github.com/cilium/cilium-cli/utils/features"
	check2 "github.com/cilium/cilium/cilium-cli/connectivity/check"
	tests2 "github.com/cilium/cilium/cilium-cli/connectivity/tests"
)

type clientEgressToCidrDeny struct{}

func (t clientEgressToCidrDeny) build(ct *check2.ConnectivityTest, templates map[string]string) {
	// This policy denies L3 traffic to ExternalCIDR except ExternalIP/32
	newTest("client-egress-to-cidr-deny", ct).
		WithCiliumPolicy(allowAllEgressPolicyYAML). // Allow all egress traffic
		WithCiliumPolicy(templates["clientEgressToCIDRExternalDenyPolicyYAML"]).
		WithScenarios(
			tests2.PodToCIDR(tests2.WithRetryDestIP(ct.Params().ExternalIP)), // Denies all traffic to ExternalOtherIP, but allow ExternalIP
		).
		WithExpectations(func(a *check2.Action) (egress, ingress check2.Result) {
			if a.Destination().Address(features.GetIPFamily(ct.Params().ExternalOtherIP)) == ct.Params().ExternalOtherIP {
				return check2.ResultPolicyDenyEgressDrop, check2.ResultNone
			}
			if a.Destination().Address(features.GetIPFamily(ct.Params().ExternalIP)) == ct.Params().ExternalIP {
				return check2.ResultOK, check2.ResultNone
			}
			return check2.ResultDrop, check2.ResultDrop
		})
}

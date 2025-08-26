// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package builder

import (
	"github.com/cilium/cilium/cilium-cli/connectivity/check"
	"github.com/cilium/cilium/cilium-cli/connectivity/tests"
	"github.com/cilium/cilium/cilium-cli/utils/features"
)

type clientEgressToCidrDeny struct{}

func (t clientEgressToCidrDeny) build(ct *check.ConnectivityTest, templates map[string]string) {
	// This policy denies L3 traffic to ExternalCIDR except ExternalIP/32
	newTest("client-egress-to-cidr-deny", ct).
		WithCiliumPolicy(allowAllEgressPolicyYAML). // Allow all egress traffic
		WithCiliumPolicy(templates["clientEgressToCIDRExternalDenyPolicyYAML"]).
		WithScenarios(
			tests.PodToCIDR(tests.WithRetryDestIP(ct.Params().ExternalIPv4)), // Denies all traffic to ExternalOtherIP, but allow ExternalIP
		).
		WithExpectations(func(a *check.Action) (egress, ingress check.Result) {
			if a.Destination().Address(features.GetIPFamily(ct.Params().ExternalOtherIPv4)) == ct.Params().ExternalOtherIPv4 ||
				a.Destination().Address(features.GetIPFamily(ct.Params().ExternalOtherIPv6)) == ct.Params().ExternalOtherIPv6 {
				return check.ResultPolicyDenyEgressDrop, check.ResultNone
			}
			if a.Destination().Address(features.GetIPFamily(ct.Params().ExternalIPv4)) == ct.Params().ExternalIPv4 ||
				a.Destination().Address(features.GetIPFamily(ct.Params().ExternalIPv6)) == ct.Params().ExternalIPv6 {
				return check.ResultOK, check.ResultNone
			}
			return check.ResultDrop, check.ResultDrop
		})
}

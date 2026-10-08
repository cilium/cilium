// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package builder

import (
	"github.com/cilium/cilium/cilium-cli/connectivity/check"
	"github.com/cilium/cilium/cilium-cli/connectivity/tests"
	"github.com/cilium/cilium/cilium-cli/utils/features"
)

type clientEgressToCidrDenyDefault struct{}

func (t clientEgressToCidrDenyDefault) build(ct *check.ConnectivityTest, templates map[string]string) {
	// This test is same as the previous one, but there is no allowed policy.
	// The goal is to test default deny policy
	newTest("client-egress-to-cidr-deny-default", ct).
		WithCiliumPolicy(templates["clientEgressToCIDRExternalDenyPolicyYAML"]).
		WithScenarios(tests.PodToCIDR()). // Denies all traffic to ExternalOtherIP, but allow ExternalIP
		WithExpectations(func(a *check.Action) (egress, ingress check.Result) {
			if a.Destination().Address(features.GetIPFamily(ct.Params().ExternalOtherIPv4)) == ct.Params().ExternalOtherIPv4 ||
				a.Destination().Address(features.GetIPFamily(ct.Params().ExternalOtherIPv6)) == ct.Params().ExternalOtherIPv6 {
				return check.ResultPolicyDenyEgressDrop, check.ResultNone
			}
			if a.Destination().Address(features.GetIPFamily(ct.Params().ExternalIPv4)) == ct.Params().ExternalIPv4 ||
				a.Destination().Address(features.GetIPFamily(ct.Params().ExternalIPv6)) == ct.Params().ExternalIPv6 {
				return check.ResultDefaultDenyEgressDrop, check.ResultNone
			}
			return check.ResultDrop, check.ResultDrop
		})
}

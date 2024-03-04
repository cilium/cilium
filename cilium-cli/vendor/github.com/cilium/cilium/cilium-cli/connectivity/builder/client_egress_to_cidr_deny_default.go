// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package builder

import (
	"github.com/cilium/cilium-cli/utils/features"
	check2 "github.com/cilium/cilium/cilium-cli/connectivity/check"
	"github.com/cilium/cilium/cilium-cli/connectivity/tests"
)

type clientEgressToCidrDenyDefault struct{}

func (t clientEgressToCidrDenyDefault) build(ct *check2.ConnectivityTest, templates map[string]string) {
	// This test is same as the previous one, but there is no allowed policy.
	// The goal is to test default deny policy
	newTest("client-egress-to-cidr-deny-default", ct).
		WithCiliumPolicy(templates["clientEgressToCIDRExternalDenyPolicyYAML"]).
		WithScenarios(tests.PodToCIDR()). // Denies all traffic to ExternalOtherIP, but allow ExternalIP
		WithExpectations(func(a *check2.Action) (egress, ingress check2.Result) {
			if a.Destination().Address(features.GetIPFamily(ct.Params().ExternalOtherIP)) == ct.Params().ExternalOtherIP {
				return check2.ResultPolicyDenyEgressDrop, check2.ResultNone
			}
			if a.Destination().Address(features.GetIPFamily(ct.Params().ExternalIP)) == ct.Params().ExternalIP {
				return check2.ResultDefaultDenyEgressDrop, check2.ResultNone
			}
			return check2.ResultDrop, check2.ResultDrop
		})
}

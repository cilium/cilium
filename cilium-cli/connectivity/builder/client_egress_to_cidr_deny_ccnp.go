// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package builder

import (
	"github.com/cilium/cilium/cilium-cli/connectivity/check"
	"github.com/cilium/cilium/cilium-cli/connectivity/tests"
	"github.com/cilium/cilium/cilium-cli/utils/features"
)

type clientEgressToCidrDenyCCNP struct{}

func (t clientEgressToCidrDenyCCNP) build(ct *check.ConnectivityTest, templates map[string]string) {
	newTest("client-egress-to-cidr-deny-ccnp", ct).
		WithCiliumClusterwidePolicy(allowAllEgressPolicyYAML). 
		WithCiliumClusterwidePolicy(templates["clientEgressToCIDRExternalDenyCCNPPolicyYAML"]).
		WithScenarios(
			tests.PodToCIDR(tests.WithRetryDestIP(ct.Params().ExternalIP)), 
		).
		WithExpectations(func(a *check.Action) (egress, ingress check.Result) {
			if a.Destination().Address(features.GetIPFamily(ct.Params().ExternalOtherIP)) == ct.Params().ExternalOtherIP {
				return check.ResultPolicyDenyEgressDrop, check.ResultNone
			}
			if a.Destination().Address(features.GetIPFamily(ct.Params().ExternalIP)) == ct.Params().ExternalIP {
				return check.ResultOK, check.ResultNone
			}
			return check.ResultDrop, check.ResultDrop
		})
}

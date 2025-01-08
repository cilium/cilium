// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package builder

import (
	_ "embed"

	"github.com/cilium/cilium/cilium-cli/connectivity/check"
	"github.com/cilium/cilium/cilium-cli/connectivity/tests"
)

//go:embed manifests/client-egress-to-echo-named-port-deny-ccnp.yaml
var clientEgressToEchoDenyNamedCCNPPortPolicyYAML string

type clientIngressToEchoNamedPortDenyCCNP struct{}

func (t clientIngressToEchoNamedPortDenyCCNP) build(ct *check.ConnectivityTest, _ map[string]string) {
	newTest("client-ingress-to-echo-named-port-deny-ccnp", ct).
		WithCiliumClusterwidePolicy(allowAllEgressCCNPPolicyYAML).  
		WithCiliumClusterwidePolicy(allowAllIngressCCNPPolicyYAML). 
		WithCiliumClusterwidePolicy(clientEgressToEchoDenyNamedCCNPPortPolicyYAML).
		WithScenarios(
			tests.PodToPod(tests.WithSourceLabelsOption(clientLabel)),  //client -> echo should be denied
			tests.PodToPod(tests.WithSourceLabelsOption(client2Label)), //client2 -> echo should be allowed
		).
		WithExpectations(func(a *check.Action) (egress, ingress check.Result) {
			if a.Destination().HasLabel("kind", "echo") && a.Source().HasLabel("name", "client") {
				return check.ResultDropCurlTimeout, check.ResultPolicyDenyIngressDrop
			}
			return check.ResultOK, check.ResultOK
		})
}

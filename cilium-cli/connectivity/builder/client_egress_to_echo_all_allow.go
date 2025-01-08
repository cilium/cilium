// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package builder

import (
	_ "embed"

	"github.com/cilium/cilium/cilium-cli/connectivity/check"
	"github.com/cilium/cilium/cilium-cli/connectivity/tests"

)

//go:embed manifests/client-egress-to-echo-allow.yaml
var clientEgressToEchoAllAllowPolicyYAML string


type clientEgressToEchoAllAllow struct{}

func (t clientEgressToEchoAllAllow) build(ct *check.ConnectivityTest, _ map[string]string) {

	// This policy allows port 8080 from client to echo (using label match expression), but allows traffic from client2
	newTest("client-egress-to-echo-multipolicy-allow", ct).
		WithCiliumClusterwidePolicy(allowAllEgressCCNPPolicyYAML).  // Allow all egress traffic ccnp
		WithCiliumPolicy(allowAllIngressPolicyYAML). // Allow all ingress traffic cnp
		WithCiliumPolicy(clientEgressToEchoAllAllowPolicyYAML).
		WithScenarios(
			tests.PodToPod(tests.WithSourceLabelsOption(clientLabel)),  //client -> echo should be allowed
			tests.PodToPod(tests.WithSourceLabelsOption(client2Label)), //client2 -> echo should be allowed
			
		).
		WithExpectations(func(a *check.Action) (egress, ingress check.Result) {
			if a.Destination().HasLabel("kind", "echo") &&
				a.Source().HasLabel("name", "client") && a.Destination().Port() == 8080  {
				return check.ResultOK, check.ResultNone
			}
			return check.ResultOK, check.ResultOK
		})
	

}



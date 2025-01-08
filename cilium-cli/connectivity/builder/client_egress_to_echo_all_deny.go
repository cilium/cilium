// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package builder

import (
	_ "embed"

	"github.com/cilium/cilium/cilium-cli/connectivity/check"
	"github.com/cilium/cilium/cilium-cli/connectivity/tests"

)

//go:embed manifests/client-egress-to-echo-deny.yaml
var clientEgressToEchoAllDenyPolicyYAML string


type clientEgressToEchoAllDeny struct{}

func (t clientEgressToEchoAllDeny) build(ct *check.ConnectivityTest, _ map[string]string) {

	newTest("client-egress-to-echo-multipolicy-deny", ct).
		WithCiliumClusterwidePolicy(denyAllEgressCCNPPolicyYAML).  // Deny all egress traffic ccnp
		WithCiliumClusterwidePolicy(denyAllIngressCCNPPolicyYAML). // Deny all ingress traffic ccnp
		WithCiliumPolicy(denyAllIngressPolicyYAML). //Deny all ingress traffic cnp
		WithCiliumPolicy(clientEgressToEchoAllDenyPolicyYAML). //Egress policy cnp 
		WithScenarios(
			tests.PodToPod(tests.WithSourceLabelsOption(clientLabel)),  //client -> echo should be denied
			tests.PodToPod(tests.WithSourceLabelsOption(client2Label)), //client2 -> echo should be denied
			
		).
		WithExpectations(func(a *check.Action) (egress, ingress check.Result) {
            if a.Destination().HasLabel("kind", "echo") {
                return check.ResultPolicyDenyEgressDrop, check.ResultNone
            }
            return check.ResultOK, check.ResultNone
		})
	

}



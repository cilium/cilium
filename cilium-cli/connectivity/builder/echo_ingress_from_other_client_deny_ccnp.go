// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package builder

import (
	_ "embed"

	"github.com/cilium/cilium/cilium-cli/connectivity/check"
	"github.com/cilium/cilium/cilium-cli/connectivity/tests"
)

//go:embed manifests/echo-ingress-from-other-client-deny-ccnp.yaml
var echoIngressFromOtherClientDenyCCNPPolicyYAML string

type echoIngressFromOtherClientDenyCCNP struct{}

func (t echoIngressFromOtherClientDenyCCNP) build(ct *check.ConnectivityTest, _ map[string]string) {
	// Tests with deny policy
	newTest("echo-ingress-from-other-client-deny-ccnp", ct).
		WithCiliumClusterwidePolicy(allowAllEgressCCNPPolicyYAML).              
		WithCiliumClusterwidePolicy(allowAllIngressCCNPPolicyYAML).              
		WithCiliumClusterwidePolicy(echoIngressFromOtherClientDenyCCNPPolicyYAML). 
		WithScenarios(
			tests.PodToPod(tests.WithSourceLabelsOption(clientLabel)),  //client -> echo should be allowed
			tests.PodToPod(tests.WithSourceLabelsOption(client2Label)), //client2 -> echo should be denied
			tests.ClientToClient(), //client -> client should be allowed
		).
		WithExpectations(func(a *check.Action) (egress, ingress check.Result) {
			if a.Source().HasLabel("other", "client") && a.Destination().HasLabel("kind", "echo") {
				return check.ResultDrop, check.ResultPolicyDenyIngressDrop
			}
			return check.ResultOK, check.ResultOK
		})
}

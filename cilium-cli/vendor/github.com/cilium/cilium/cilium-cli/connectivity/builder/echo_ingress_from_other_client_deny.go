// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package builder

import (
	_ "embed"
	check2 "github.com/cilium/cilium/cilium-cli/connectivity/check"
	tests2 "github.com/cilium/cilium/cilium-cli/connectivity/tests"
)

//go:embed manifests/echo-ingress-from-other-client-deny.yaml
var echoIngressFromOtherClientDenyPolicyYAML string

type echoIngressFromOtherClientDeny struct{}

func (t echoIngressFromOtherClientDeny) build(ct *check2.ConnectivityTest, _ map[string]string) {
	// Tests with deny policy
	newTest("echo-ingress-from-other-client-deny", ct).
		WithCiliumPolicy(allowAllEgressPolicyYAML).                 // Allow all egress traffic
		WithCiliumPolicy(allowAllIngressPolicyYAML).                // Allow all ingress traffic
		WithCiliumPolicy(echoIngressFromOtherClientDenyPolicyYAML). // Deny other client contact echo
		WithScenarios(
			tests2.PodToPod(tests2.WithSourceLabelsOption(clientLabel)),  // Client to echo should be allowed
			tests2.PodToPod(tests2.WithSourceLabelsOption(client2Label)), // Client2 to echo should be denied
			tests2.ClientToClient(), // Client to client should be allowed
		).
		WithExpectations(func(a *check2.Action) (egress, ingress check2.Result) {
			if a.Source().HasLabel("other", "client") && a.Destination().HasLabel("kind", "echo") {
				return check2.ResultDrop, check2.ResultPolicyDenyIngressDrop
			}
			return check2.ResultOK, check2.ResultOK
		})
}

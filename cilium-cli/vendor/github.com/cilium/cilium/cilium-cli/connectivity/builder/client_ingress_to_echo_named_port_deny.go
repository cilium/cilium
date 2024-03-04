// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package builder

import (
	_ "embed"
	check2 "github.com/cilium/cilium/cilium-cli/connectivity/check"
	tests2 "github.com/cilium/cilium/cilium-cli/connectivity/tests"
)

//go:embed manifests/client-egress-to-echo-named-port-deny.yaml
var clientEgressToEchoDenyNamedPortPolicyYAML string

type clientIngressToEchoNamedPortDeny struct{}

func (t clientIngressToEchoNamedPortDeny) build(ct *check2.ConnectivityTest, _ map[string]string) {
	// This policy denies port http-8080 from client to echo, but allows traffic from client2 to echo
	newTest("client-ingress-to-echo-named-port-deny", ct).
		WithCiliumPolicy(allowAllEgressPolicyYAML).  // Allow all egress traffic
		WithCiliumPolicy(allowAllIngressPolicyYAML). // Allow all ingress traffic
		WithCiliumPolicy(clientEgressToEchoDenyNamedPortPolicyYAML).
		WithScenarios(
			tests2.PodToPod(tests2.WithSourceLabelsOption(clientLabel)),  // Client to echo should be denied
			tests2.PodToPod(tests2.WithSourceLabelsOption(client2Label)), // Client2 to echo should be allowed
		).
		WithExpectations(func(a *check2.Action) (egress, ingress check2.Result) {
			if a.Destination().HasLabel("kind", "echo") && a.Source().HasLabel("name", "client") {
				return check2.ResultDropCurlTimeout, check2.ResultPolicyDenyIngressDrop
			}
			return check2.ResultOK, check2.ResultOK
		})
}

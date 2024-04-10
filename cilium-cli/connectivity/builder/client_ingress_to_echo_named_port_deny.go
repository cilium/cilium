// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package builder

import (
	_ "embed"

	"github.com/cilium/cilium-cli/connectivity/check"
	"github.com/cilium/cilium-cli/connectivity/tests"
)

//go:embed manifests/client-egress-to-echo-named-port-deny.yaml
var clientEgressToEchoDenyNamedPortPolicyYAML string

type clientIngressToEchoNamedPortDeny struct{}

func (t clientIngressToEchoNamedPortDeny) build(ct *check.ConnectivityTest, _ map[string]string) {
	// This policy denies port http-8080 from client to echo, but allows traffic from client2 to echo
	newTest("client-ingress-to-echo-named-port-deny", ct).
		WithCiliumPolicy(allowAllEgressPolicyYAML).  // Allow all egress traffic
		WithCiliumPolicy(allowAllIngressPolicyYAML). // Allow all ingress traffic
		WithCiliumPolicy(clientEgressToEchoDenyNamedPortPolicyYAML).
		WithScenarios(
			tests.PodToPod(tests.WithSourceLabelsOption(clientLabel)),  // Client to echo should be denied
			tests.PodToPod(tests.WithSourceLabelsOption(client2Label)), // Client2 to echo should be allowed
		).
		WithExpectations(func(a *check.Action) (egress, ingress check.Result) {
			if a.Destination().HasLabel("kind", "echo") && a.Source().HasLabel("name", "client") {
				return check.ResultDropCurlTimeout, check.ResultPolicyDenyIngressDrop
			}
			return check.ResultOK, check.ResultOK
		})
}

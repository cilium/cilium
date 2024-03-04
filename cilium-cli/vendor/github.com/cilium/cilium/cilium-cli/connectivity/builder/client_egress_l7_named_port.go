// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package builder

import (
	"github.com/cilium/cilium-cli/utils/features"
	check2 "github.com/cilium/cilium/cilium-cli/connectivity/check"
	tests2 "github.com/cilium/cilium/cilium-cli/connectivity/tests"
)

type clientEgressL7NamedPort struct{}

func (t clientEgressL7NamedPort) build(ct *check2.ConnectivityTest, templates map[string]string) {
	// Test L7 HTTP named port introspection using an egress policy on the clients.
	newTest("client-egress-l7-named-port", ct).
		WithFeatureRequirements(features.RequireEnabled(features.L7Proxy)).
		WithCiliumPolicy(clientEgressOnlyDNSPolicyYAML).                      // DNS resolution only
		WithCiliumPolicy(templates["clientEgressL7HTTPNamedPortPolicyYAML"]). // L7 allow policy with HTTP introspection (named port)
		WithScenarios(
			tests2.PodToPod(),
			tests2.PodToWorld(tests2.WithRetryDestPort(80), tests2.WithRetryPodLabel("other", "client")),
		).
		WithExpectations(func(a *check2.Action) (egress, ingress check2.Result) {
			if a.Source().HasLabel("other", "client") && // Only client2 is allowed to make HTTP calls.
				// Outbound HTTP to domain-name, default one.one.one.one, is L7-introspected and allowed.
				(a.Destination().Port() == 80 && a.Destination().Address(features.GetIPFamily(ct.Params().ExternalTarget)) == ct.Params().ExternalTarget ||
					a.Destination().Port() == 8080) { // named port http-8080 is traffic to echo Pod.
				if a.Destination().Path() == "/" || a.Destination().Path() == "" {
					egress = check2.ResultOK
					// Expect all curls from client2 to be proxied and to be GET calls.
					egress.HTTP = check2.HTTP{
						Method: "GET",
					}
					return egress, check2.ResultNone
				}
				// Else expect HTTP drop by proxy
				return check2.ResultDNSOKDropCurlHTTPError, check2.ResultNone
			}
			return check2.ResultDefaultDenyEgressDrop, check2.ResultNone
		})
}

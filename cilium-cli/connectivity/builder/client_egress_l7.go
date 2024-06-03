// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package builder

import (
	"github.com/cilium/cilium-cli/connectivity/check"
	"github.com/cilium/cilium-cli/connectivity/tests"
	"github.com/cilium/cilium-cli/utils/features"
)

type clientEgressL7 struct{}

func (t clientEgressL7) build(ct *check.ConnectivityTest, templates map[string]string) {
	clientEgressL7Test(ct, templates, false)
	if ct.Features[features.PortRanges].Enabled {
		clientEgressL7Test(ct, templates, true)
	}
}

func clientEgressL7Test(ct *check.ConnectivityTest, templates map[string]string, portRanges bool) {
	testName := "client-egress-l7"
	templateName := "clientEgressL7HTTPPolicyYAML"
	if portRanges {
		testName = "client-egress-l7-port-range"
		templateName = "clientEgressL7HTTPPolicyPortRangeYAML"
	}
	// Test L7 HTTP introspection using an egress policy on the clients.
	newTest(testName, ct).
		WithFeatureRequirements(features.RequireEnabled(features.L7Proxy)).
		WithCiliumPolicy(clientEgressOnlyDNSPolicyYAML). // DNS resolution only
		WithCiliumPolicy(templates[templateName]).       // L7 allow policy with HTTP introspection
		WithScenarios(
			tests.PodToPod(),
			tests.PodToWorld(tests.WithRetryDestPort(80), tests.WithRetryPodLabel("other", "client")),
		).
		WithExpectations(func(a *check.Action) (egress, ingress check.Result) {
			if a.Source().HasLabel("other", "client") && // Only client2 is allowed to make HTTP calls.
				// Outbound HTTP to set domain-name defaults to one.one.one.one is L7-introspected and allowed.
				(a.Destination().Port() == 80 && a.Destination().Address(features.GetIPFamily(ct.Params().ExternalTarget)) == ct.Params().ExternalTarget ||
					a.Destination().Port() == 8080) { // 8080 is traffic to echo Pod.
				if a.Destination().Path() == "/" || a.Destination().Path() == "" {
					egress = check.ResultOK
					// Expect all curls from client2 to be proxied and to be GET calls.
					egress.HTTP = check.HTTP{
						Method: "GET",
					}
					return egress, check.ResultNone
				}
				// Else expect HTTP drop by proxy
				return check.ResultDNSOKDropCurlHTTPError, check.ResultNone
			}
			return check.ResultDefaultDenyEgressDrop, check.ResultNone
		})
}

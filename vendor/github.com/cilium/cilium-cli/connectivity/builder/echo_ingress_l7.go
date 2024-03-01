// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package builder

import (
	_ "embed"

	"github.com/cilium/cilium-cli/connectivity/check"
	"github.com/cilium/cilium-cli/connectivity/tests"
	"github.com/cilium/cilium-cli/utils/features"
)

//go:embed manifests/echo-ingress-l7-http.yaml
var echoIngressL7HTTPPolicyYAML string

type echoIngressL7 struct{}

func (t echoIngressL7) build(ct *check.ConnectivityTest, _ map[string]string) {
	// Test L7 HTTP introspection using an ingress policy on echo pods.
	newTest("echo-ingress-l7", ct).
		WithFeatureRequirements(features.RequireEnabled(features.L7Proxy)).
		WithCiliumPolicy(echoIngressL7HTTPPolicyYAML). // L7 allow policy with HTTP introspection
		WithScenarios(tests.PodToPodWithEndpoints()).
		WithExpectations(func(a *check.Action) (egress, ingress check.Result) {
			if a.Source().HasLabel("other", "client") { // Only client2 is allowed to make HTTP calls.
				// Trying to access private endpoint without "secret" header set
				// should lead to a drop.
				if a.Destination().Path() == "/private" && !a.Destination().HasLabel("X-Very-Secret-Token", "42") {
					return check.ResultDropCurlHTTPError, check.ResultNone
				}
				egress = check.ResultOK
				// Expect all curls from client2 to be proxied and to be GET calls.
				egress.HTTP = check.HTTP{
					Method: "GET",
				}
				return egress, check.ResultNone
			}
			return check.ResultDrop, check.ResultDefaultDenyIngressDrop
		})
}

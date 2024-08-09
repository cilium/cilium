// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package builder

import (
	_ "embed"

	"github.com/cilium/cilium/cilium-cli/connectivity/check"
	"github.com/cilium/cilium/cilium-cli/connectivity/tests"
	"github.com/cilium/cilium/cilium-cli/utils/features"
)

//go:embed manifests/echo-ingress-icmp-deny.yaml
var echoIngressICMPDenyPolicyYAML string

type clientIngressFromOtherClientIcmpDeny struct{}

func (t clientIngressFromOtherClientIcmpDeny) build(ct *check.ConnectivityTest, _ map[string]string) {
	// This policy denies ICMP ingress to client only from other client
	newTest("client-ingress-from-other-client-icmp-deny", ct).
		WithCiliumPolicy(allowAllEgressPolicyYAML).      // Allow all egress traffic
		WithCiliumPolicy(allowAllIngressPolicyYAML).     // Allow all ingress traffic
		WithCiliumPolicy(echoIngressICMPDenyPolicyYAML). // Deny ICMP traffic from client to another client
		WithFeatureRequirements(features.RequireEnabled(features.ICMPPolicy)).
		WithScenarios(
			tests.PodToPod(),       // Client to echo traffic should be allowed
			tests.ClientToClient(), // Client to client traffic should be denied
		).
		WithExpectations(func(a *check.Action) (egress, ingress check.Result) {
			if a.Source().HasLabel("other", "client") &&
				a.Destination().HasLabel("kind", "client") {
				return check.ResultDrop, check.ResultPolicyDenyIngressDrop
			}
			return check.ResultOK, check.ResultNone
		})
}

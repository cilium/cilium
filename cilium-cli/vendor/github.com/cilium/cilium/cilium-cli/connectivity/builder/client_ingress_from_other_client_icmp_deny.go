// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package builder

import (
	_ "embed"
	check2 "github.com/cilium/cilium/cilium-cli/connectivity/check"
	tests2 "github.com/cilium/cilium/cilium-cli/connectivity/tests"

	"github.com/cilium/cilium-cli/utils/features"
)

//go:embed manifests/echo-ingress-icmp-deny.yaml
var echoIngressICMPDenyPolicyYAML string

type clientIngressFromOtherClientIcmpDeny struct{}

func (t clientIngressFromOtherClientIcmpDeny) build(ct *check2.ConnectivityTest, _ map[string]string) {
	// This policy denies ICMP ingress to client only from other client
	newTest("client-ingress-from-other-client-icmp-deny", ct).
		WithCiliumPolicy(allowAllEgressPolicyYAML).      // Allow all egress traffic
		WithCiliumPolicy(allowAllIngressPolicyYAML).     // Allow all ingress traffic
		WithCiliumPolicy(echoIngressICMPDenyPolicyYAML). // Deny ICMP traffic from client to another client
		WithFeatureRequirements(features.RequireEnabled(features.ICMPPolicy)).
		WithScenarios(
			tests2.PodToPod(),       // Client to echo traffic should be allowed
			tests2.ClientToClient(), // Client to client traffic should be denied
		).
		WithExpectations(func(a *check2.Action) (egress, ingress check2.Result) {
			if a.Source().HasLabel("other", "client") &&
				a.Destination().HasLabel("kind", "client") {
				return check2.ResultDrop, check2.ResultPolicyDenyIngressDrop
			}
			return check2.ResultOK, check2.ResultNone
		})
}

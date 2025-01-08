// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package builder

import (
	_ "embed"

	"github.com/cilium/cilium/cilium-cli/connectivity/check"
	"github.com/cilium/cilium/cilium-cli/connectivity/tests"
	"github.com/cilium/cilium/cilium-cli/utils/features"
)

//go:embed manifests/echo-ingress-icmp-deny-ccnp.yaml
var echoIngressICMPDenyCCNPPolicyYAML string

type clientIngressFromOtherClientIcmpDenyCCNP struct{}

func (t clientIngressFromOtherClientIcmpDenyCCNP) build(ct *check.ConnectivityTest, _ map[string]string) {
	newTest("client-ingress-from-other-client-icmp-deny-ccnp", ct).
		WithCiliumClusterwidePolicy(allowAllEgressCCNPPolicyYAML).      
		WithCiliumClusterwidePolicy(allowAllIngressCCNPPolicyYAML).    
		WithCiliumClusterwidePolicy(echoIngressICMPDenyCCNPPolicyYAML). 
		WithFeatureRequirements(features.RequireEnabled(features.ICMPPolicy)).
		WithScenarios(
			tests.PodToPod(),      
			tests.ClientToClient(), 
		).
		WithExpectations(func(a *check.Action) (egress, ingress check.Result) {
			if a.Source().HasLabel("other", "client") &&
				a.Destination().HasLabel("kind", "client") {
				return check.ResultDrop, check.ResultPolicyDenyIngressDrop
			}
			return check.ResultOK, check.ResultNone
		})
}

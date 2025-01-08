// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package builder

import (
	_ "embed"

	"github.com/cilium/cilium/cilium-cli/connectivity/check"
	"github.com/cilium/cilium/cilium-cli/connectivity/tests"
	"github.com/cilium/cilium/cilium-cli/utils/features"
)

//go:embed manifests/echo-ingress-icmp-ccnp.yaml
var echoIngressICMPCCNPPolicyYAML string

type clientIngressIcmpCCNP struct{}

func (t clientIngressIcmpCCNP) build(ct *check.ConnectivityTest, _ map[string]string) {
	newTest("client-ingress-icmp-ccnp", ct).
		WithCiliumClusterwidePolicy(echoIngressICMPCCNPPolicyYAML).
		WithFeatureRequirements(features.RequireEnabled(features.ICMPPolicy)).
		WithScenarios(tests.ClientToClient()).
		WithExpectations(func(a *check.Action) (egress, ingress check.Result) {
			if a.Source().HasLabel("other", "client") {
				return check.ResultOK, check.ResultOK
			}
			return check.ResultOK, check.ResultDefaultDenyIngressDrop
		})
}

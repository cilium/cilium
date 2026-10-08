// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package builder

import (
	_ "embed"

	"github.com/cilium/cilium/cilium-cli/connectivity/check"
	"github.com/cilium/cilium/cilium-cli/connectivity/tests"
	"github.com/cilium/cilium/cilium-cli/utils/features"
)

//go:embed manifests/echo-ingress-icmp.yaml
var echoIngressICMPPolicyYAML string

type clientIngressIcmp struct{}

func (t clientIngressIcmp) build(ct *check.ConnectivityTest, _ map[string]string) {
	// This policy allowed ICMP traffic from client to another client.
	newTest("client-ingress-icmp", ct).
		WithCiliumPolicy(echoIngressICMPPolicyYAML).
		WithFeatureRequirements(features.RequireEnabled(features.ICMPPolicy)).
		WithScenarios(tests.ClientToClient()).
		WithExpectations(func(a *check.Action) (egress, ingress check.Result) {
			if a.Source().HasLabel("other", "client") {
				return check.ResultOK, check.ResultOK
			}
			return check.ResultOK, check.ResultDefaultDenyIngressDrop
		})
}

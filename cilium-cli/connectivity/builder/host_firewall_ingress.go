// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package builder

import (
	_ "embed"

	"github.com/cilium/cilium/cilium-cli/connectivity/check"
	"github.com/cilium/cilium/cilium-cli/connectivity/tests"
	"github.com/cilium/cilium/cilium-cli/utils/features"
)

//go:embed manifests/host-firewall-ingress.yaml
var hostFirewallIngressPolicyYAML string

type hostFirewallIngress struct{}

func (t hostFirewallIngress) build(ct *check.ConnectivityTest, _ map[string]string) {
	newTest("host-firewall-ingress", ct).
		WithCondition(func() bool { return ct.Params().IncludeUnsafeTests }).
		WithFeatureRequirements(features.RequireEnabled(features.HostFirewall)).
		WithCiliumClusterwidePolicy(hostFirewallIngressPolicyYAML).
		WithScenarios(tests.PodToHost()).
		WithExpectations(func(a *check.Action) (egress check.Result, ingress check.Result) {
			if a.Source().HasLabel("name", "client") {
				return check.ResultOK, check.ResultPolicyDenyIngressDrop
			}
			return check.ResultOK, check.ResultOK
		})
}

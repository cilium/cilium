// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package builder

import (
	_ "embed"

	"github.com/cilium/cilium/cilium-cli/connectivity/check"
	"github.com/cilium/cilium/cilium-cli/connectivity/tests"
	"github.com/cilium/cilium/cilium-cli/utils/features"
)

//go:embed manifests/host-firewall-egress.yaml
var hostFirewallEgressPolicyYAML string

type hostFirewallEgress struct{}

func (t hostFirewallEgress) build(ct *check.ConnectivityTest, _ map[string]string) {
	newTest("host-firewall-egress", ct).
		WithCondition(func() bool { return ct.Params().IncludeUnsafeTests }).
		WithFeatureRequirements(features.RequireEnabled(features.HostFirewall)).
		WithCiliumClusterwidePolicy(hostFirewallEgressPolicyYAML).
		WithScenarios(tests.HostToPod()).
		WithExpectations(func(a *check.Action) (egress check.Result, ingress check.Result) {
			if a.Destination().HasLabel("name", "echo-other-node") {
				return check.ResultPolicyDenyEgressDrop, check.ResultOK
			}
			return check.ResultOK, check.ResultOK
		})
}

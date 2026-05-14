// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package builder

import (
	"github.com/cilium/cilium/cilium-cli/connectivity/check"
	"github.com/cilium/cilium/cilium-cli/connectivity/tests"
	"github.com/cilium/cilium/cilium-cli/utils/features"
)

type hostFirewallEgressToFqdns struct{}

func (t hostFirewallEgressToFqdns) build(ct *check.ConnectivityTest, templates map[string]string) {
	// This test does only half the job unless external targets differ
	differentExternalTargets := func() bool {
		return ct.Params().ExternalTarget != ct.Params().ExternalOtherTarget
	}
	// This policy only allows port 80 to domain-name, default one.one.one.one., DNS proxy enabled.
	newTest("host-firewall-egress-to-fqdns", ct).
		WithCiliumVersion(">=1.19.5").
		WithCondition(func() bool { return ct.Params().IncludeUnsafeTests }).
		WithCondition(differentExternalTargets).
		WithFeatureRequirements(
			features.RequireDisabled(features.EndpointRoutes), // currently broken when proxying to in-cluster endpoints, see #45957
			features.RequireEnabled(features.L7Proxy),
			features.RequireEnabled(features.HostFirewall)).
		WithCiliumClusterwidePolicy(templates["hostFirewallEgressToFQDNsPolicyYAML"]).
		WithScenarios(
			tests.HostToWorld()).
		WithExpectations(func(a *check.Action) (egress, ingress check.Result) {
			extTarget := ct.Params().ExternalTarget
			if a.Destination().Address(features.GetIPFamily(extTarget)) == extTarget {
				return check.ResultOK, check.ResultNone
			}

			return check.ResultDNSOKDropCurlTimeout, check.ResultNone
		})
}

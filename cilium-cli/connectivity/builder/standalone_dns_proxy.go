// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package builder

import (
	"github.com/cilium/cilium/cilium-cli/connectivity/check"
	"github.com/cilium/cilium/cilium-cli/connectivity/tests"
	"github.com/cilium/cilium/cilium-cli/utils/features"
)

type standaloneDnsProxy struct{}

func (t standaloneDnsProxy) build(ct *check.ConnectivityTest, templates map[string]string) {
	// Functional test: with the Cilium agent up, verify the Standalone DNS Proxy
	// actively serves DNS. It uses a restrictive DNS policy that only permits the
	// allowed external target, so queries for the other target are refused by the
	// proxy (DNS-level deny). The test asserts DNS proxy metric deltas and that a
	// subset of DNS flows are attributed to the SDP.
	newTest("standalone-dns-proxy", ct).
		WithCiliumPolicy(templates["clientEgressToFQDNsPolicyYAML"]).
		WithCiliumPolicy(templates["clientEgressOnlyDNSTargetPolicyYAML"]).
		WithFeatureRequirements(
			features.RequireEnabled(features.L7Proxy),
			features.RequireEnabled(features.StandaloneDNSProxy),
		).
		WithCiliumVersion(">=1.20.0").
		WithScenarios(tests.StandaloneDNSProxy()).
		WithExpectations(func(a *check.Action) (egress, ingress check.Result) {
			if a.Destination().Address(features.IPFamilyAny) == ct.Params().ExternalOtherTarget {
				// Denied domain: the DNS proxy refuses the query, so curl fails
				// to resolve the name. The exact curl exit code depends on the
				// resolver, so any failure is accepted.
				return check.Result{ExitCode: check.ExitAnyError}, check.ResultNone
			}
			// Allowed domain: DNS resolves through the proxy and the connection
			// to port 80 succeeds.
			return check.ResultDNSOK, check.ResultNone
		})

	// HA / resilience test: verify the Standalone DNS Proxy keeps enforcing
	// toFQDNs/DNS policy for previously-resolved domains while the Cilium agent on
	// the client's node is down. Reuses the toFQDNs policy (allows port 80 to
	// ExternalTarget) and the permissive DNS-visibility policy (both domains
	// resolve; the blocked one is dropped at L4).
	newTest("standalone-dns-proxy-ha", ct).
		WithCiliumPolicy(templates["clientEgressToFQDNsPolicyYAML"]).
		WithCiliumPolicy(templates["clientEgressOnlyDNSPolicyYAML"]).
		WithFeatureRequirements(
			features.RequireEnabled(features.L7Proxy),
			features.RequireEnabled(features.StandaloneDNSProxy),
		).
		WithCiliumVersion(">=1.20.0").
		WithScenarios(tests.StandaloneDNSProxyHA()).
		WithExpectations(func(a *check.Action) (egress, ingress check.Result) {
			if a.Destination().Address(features.IPFamilyAny) == ct.Params().ExternalOtherTarget {
				// Blocked domain: DNS resolves through the proxy, but the
				// connection is dropped as it is not allowed by the toFQDNs policy.
				return check.ResultDNSOKDropCurlTimeout, check.ResultNone
			}
			// Allowed domain: DNS resolves through the proxy and the connection
			// to port 80 succeeds.
			return check.ResultDNSOK, check.ResultNone
		})
}

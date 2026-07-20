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
	// Validates that the Standalone DNS Proxy keeps enforcing toFQDNs/DNS policy
	// for previously-resolved domains while the Cilium agent on the client's node
	// is down. Reuses the toFQDNs policy (allows port 80 to ExternalTarget) and
	// the DNS-visibility policy (proxies DNS via the DNS proxy).
	newTest("standalone-dns-proxy", ct).
		WithCiliumPolicy(templates["clientEgressToFQDNsPolicyYAML"]).
		WithCiliumPolicy(templates["clientEgressOnlyDNSPolicyYAML"]).
		WithFeatureRequirements(
			features.RequireEnabled(features.L7Proxy),
			features.RequireEnabled(features.StandaloneDNSProxy),
		).
		WithCiliumVersion(">=1.20.0").
		WithScenarios(tests.StandaloneDNSProxy()).
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

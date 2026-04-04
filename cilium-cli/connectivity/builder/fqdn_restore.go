// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package builder

import (
	"github.com/cilium/cilium/cilium-cli/connectivity/check"
	"github.com/cilium/cilium/cilium-cli/connectivity/tests"
	"github.com/cilium/cilium/cilium-cli/utils/features"
)

type fqdnRestoreAfterRestart struct{}

func (t fqdnRestoreAfterRestart) build(ct *check.ConnectivityTest, templates map[string]string) {
	// Apply the same policies as the to-fqdns test: allow DNS (port 53) and
	// allow egress to ExternalTarget via toFQDNs. ExternalOtherTarget is
	// implicitly blocked because there is no rule permitting it.
	newTest("seq-fqdn-restore-after-restart", ct).
		WithCiliumPolicy(templates["clientEgressToFQDNsPolicyYAML"]).
		WithCiliumPolicy(templates["clientEgressOnlyDNSPolicyYAML"]).
		WithFeatureRequirements(
			features.RequireEnabled(features.L7Proxy),
			features.RequireEnabled(features.FQDNProxyMinTTL),
			features.RequireEnabled(features.FQDNProxyIdleConnectionGracePeriod),
		).
		WithCondition(func() bool {
			p := ct.Params()
			ipv4 := ct.Features[features.IPv4].Enabled
			ipv6 := ct.Features[features.IPv6].Enabled
			hasIPv4 := ipv4 && p.ExternalIPv4 != "" && p.ExternalOtherIPv4 != ""
			hasIPv6 := ipv6 && p.ExternalIPv6 != "" && p.ExternalOtherIPv6 != ""
			return hasIPv4 || hasIPv6
		}).
		WithScenarios(tests.FQDNRestoreAfterRestart())
}

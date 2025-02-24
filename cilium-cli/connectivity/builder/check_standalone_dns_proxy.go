// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package builder

import (
	"github.com/cilium/cilium/cilium-cli/connectivity/check"
	"github.com/cilium/cilium/cilium-cli/connectivity/tests"
	"github.com/cilium/cilium/cilium-cli/utils/features"
)

type checkStandaloneDnsProxy struct{}

func (t checkStandaloneDnsProxy) build(ct *check.ConnectivityTest, templates map[string]string) {
	newTest("check-standalone-dns-proxy", ct).
		WithCiliumPolicy(templates["clientEgressStandaloneDNSProxyYAML"]).
		WithFeatureRequirements(features.RequireEnabled(features.L7Proxy), features.RequireDisabled(features.EmbeddedDNSProxy), features.RequireEnabled(features.StandaloneDNSProxy)). // Flags for standalone DNS proxy
		WithScenarios(
			tests.StandaloneDNSProxy(),
		)
}

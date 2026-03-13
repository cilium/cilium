// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package builder

import (
	"github.com/cilium/cilium/cilium-cli/connectivity/check"
	"github.com/cilium/cilium/cilium-cli/connectivity/tests"
	"github.com/cilium/cilium/cilium-cli/utils/features"
)

type bgpControlPlane struct{}

func (t bgpControlPlane) build(ct *check.ConnectivityTest, _ map[string]string) {
	// prefix the test name with `seq-` to run it sequentially
	newTest("seq-bgp-control-plane-v1", ct).
		// NOTE: BGPv1 was removed in v1.19, this test can be removed once v1.18 is out of support
		WithCiliumVersion(">=1.16.0 <1.19.0").
		WithCondition(func() bool {
			return ct.Params().IncludeUnsafeTests
		}).
		WithFeatureRequirements(
			features.RequireEnabled(features.BGPControlPlane),
			features.RequireEnabled(features.NodeWithoutCilium),
		).
		WithScenarios(tests.BGPAdvertisements(1, bgpPeeringPolicyYAML))

	// prefix the test name with `seq-` to run it sequentially
	newTest("seq-bgp-control-plane-v2", ct).
		WithCiliumVersion(">=1.16.0").
		WithCondition(func() bool {
			return ct.Params().IncludeUnsafeTests
		}).
		WithFeatureRequirements(
			features.RequireEnabled(features.BGPControlPlane),
			features.RequireEnabled(features.NodeWithoutCilium),
		).
		WithScenarios(tests.BGPAdvertisements(2, ""))
}

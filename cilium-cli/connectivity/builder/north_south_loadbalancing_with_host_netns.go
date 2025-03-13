// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package builder

import (
	"github.com/cilium/cilium/cilium-cli/connectivity/check"
	"github.com/cilium/cilium/cilium-cli/connectivity/tests"
	"github.com/cilium/cilium/cilium-cli/utils/features"
	"github.com/cilium/cilium/pkg/versioncheck"
)

type northSouthLoadbalancingWithHostNetNs struct{}

func (t northSouthLoadbalancingWithHostNetNs) build(ct *check.ConnectivityTest, _ map[string]string) {
	newTest("north-south-loadbalancing-with-host-netns", ct).
		WithCondition(func() bool {
			return versioncheck.MustCompile(">=1.18.0")(ct.CiliumVersion)
		}).
		WithFeatureRequirements(
			withKPRReqForMultiCluster(ct, features.RequireEnabled(features.NodeWithoutCilium))...,
		).
		WithScenarios(tests.OutsideToNodePortForHostNetNs())
}

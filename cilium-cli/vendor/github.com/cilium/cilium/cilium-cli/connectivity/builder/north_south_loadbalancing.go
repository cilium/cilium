// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package builder

import (
	"github.com/cilium/cilium-cli/utils/features"
	"github.com/cilium/cilium/cilium-cli/connectivity/check"
	"github.com/cilium/cilium/cilium-cli/connectivity/tests"
)

type northSouthLoadbalancing struct{}

func (t northSouthLoadbalancing) build(ct *check.ConnectivityTest, _ map[string]string) {
	newTest("north-south-loadbalancing", ct).
		WithFeatureRequirements(
			withKPRReqForMultiCluster(ct, features.RequireEnabled(features.NodeWithoutCilium))...,
		).
		WithScenarios(tests.OutsideToNodePort())
}

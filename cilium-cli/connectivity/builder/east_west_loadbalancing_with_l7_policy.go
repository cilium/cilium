// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package builder

import (
	"github.com/cilium/cilium/cilium-cli/connectivity/check"
	"github.com/cilium/cilium/cilium-cli/connectivity/tests"
	"github.com/cilium/cilium/cilium-cli/utils/features"
)

type eastWestLoadbalancingWithL7Policy struct{}

func (t eastWestLoadbalancingWithL7Policy) build(ct *check.ConnectivityTest, _ map[string]string) {
	eastWestLoadbalancingWithL7PolicyTest(ct, false)
	if ct.Features[features.L7PortRanges].Enabled {
		eastWestLoadbalancingWithL7PolicyTest(ct, true)
	}
}

func eastWestLoadbalancingWithL7PolicyTest(ct *check.ConnectivityTest, portRanges bool) {
	testName := "east-west-loadbalancing-with-l7-policy"
	policyYAML := echoIngressL7HTTPFromAnywherePolicyYAML
	if portRanges {
		testName = "east-west-loadbalancing-with-l7-policy-port-range"
		policyYAML = echoIngressL7HTTPFromAnywherePolicyPortRangeYAML
	}

	newTest(testName, ct).
		WithFeatureRequirements(
			withKPRReqForMultiCluster(ct, features.RequireEnabled(features.L7Proxy))...,
		).
		WithCiliumPolicy(policyYAML).
		WithScenarios(
			tests.PodToLocalNodePort(),
			tests.PodToRemoteNodePort(),
		)
}

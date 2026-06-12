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

	// With per-endpoint routes (ENI, GKE, Azure, aws-cni chaining, ...) and
	// kube-proxy still managing services, remote nodeport traffic bypasses
	// cilium_host and kube-proxy's iptables rules run outside Cilium's BPF
	// context. This makes CT state inconsistent for L7 proxy flows from
	// remote nodes, causing drops. KPR avoids this by owning the full
	// service path in BPF.
	scenarios := []check.Scenario{tests.PodToLocalNodePort()}
	if !ct.Features[features.EndpointRoutes].Enabled || ct.Features[features.KPR].Enabled {
		scenarios = append(scenarios, tests.PodToRemoteNodePort())
	}

	newTest(testName, ct).
		WithFeatureRequirements(
			withKPRReqForMultiCluster(ct, features.RequireEnabled(features.L7Proxy))...,
		).
		WithCiliumPolicy(policyYAML).
		WithScenarios(scenarios...)
}

// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package builder

import (
	_ "embed"

	"github.com/cilium/cilium-cli/connectivity/check"
	"github.com/cilium/cilium-cli/connectivity/tests"
	"github.com/cilium/cilium-cli/utils/features"
)

//go:embed manifests/echo-ingress-l7-http-from-anywhere.yaml
var echoIngressL7HTTPFromAnywherePolicyYAML string

//go:embed manifests/echo-ingress-l7-http-from-anywhere-port-range.yaml
var echoIngressL7HTTPFromAnywherePolicyPortRangeYAML string

type northSouthLoadbalancingWithL7Policy struct{}

func (t northSouthLoadbalancingWithL7Policy) build(ct *check.ConnectivityTest, _ map[string]string) {
	northSouthLoadbalancingWithL7PolicyTest(ct, false)
	if ct.Features[features.PortRanges].Enabled {
		northSouthLoadbalancingWithL7PolicyTest(ct, true)
	}
}

func northSouthLoadbalancingWithL7PolicyTest(ct *check.ConnectivityTest, portRanges bool) {
	testName := "north-south-loadbalancing-with-l7-policy"
	policyYAML := echoIngressL7HTTPFromAnywherePolicyYAML
	if portRanges {
		testName = "north-south-loadbalancing-with-l7-policy-port-range"
		policyYAML = echoIngressL7HTTPFromAnywherePolicyPortRangeYAML
	}
	// The following tests have DNS redirect policies. They should be executed last.
	newTest(testName, ct).
		WithFeatureRequirements(
			withKPRReqForMultiCluster(ct,
				features.RequireEnabled(features.NodeWithoutCilium),
				features.RequireEnabled(features.L7Proxy))...,
		).
		WithCiliumVersion(">1.13.2").
		WithCiliumPolicy(policyYAML).
		WithScenarios(tests.OutsideToNodePort())
}

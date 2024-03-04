// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package builder

import (
	_ "embed"
	"github.com/cilium/cilium/cilium-cli/connectivity/check"
	"github.com/cilium/cilium/cilium-cli/connectivity/tests"

	"github.com/cilium/cilium-cli/utils/features"
)

//go:embed manifests/echo-ingress-l7-http-from-anywhere.yaml
var echoIngressL7HTTPFromAnywherePolicyYAML string

type northSouthLoadbalancingWithL7Policy struct{}

func (t northSouthLoadbalancingWithL7Policy) build(ct *check.ConnectivityTest, _ map[string]string) {
	// The following tests have DNS redirect policies. They should be executed last.
	newTest("north-south-loadbalancing-with-l7-policy", ct).
		WithFeatureRequirements(
			withKPRReqForMultiCluster(ct,
				features.RequireEnabled(features.NodeWithoutCilium),
				features.RequireEnabled(features.L7Proxy))...,
		).
		WithCiliumVersion(">1.13.2").
		WithCiliumPolicy(echoIngressL7HTTPFromAnywherePolicyYAML).
		WithScenarios(tests.OutsideToNodePort())
}

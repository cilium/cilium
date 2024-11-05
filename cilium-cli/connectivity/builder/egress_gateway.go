// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package builder

import (
	"github.com/cilium/cilium/cilium-cli/connectivity/check"
	"github.com/cilium/cilium/cilium-cli/connectivity/tests"
	"github.com/cilium/cilium/cilium-cli/utils/features"
)

type egressGateway struct{}

func (t egressGateway) build(ct *check.ConnectivityTest, _ map[string]string) {
	newTest("egress-gateway", ct).
		WithCondition(func() bool { return ct.Params().IncludeUnsafeTests }).
		WithCiliumEgressGatewayPolicy(check.CiliumEgressGatewayPolicyParams{
			Name:            "cegp-sample-client",
			PodSelectorKind: "client",
		}).
		WithCiliumEgressGatewayPolicy(check.CiliumEgressGatewayPolicyParams{
			Name:            "cegp-sample-echo",
			PodSelectorKind: "echo",
		}).
		WithIPRoutesFromOutsideToPodCIDRs().
		WithFeatureRequirements(
			features.RequireEnabled(features.EgressGateway),
			features.RequireEnabled(features.NodeWithoutCilium),
		).
		WithScenarios(tests.EgressGateway())
}

// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package builder

import (
	"github.com/cilium/cilium-cli/utils/features"
	check2 "github.com/cilium/cilium/cilium-cli/connectivity/check"
	"github.com/cilium/cilium/cilium-cli/connectivity/tests"
)

type egressGateway struct{}

func (t egressGateway) build(ct *check2.ConnectivityTest, _ map[string]string) {
	newTest("egress-gateway", ct).
		WithCondition(func() bool { return ct.Params().IncludeUnsafeTests }).
		WithCiliumEgressGatewayPolicy(check2.CiliumEgressGatewayPolicyParams{
			Name:            "cegp-sample-client",
			PodSelectorKind: "client",
		}).
		WithCiliumEgressGatewayPolicy(check2.CiliumEgressGatewayPolicyParams{
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

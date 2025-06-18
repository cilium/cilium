// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package builder

import (
	"fmt"

	"github.com/cilium/cilium/cilium-cli/connectivity/check"
	"github.com/cilium/cilium/cilium-cli/connectivity/tests"
	"github.com/cilium/cilium/cilium-cli/utils/features"
)

type egressGatewayMultigateway struct{}

func (t egressGatewayMultigateway) build(ct *check.ConnectivityTest, _ map[string]string) {
	newTest("egress-gateway-multigateway", ct).
		WithCiliumVersion(">=1.18.0").
		WithCondition(func() bool { return ct.Params().IncludeUnsafeTests }).
		WithCiliumEgressGatewayPolicy(check.CiliumEgressGatewayPolicyParams{
			Name:            fmt.Sprintf("cegp-sample-client-%d", ct.Params().TestNamespaceIndex),
			PodSelectorKind: "client",
			Multigateway:    true,
		}).
		WithCiliumEgressGatewayPolicy(check.CiliumEgressGatewayPolicyParams{
			Name:            fmt.Sprintf("cegp-sample-echo-%d", ct.Params().TestNamespaceIndex),
			PodSelectorKind: "echo",
			Multigateway:    true,
		}).
		WithIPRoutesFromOutsideToPodCIDRs().
		WithFeatureRequirements(
			features.RequireEnabled(features.EgressGateway),
			features.RequireEnabled(features.NodeWithoutCilium),
		).
		WithScenarios(tests.EgressGatewayMultigateway())
}

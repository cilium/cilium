// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package builder

import (
	"fmt"

	"github.com/cilium/cilium/cilium-cli/connectivity/check"
	"github.com/cilium/cilium/cilium-cli/connectivity/tests"
	"github.com/cilium/cilium/cilium-cli/utils/features"
)

type egressGatewayExcludedCidrs struct{}

func (t egressGatewayExcludedCidrs) build(ct *check.ConnectivityTest, _ map[string]string) {
	newTest("egress-gateway-excluded-cidrs", ct).
		WithCiliumEgressGatewayPolicy(check.CiliumEgressGatewayPolicyParams{
			Name:              fmt.Sprintf("cegp-sample-client-%d", ct.Params().TestNamespaceIndex),
			PodSelectorKind:   "client",
			ExcludedCIDRsConf: check.ExternalNodeExcludedCIDRs,
		}).
		WithFeatureRequirements(
			features.RequireEnabled(features.EgressGateway),
			features.RequireEnabled(features.NodeWithoutCilium),
		).
		WithScenarios(tests.EgressGatewayExcludedCIDRs())
}

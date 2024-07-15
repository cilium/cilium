// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package builder

import (
	"github.com/cilium/cilium/pkg/versioncheck"

	"github.com/cilium/cilium/cilium-cli/connectivity/check"
	"github.com/cilium/cilium/cilium-cli/connectivity/tests"
	"github.com/cilium/cilium/cilium-cli/utils/features"
)

type egressGatewayExcludedCidrs struct{}

func (t egressGatewayExcludedCidrs) build(ct *check.ConnectivityTest, _ map[string]string) {
	newTest("egress-gateway-excluded-cidrs", ct).
		WithCondition(func() bool {
			return versioncheck.MustCompile(">=1.14.0")(ct.CiliumVersion)
		}).
		WithCiliumEgressGatewayPolicy(check.CiliumEgressGatewayPolicyParams{
			Name:              "cegp-sample-client",
			PodSelectorKind:   "client",
			ExcludedCIDRsConf: check.ExternalNodeExcludedCIDRs,
		}).
		WithFeatureRequirements(
			features.RequireEnabled(features.EgressGateway),
			features.RequireEnabled(features.NodeWithoutCilium),
		).
		WithScenarios(tests.EgressGatewayExcludedCIDRs())
}

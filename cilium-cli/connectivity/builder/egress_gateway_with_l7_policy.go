// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package builder

import (
	_ "embed"

	"github.com/cilium/cilium/pkg/versioncheck"

	"github.com/cilium/cilium-cli/connectivity/check"
	"github.com/cilium/cilium-cli/connectivity/tests"
	"github.com/cilium/cilium-cli/utils/features"
)

//go:embed manifests/client-egress-icmp.yaml
var clientEgressICMPYAML string

//go:embed manifests/client-egress-l7-http-external-node.yaml
var clientEgressL7HTTPExternalYAML string

type egressGatewayWithL7Policy struct{}

func (t egressGatewayWithL7Policy) build(ct *check.ConnectivityTest, _ map[string]string) {
	newTest("egress-gateway-with-l7-policy", ct).
		WithCondition(func() bool {
			return versioncheck.MustCompile(">=1.16.0")(ct.CiliumVersion) && ct.Params().IncludeUnsafeTests
		}).
		WithCiliumPolicy(clientEgressICMPYAML).
		WithCiliumPolicy(clientEgressOnlyDNSPolicyYAML).  // DNS resolution only
		WithCiliumPolicy(clientEgressL7HTTPExternalYAML). // L7 allow policy with HTTP introspection
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
			features.RequireEnabled(features.L7Proxy),
			features.RequireEnabled(features.NodeWithoutCilium),
		).
		WithScenarios(tests.EgressGateway())
}

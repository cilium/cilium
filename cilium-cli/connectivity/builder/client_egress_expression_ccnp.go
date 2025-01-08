// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package builder

import (
	_ "embed"

	"github.com/cilium/cilium/cilium-cli/connectivity/check"
	"github.com/cilium/cilium/cilium-cli/connectivity/tests"
	"github.com/cilium/cilium/cilium-cli/utils/features"
)

//go:embed manifests/client-egress-to-echo-expression-ccnp.yaml
var clientEgressToEchoExpressionCCNPPolicyYAML string

//go:embed manifests/client-egress-to-echo-expression-port-range-ccnp.yaml
var clientEgressToEchoExpressionCCNPPolicyPortRangeYAML string

type clientEgressExpressionCCNP struct{}

func (t clientEgressExpressionCCNP) build(ct *check.ConnectivityTest, _ map[string]string) {
	clientEgressExpressionCCNPTest(ct, false)
	if ct.Features[features.PortRanges].Enabled {
		clientEgressExpressionCCNPTest(ct, true)
	}
}

func clientEgressExpressionCCNPTest(ct *check.ConnectivityTest, portRanges bool) {
	testName := "client-egress-expression-ccnp"
	policyYAML := clientEgressToEchoExpressionCCNPPolicyYAML
	if portRanges {
		testName = "client-egress-expression-port-range-ccnp"
		policyYAML = clientEgressToEchoExpressionCCNPPolicyPortRangeYAML
	}
	newTest(testName, ct).
		WithCiliumClusterwidePolicy(policyYAML).
		WithScenarios(tests.PodToPod())
}

// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package builder

import (
	_ "embed"

	"github.com/cilium/cilium-cli/connectivity/check"
	"github.com/cilium/cilium-cli/connectivity/tests"
	"github.com/cilium/cilium-cli/utils/features"
)

//go:embed manifests/client-egress-to-echo-expression.yaml
var clientEgressToEchoExpressionPolicyYAML string

//go:embed manifests/client-egress-to-echo-expression-port-range.yaml
var clientEgressToEchoExpressionPolicyPortRangeYAML string

type clientEgressExpression struct{}

func (t clientEgressExpression) build(ct *check.ConnectivityTest, _ map[string]string) {
	clientEgressExpressionTest(ct, false)
	if ct.Features[features.PortRanges].Enabled {
		clientEgressExpressionTest(ct, true)
	}
}

func clientEgressExpressionTest(ct *check.ConnectivityTest, portRanges bool) {
	testName := "client-egress-expression"
	policyYAML := clientEgressToEchoExpressionPolicyYAML
	if portRanges {
		testName = "client-egress-expression-port-range"
		policyYAML = clientEgressToEchoExpressionPolicyPortRangeYAML
	}
	// This policy allows port 8080 from client to echo (using label match expression, so this should succeed
	newTest(testName, ct).
		WithCiliumPolicy(policyYAML).
		WithScenarios(tests.PodToPod())
}

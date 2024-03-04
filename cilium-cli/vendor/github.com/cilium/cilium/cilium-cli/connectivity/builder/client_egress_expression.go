// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package builder

import (
	_ "embed"
	"github.com/cilium/cilium/cilium-cli/connectivity/check"
	"github.com/cilium/cilium/cilium-cli/connectivity/tests"
)

//go:embed manifests/client-egress-to-echo-expression.yaml
var clientEgressToEchoExpressionPolicyYAML string

type clientEgressExpression struct{}

func (t clientEgressExpression) build(ct *check.ConnectivityTest, _ map[string]string) {
	// This policy allows port 8080 from client to echo (using label match expression, so this should succeed
	newTest("client-egress-expression", ct).
		WithCiliumPolicy(clientEgressToEchoExpressionPolicyYAML).
		WithScenarios(tests.PodToPod())
}

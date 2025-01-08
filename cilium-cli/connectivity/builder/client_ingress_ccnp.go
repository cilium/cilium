// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package builder

import (
	_ "embed"

	"github.com/cilium/cilium/cilium-cli/connectivity/check"
	"github.com/cilium/cilium/cilium-cli/connectivity/tests"
)


//go:embed manifests/client-ingress-from-client2-ccnp.yaml
var clientIngressFromClient2CCNPPolicyYAML string
type clientIngressCCNP struct{}

func (t clientIngressCCNP) build(ct *check.ConnectivityTest, _ map[string]string) {

	newTest("client-ingress-ccnp", ct).
		WithCiliumClusterwidePolicy(clientIngressFromClient2CCNPPolicyYAML).
		WithScenarios(tests.ClientToClient()).
		WithExpectations(func(a *check.Action) (egress, ingress check.Result) {
			if a.Source().HasLabel("other", "client") {
				return check.ResultOK, check.ResultOK
			}
			return check.ResultOK, check.ResultDefaultDenyIngressDrop
		})
}

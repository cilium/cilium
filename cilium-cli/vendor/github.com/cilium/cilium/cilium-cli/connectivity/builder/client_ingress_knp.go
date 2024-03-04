// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package builder

import (
	_ "embed"
	check2 "github.com/cilium/cilium/cilium-cli/connectivity/check"
	"github.com/cilium/cilium/cilium-cli/connectivity/tests"
)

//go:embed manifests/client-ingress-from-client2-knp.yaml
var clientIngressFromClient2PolicyKNPYAML string

type clientIngressKnp struct{}

func (t clientIngressKnp) build(ct *check2.ConnectivityTest, _ map[string]string) {
	// Run a simple test with k8s Network Policy.
	newTest("client-ingress-knp", ct).
		WithK8SPolicy(clientIngressFromClient2PolicyKNPYAML).
		WithScenarios(tests.ClientToClient()).
		WithExpectations(func(a *check2.Action) (egress, ingress check2.Result) {
			if a.Source().HasLabel("other", "client") {
				return check2.ResultOK, check2.ResultOK
			}
			return check2.ResultOK, check2.ResultDefaultDenyIngressDrop
		})
}

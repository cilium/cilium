// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package builder

import (
	_ "embed"

	"github.com/cilium/cilium-cli/connectivity/check"
	"github.com/cilium/cilium-cli/connectivity/tests"
)

//go:embed manifests/client-ingress-from-client2.yaml
var clientIngressFromClient2PolicyYAML string

type clientIngress struct{}

func (t clientIngress) build(ct *check.ConnectivityTest, _ map[string]string) {
	// This policy only allows ingress into client from client2.
	newTest("client-ingress", ct).
		WithCiliumPolicy(clientIngressFromClient2PolicyYAML).
		WithScenarios(tests.ClientToClient()).
		WithExpectations(func(a *check.Action) (egress, ingress check.Result) {
			if a.Source().HasLabel("other", "client") {
				return check.ResultOK, check.ResultOK
			}
			return check.ResultOK, check.ResultDefaultDenyIngressDrop
		})
}

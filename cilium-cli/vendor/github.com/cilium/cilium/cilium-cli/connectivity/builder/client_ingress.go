// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package builder

import (
	_ "embed"
	check2 "github.com/cilium/cilium/cilium-cli/connectivity/check"
	"github.com/cilium/cilium/cilium-cli/connectivity/tests"
)

//go:embed manifests/client-ingress-from-client2.yaml
var clientIngressFromClient2PolicyYAML string

type clientIngress struct{}

func (t clientIngress) build(ct *check2.ConnectivityTest, _ map[string]string) {
	// This policy only allows ingress into client from client2.
	newTest("client-ingress", ct).
		WithCiliumPolicy(clientIngressFromClient2PolicyYAML).
		WithScenarios(tests.ClientToClient()).
		WithExpectations(func(a *check2.Action) (egress, ingress check2.Result) {
			if a.Source().HasLabel("other", "client") {
				return check2.ResultOK, check2.ResultOK
			}
			return check2.ResultOK, check2.ResultDefaultDenyIngressDrop
		})
}

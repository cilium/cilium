// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package builder

import (
	_ "embed"
	check2 "github.com/cilium/cilium/cilium-cli/connectivity/check"
	"github.com/cilium/cilium/cilium-cli/connectivity/tests"
)

//go:embed manifests/echo-ingress-from-other-client-knp.yaml
var echoIngressFromOtherClientPolicyKNPYAML string

type echoIngressKnp struct{}

func (t echoIngressKnp) build(ct *check2.ConnectivityTest, _ map[string]string) {
	// This k8s policy allows ingress to echo only from client with a label 'other:client'.
	newTest("echo-ingress-knp", ct).
		WithK8SPolicy(echoIngressFromOtherClientPolicyKNPYAML).
		WithScenarios(tests.PodToPod()).
		WithExpectations(func(a *check2.Action) (egress, ingress check2.Result) {
			if a.Destination().HasLabel("kind", "echo") && !a.Source().HasLabel("other", "client") {
				// TCP handshake fails both in egress and ingress when
				// L3(/L4) policy drops at either location.
				return check2.ResultDropCurlTimeout, check2.ResultDropCurlTimeout
			}
			return check2.ResultOK, check2.ResultOK
		})
}

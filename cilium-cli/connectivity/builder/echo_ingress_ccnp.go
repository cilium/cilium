// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package builder

import (
	_ "embed"

	"github.com/cilium/cilium/cilium-cli/connectivity/check"
	"github.com/cilium/cilium/cilium-cli/connectivity/tests"
)

//go:embed manifests/echo-ingress-from-other-client-ccnp.yaml
var echoIngressFromOtherClientCCNPPolicyYAML string

type echoIngressCCNP struct{}

func (t echoIngressCCNP) build(ct *check.ConnectivityTest, _ map[string]string) {
	newTest("echo-ingress-ccnp", ct).
		WithCiliumClusterwidePolicy(echoIngressFromOtherClientCCNPPolicyYAML).
		WithScenarios(tests.PodToPod()).
		WithExpectations(func(a *check.Action) (egress, ingress check.Result) {
			if a.Destination().HasLabel("kind", "echo") && !a.Source().HasLabel("other", "client") {
				return check.ResultDropCurlTimeout, check.ResultDropCurlTimeout
			}
			return check.ResultOK, check.ResultOK
		})
}

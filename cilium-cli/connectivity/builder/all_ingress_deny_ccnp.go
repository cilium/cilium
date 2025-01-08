// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package builder

import (
	_ "embed"

	"github.com/cilium/cilium/cilium-cli/connectivity/check"
	"github.com/cilium/cilium/cilium-cli/connectivity/tests"
	"github.com/cilium/cilium/cilium-cli/utils/features"
)


//go:embed manifests/deny-all-ingress-ccnp.yaml
var denyAllIngressCCNPPolicyYAML string

type allIngressDenyCCNP struct{}

func (t allIngressDenyCCNP) build(ct *check.ConnectivityTest, _ map[string]string) {
	newTest("all-ingress-deny-ccnp", ct).
		WithCiliumClusterwidePolicy(denyAllIngressCCNPPolicyYAML).
		WithScenarios(tests.PodToPod(), tests.PodToCIDR(tests.WithRetryAll())).
		WithExpectations(func(a *check.Action) (egress, ingress check.Result) {
			if a.Destination().Address(features.GetIPFamily(ct.Params().ExternalOtherIP)) == ct.Params().ExternalOtherIP ||
				a.Destination().Address(features.GetIPFamily(ct.Params().ExternalIP)) == ct.Params().ExternalIP {
				return check.ResultOK, check.ResultNone
			}
			return check.ResultDrop, check.ResultDefaultDenyIngressDrop
		})
}

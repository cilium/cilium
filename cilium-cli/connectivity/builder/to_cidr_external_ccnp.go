// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package builder

import (

	_ "embed"

	"github.com/cilium/cilium/cilium-cli/connectivity/check"
	"github.com/cilium/cilium/cilium-cli/connectivity/tests"
	"github.com/cilium/cilium/cilium-cli/utils/features"
)


type toCidrExternalCCNP struct{}

func (t toCidrExternalCCNP) build(ct *check.ConnectivityTest, templates map[string]string) {
	newTest("to-cidr-external-ccnp", ct).
		WithCiliumClusterwidePolicy(templates["clientEgressToCIDRExternalCCNPPolicyYAML"]).
		WithScenarios(
			tests.PodToCIDR(tests.WithRetryDestIP(ct.Params().ExternalIP)),
		).
		WithExpectations(func(a *check.Action) (egress, ingress check.Result) {
			if a.Destination().Address(features.IPFamilyV4) == ct.Params().ExternalOtherIP {
				return check.ResultDropCurlTimeout, check.ResultNone
			}
			return check.ResultOK, check.ResultNone
		})
}

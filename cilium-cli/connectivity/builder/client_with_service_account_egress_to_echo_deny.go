// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package builder

import (
	_ "embed"

	"github.com/cilium/cilium/cilium-cli/connectivity/check"
	"github.com/cilium/cilium/cilium-cli/connectivity/tests"
	"github.com/cilium/cilium/cilium-cli/utils/features"
)

//go:embed manifests/client-with-service-account-egress-to-echo-deny.yaml
var clientWithServiceAccountEgressToEchoDenyPolicyYAML string

//go:embed manifests/client-with-service-account-egress-to-echo-deny-port-range.yaml
var clientWithServiceAccountEgressToEchoDenyPolicyPortRangeYAML string

type clientWithServiceAccountEgressToEchoDeny struct{}

func (t clientWithServiceAccountEgressToEchoDeny) build(ct *check.ConnectivityTest, _ map[string]string) {
	clientWithServiceAccountEgressToEchoDenyTest(ct, false)
	if ct.Features[features.PortRanges].Enabled {
		clientWithServiceAccountEgressToEchoDenyTest(ct, true)
	}
}

func clientWithServiceAccountEgressToEchoDenyTest(ct *check.ConnectivityTest, portRanges bool) {
	testName := "client-with-service-account-egress-to-echo-deny"
	policyYAML := clientWithServiceAccountEgressToEchoDenyPolicyYAML
	if portRanges {
		testName = "client-with-service-account-egress-to-echo-deny-port-range"
		policyYAML = clientWithServiceAccountEgressToEchoDenyPolicyPortRangeYAML
	}
	// This policy denies port 8080 from client with service account selector to echo, but not from client2
	newTest(testName, ct).
		WithCiliumPolicy(allowAllEgressPolicyYAML).  // Allow all egress traffic
		WithCiliumPolicy(allowAllIngressPolicyYAML). // Allow all ingress traffic
		WithCiliumPolicy(policyYAML).
		WithScenarios(
			tests.PodToPod(tests.WithSourceLabelsOption(map[string]string{"name": "client"})),  // Client to echo should be denied
			tests.PodToPod(tests.WithSourceLabelsOption(map[string]string{"name": "client2"})), // Client2 to echo should be allowed
		).
		WithExpectations(func(a *check.Action) (egress, ingress check.Result) {
			if a.Destination().HasLabel("kind", "echo") && a.Source().HasLabel("name", "client") {
				return check.ResultPolicyDenyEgressDrop, check.ResultNone
			}
			return check.ResultOK, check.ResultOK
		})
}

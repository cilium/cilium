// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package builder

import (
	_ "embed"

	"github.com/cilium/cilium/cilium-cli/connectivity/check"
	"github.com/cilium/cilium/cilium-cli/connectivity/tests"
	"github.com/cilium/cilium/cilium-cli/utils/features"
)

//go:embed manifests/client-with-service-account-egress-to-echo-ccnp.yaml
var clientWithServiceAccountEgressToEchoCCNPPolicyYAML string

//go:embed manifests/client-with-service-account-egress-to-echo-port-range-ccnp.yaml
var clientWithServiceAccountEgressToEchoCCNPPolicyPortRangeYAML string

type clientWithServiceAccountEgressToEchoCCNP struct{}

func (t clientWithServiceAccountEgressToEchoCCNP) build(ct *check.ConnectivityTest, _ map[string]string) {
	clientWithServiceAccountEgressToEchoCCNPTest(ct, false)
	if ct.Features[features.PortRanges].Enabled {
		clientWithServiceAccountEgressToEchoCCNPTest(ct, true)
	}
}

func clientWithServiceAccountEgressToEchoCCNPTest(ct *check.ConnectivityTest, portRanges bool) {
	testName := "client-with-service-account-egress-to-echo-ccnp"
	policyYAML := clientWithServiceAccountEgressToEchoCCNPPolicyYAML
	if portRanges {
		testName = "client-with-service-account-egress-to-echo-port-range-ccnp"
		policyYAML = clientWithServiceAccountEgressToEchoCCNPPolicyPortRangeYAML
	}
	newTest(testName, ct).
		WithCiliumClusterwidePolicy(policyYAML).
		WithScenarios(
			tests.PodToPod(tests.WithSourceLabelsOption(map[string]string{"kind": "client"})),
		)
}

// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package builder

import (
	_ "embed"

	"github.com/cilium/cilium/cilium-cli/connectivity/check"
	"github.com/cilium/cilium/cilium-cli/connectivity/tests"
	"github.com/cilium/cilium/cilium-cli/utils/features"
)

//go:embed manifests/client-with-service-account-egress-to-echo.yaml
var clientWithServiceAccountEgressToEchoPolicyYAML string

//go:embed manifests/client-with-service-account-egress-to-echo-port-range.yaml
var clientWithServiceAccountEgressToEchoPolicyPortRangeYAML string

type clientWithServiceAccountEgressToEcho struct{}

func (t clientWithServiceAccountEgressToEcho) build(ct *check.ConnectivityTest, _ map[string]string) {
	clientWithServiceAccountEgressToEchoTest(ct, false)
	if ct.Features[features.PortRanges].Enabled {
		clientWithServiceAccountEgressToEchoTest(ct, true)
	}
}

func clientWithServiceAccountEgressToEchoTest(ct *check.ConnectivityTest, portRanges bool) {
	testName := "client-with-service-account-egress-to-echo"
	policyYAML := clientWithServiceAccountEgressToEchoPolicyYAML
	if portRanges {
		testName = "client-with-service-account-egress-to-echo-port-range"
		policyYAML = clientWithServiceAccountEgressToEchoPolicyPortRangeYAML
	}
	// This policy allows port 8080 from client with service account label to echo
	newTest(testName, ct).
		WithCiliumPolicy(policyYAML).
		WithScenarios(
			tests.PodToPod(tests.WithSourceLabelsOption(map[string]string{"kind": "client"})),
		)
}

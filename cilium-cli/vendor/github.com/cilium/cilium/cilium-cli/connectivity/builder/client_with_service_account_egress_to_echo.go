// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package builder

import (
	_ "embed"
	"github.com/cilium/cilium/cilium-cli/connectivity/check"
	tests2 "github.com/cilium/cilium/cilium-cli/connectivity/tests"
)

//go:embed manifests/client-with-service-account-egress-to-echo.yaml
var clientWithServiceAccountEgressToEchoPolicyYAML string

type clientWithServiceAccountEgressToEcho struct{}

func (t clientWithServiceAccountEgressToEcho) build(ct *check.ConnectivityTest, _ map[string]string) {
	// This policy allows port 8080 from client with service account label to echo
	newTest("client-with-service-account-egress-to-echo", ct).
		WithCiliumPolicy(clientWithServiceAccountEgressToEchoPolicyYAML).
		WithScenarios(
			tests2.PodToPod(tests2.WithSourceLabelsOption(map[string]string{"kind": "client"})),
		)
}

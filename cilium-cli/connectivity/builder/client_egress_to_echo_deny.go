// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package builder

import (
	_ "embed"

	"github.com/cilium/cilium/cilium-cli/connectivity/check"
	"github.com/cilium/cilium/cilium-cli/connectivity/tests"
	"github.com/cilium/cilium/cilium-cli/utils/features"
)

//go:embed manifests/client-egress-to-echo-deny.yaml
var clientEgressToEchoDenyPolicyYAML string

//go:embed manifests/client-egress-to-echo-deny-port-range.yaml
var clientEgressToEchoDenyPolicyPortRangeYAML string

type clientEgressToEchoDeny struct{}

func (t clientEgressToEchoDeny) build(ct *check.ConnectivityTest, _ map[string]string) {
	clientEgressToEchoDenyTest(ct, false)
	if ct.Features[features.PortRanges].Enabled {
		clientEgressToEchoDenyTest(ct, true)
	}
}

func clientEgressToEchoDenyTest(ct *check.ConnectivityTest, portRanges bool) {
	testName := "client-egress-to-echo-deny"
	policyYAML := clientEgressToEchoDenyPolicyYAML
	if portRanges {
		testName = "client-egress-to-echo-deny-port-range"
		policyYAML = clientEgressToEchoDenyPolicyPortRangeYAML
	}
	// This policy denies port 8080 from client to echo
	newTest(testName, ct).
		WithCiliumPolicy(allowAllEgressPolicyYAML).  // Allow all egress traffic
		WithCiliumPolicy(allowAllIngressPolicyYAML). // Allow all ingress traffic
		WithCiliumPolicy(policyYAML).                // Deny client to echo traffic via port 8080
		WithScenarios(
			tests.ClientToClient(), // Client to client traffic should be allowed
			tests.PodToPod(),       // Client to echo traffic should be denied
		).
		WithExpectations(func(a *check.Action) (egress, ingress check.Result) {
			if a.Source().HasLabel("kind", "client") &&
				a.Destination().HasLabel("kind", "echo") &&
				a.Destination().Port() == 8080 {
				return check.ResultPolicyDenyEgressDrop, check.ResultNone
			}
			return check.ResultOK, check.ResultNone
		})
}

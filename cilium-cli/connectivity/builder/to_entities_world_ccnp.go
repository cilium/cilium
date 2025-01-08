// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package builder

import (
	_ "embed"

	"github.com/cilium/cilium/cilium-cli/connectivity/check"
	"github.com/cilium/cilium/cilium-cli/connectivity/tests"
	"github.com/cilium/cilium/cilium-cli/utils/features"
)

//go:embed manifests/client-egress-to-entities-world-ccnp.yaml
var clientEgressToEntitiesWorldCCNPPolicyYAML string

//go:embed manifests/client-egress-to-entities-world-port-range-ccnp.yaml
var clientEgressToEntitiesWorldCCNPPolicyPortRangeYAML string

type toEntitiesWorldCCNP struct{}

func (t toEntitiesWorldCCNP) build(ct *check.ConnectivityTest, _ map[string]string) {
	toEntitiesWorldCCNPTest(ct, false)
	if ct.Features[features.PortRanges].Enabled {
		toEntitiesWorldCCNPTest(ct, true)
	}
}

func toEntitiesWorldCCNPTest(ct *check.ConnectivityTest, portRanges bool) {
	testName := "to-entities-world-ccnp"
	policyYAML := clientEgressToEntitiesWorldCCNPPolicyYAML
	if portRanges {
		testName = "to-entities-world-port-range-ccnp"
		policyYAML = clientEgressToEntitiesWorldCCNPPolicyPortRangeYAML
	}
	newTest(testName, ct).
		WithCiliumClusterwidePolicy(policyYAML).
		WithScenarios(tests.PodToWorld(tests.WithRetryDestPort(80))).
		WithExpectations(func(a *check.Action) (egress, ingress check.Result) {
			if a.Destination().Port() == 80 {
				return check.ResultOK, check.ResultNone
			}
			return check.ResultDropCurlTimeout, check.ResultNone
		})
}

// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package builder

import (
	_ "embed"

	"github.com/cilium/cilium/cilium-cli/connectivity/check"
	"github.com/cilium/cilium/cilium-cli/connectivity/tests"
)

//go:embed manifests/deny-all-entities.yaml
var denyAllEntitiesPolicyYAML string

type allEntitiesDeny struct{}

func (t allEntitiesDeny) build(ct *check.ConnectivityTest, _ map[string]string) {
	// This policy denies all entities by default
	newTest("all-entities-deny", ct).
		WithCiliumPolicy(denyAllEntitiesPolicyYAML).
		WithScenarios(
			tests.PodToPod(),
			tests.PodToCIDR(),
		).
		WithExpectations(func(_ *check.Action) (egress, ingress check.Result) {
			return check.ResultPolicyDenyEgressDrop, check.ResultNone
		})
}

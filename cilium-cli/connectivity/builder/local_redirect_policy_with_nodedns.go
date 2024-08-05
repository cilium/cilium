// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package builder

import (
	_ "embed"

	"github.com/cilium/cilium/cilium-cli/connectivity/check"
	"github.com/cilium/cilium/cilium-cli/connectivity/tests"
	"github.com/cilium/cilium/cilium-cli/utils/features"
)

//go:embed manifests/client-egress-node-local-dns.yaml
var clientEgressNodeLocalDNSYAML string

type localRedirectPolicyWithNodeDNS struct{}

func (t localRedirectPolicyWithNodeDNS) build(ct *check.ConnectivityTest, templates map[string]string) {
	newTest("local-redirect-policy-with-node-dns", ct).
		WithCondition(func() bool { return ct.Params().IncludeUnsafeTests }).
		WithCiliumPolicy(templates["clientEgressNodeLocalDNSYAML"]).
		WithFeatureRequirements(
			features.RequireEnabled(features.NodeLocalDNS),
			features.RequireEnabled(features.NodeWithoutCilium),
			features.RequireEnabled(features.LocalRedirectPolicy),
			features.RequireEnabled(features.KPRSocketLB),
		).
		WithScenarios(
			tests.LRPWithNodeDNS(),
		)
}

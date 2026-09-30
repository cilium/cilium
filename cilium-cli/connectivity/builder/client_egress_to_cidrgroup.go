// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package builder

import (
	_ "embed"

	"github.com/cilium/cilium/cilium-cli/connectivity/check"
	"github.com/cilium/cilium/cilium-cli/connectivity/tests"
)

type clientEgressToCidrgroup struct{}

func (t clientEgressToCidrgroup) build(ct *check.ConnectivityTest, templates map[string]string) {
	// This policy allows all traffic to ExternalCIDR
	newTest("client-egress-to-cidrgroup", ct).
		WithCiliumVersion(">=1.21.0").
		WithCiliumPolicy(templates["clientEgressToCIDRGroupExternalPolicyYAML"]).
		WithScenarios(
			tests.PodToCIDR(
				tests.WithRetryDestIP(ct.Params().ExternalIPv4),
				tests.WithRetryDestIP(ct.Params().ExternalIPv6),
				tests.WithRetryDestIP(ct.Params().ExternalOtherIPv4),
				tests.WithRetryDestIP(ct.Params().ExternalOtherIPv6),
			),
		).
		WithExpectations(func(a *check.Action) (egress, ingress check.Result) {
			return check.ResultOK, check.ResultNone
		})
}

var (
	//go:embed manifests/client-egress-to-cidrgroup-external-world.yaml
	clientEgressToCIDRGroupExternalWorldPolicyYAML string
)

type clientEgressToCidrgroupWorld struct{}

func (t clientEgressToCidrgroupWorld) build(ct *check.ConnectivityTest, templates map[string]string) {
	// This policy allows all traffic to ExternalCIDR
	newTest("client-egress-to-cidrgroup-world", ct).
		WithCiliumVersion(">=1.21.0").
		WithCiliumPolicy(clientEgressToCIDRGroupExternalWorldPolicyYAML).
		WithScenarios(
			tests.PodToCIDR(
				tests.WithRetryDestIP(ct.Params().ExternalIPv4),
				tests.WithRetryDestIP(ct.Params().ExternalIPv6),
				tests.WithRetryDestIP(ct.Params().ExternalOtherIPv4),
				tests.WithRetryDestIP(ct.Params().ExternalOtherIPv6),
			),
		).
		WithExpectations(func(a *check.Action) (egress, ingress check.Result) {
			return check.ResultOK, check.ResultNone
		})
}

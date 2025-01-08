// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package builder

import (
	"github.com/cilium/cilium/cilium-cli/connectivity/check"
	"github.com/cilium/cilium/cilium-cli/connectivity/tests"
	"github.com/cilium/cilium/cilium-cli/utils/features"
)

type clientEgressToCidrgroupDeny struct{}

func (t clientEgressToCidrgroupDeny) build(ct *check.ConnectivityTest, templates map[string]string) {
	// This policy denies L3 traffic to ExternalCIDR except ExternalIP/32
	// It does so using a CiliumCIDRGroup
	newTest("client-egress-to-cidrgroup-deny", ct).
		WithCiliumVersion(">=1.17.0").
		WithCiliumPolicy(allowAllEgressPolicyYAML). // Allow all egress traffic
		WithCiliumPolicy(templates["clientEgressToCIDRGroupExternalDenyPolicyYAML"]).
		WithScenarios(
			tests.PodToCIDR(tests.WithRetryDestIP(ct.Params().ExternalIP)), // Denies all traffic to ExternalOtherIP, but allow ExternalIP
		).
		WithExpectations(func(a *check.Action) (egress, ingress check.Result) {
			if a.Destination().Address(features.GetIPFamily(ct.Params().ExternalOtherIP)) == ct.Params().ExternalOtherIP {
				return check.ResultPolicyDenyEgressDrop, check.ResultNone
			}
			if a.Destination().Address(features.GetIPFamily(ct.Params().ExternalIP)) == ct.Params().ExternalIP {
				return check.ResultOK, check.ResultNone
			}
			return check.ResultDrop, check.ResultDrop
		})
}

type clientEgressToCidrgroupDenyByLabel struct{}

// same as above, but references CIDRGroups by label, rather than name
func (t clientEgressToCidrgroupDenyByLabel) build(ct *check.ConnectivityTest, templates map[string]string) {
	// This policy denies L3 traffic to ExternalCIDR except ExternalIP/32
	// It does so using a CiliumCIDRGroup
	newTest("client-egress-to-cidrgroup-deny-by-label", ct).
		WithCiliumVersion(">=1.17.0").
		WithCiliumPolicy(allowAllEgressPolicyYAML). // Allow all egress traffic
		WithCiliumPolicy(templates["clientEgressToCIDRGroupExternalDenyLabelPolicyYAML"]).
		WithScenarios(
			tests.PodToCIDR(tests.WithRetryDestIP(ct.Params().ExternalIP)), // Denies all traffic to ExternalOtherIP, but allow ExternalIP
		).
		WithExpectations(func(a *check.Action) (egress, ingress check.Result) {
			if a.Destination().Address(features.GetIPFamily(ct.Params().ExternalOtherIP)) == ct.Params().ExternalOtherIP {
				return check.ResultPolicyDenyEgressDrop, check.ResultNone
			}
			if a.Destination().Address(features.GetIPFamily(ct.Params().ExternalIP)) == ct.Params().ExternalIP {
				return check.ResultOK, check.ResultNone
			}
			return check.ResultDrop, check.ResultDrop
		})
}

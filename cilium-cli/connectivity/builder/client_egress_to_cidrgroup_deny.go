// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package builder

import (
	"github.com/cilium/cilium/cilium-cli/connectivity/check"
	"github.com/cilium/cilium/cilium-cli/connectivity/tests"
	"github.com/cilium/cilium/cilium-cli/utils/features"
	"github.com/cilium/cilium/pkg/versioncheck"
)

type clientEgressToCidrgroupDeny struct{}

func (t clientEgressToCidrgroupDeny) build(ct *check.ConnectivityTest, templates map[string]string) {
	// This policy denies L3 traffic to ExternalCIDR except ExternalIP/32
	// It does so using a CiliumCIDRGroup
	policy := templates["clientEgressToCIDRGroupExternalDenyPolicyYAML"]
	if !versioncheck.MustCompile("<=1.17.0")(ct.CiliumVersion) {
		policy = templates["clientEgressToCIDRGroupExternalDenyPolicyV2Alpha1YAML"]
	}
	newTest("client-egress-to-cidrgroup-deny", ct).
		WithCiliumVersion(">=1.17.0").
		WithCiliumPolicy(allowAllEgressPolicyYAML). // Allow all egress traffic
		WithCiliumPolicy(policy).
		WithScenarios(
			tests.PodToCIDR(tests.WithRetryDestIP(ct.Params().ExternalIPv4)), // Denies all traffic to ExternalOtherIP, but allow ExternalIP
		).
		WithExpectations(func(a *check.Action) (egress, ingress check.Result) {
			if a.Destination().Address(features.GetIPFamily(ct.Params().ExternalOtherIPv4)) == ct.Params().ExternalOtherIPv4 ||
				a.Destination().Address(features.GetIPFamily(ct.Params().ExternalOtherIPv6)) == ct.Params().ExternalOtherIPv6 {
				return check.ResultPolicyDenyEgressDrop, check.ResultNone
			}
			if a.Destination().Address(features.GetIPFamily(ct.Params().ExternalIPv4)) == ct.Params().ExternalIPv4 ||
				a.Destination().Address(features.GetIPFamily(ct.Params().ExternalIPv6)) == ct.Params().ExternalIPv6 {
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
	policy := templates["clientEgressToCIDRGroupExternalDenyLabelPolicyYAML"]
	if !versioncheck.MustCompile("<=1.17.0")(ct.CiliumVersion) {
		policy = templates["clientEgressToCIDRGroupExternalDenyLabelPolicyV2Alpha1YAML"]
	}
	newTest("client-egress-to-cidrgroup-deny-by-label", ct).
		WithCiliumVersion(">=1.17.0").
		WithCiliumPolicy(allowAllEgressPolicyYAML). // Allow all egress traffic
		WithCiliumPolicy(policy).
		WithScenarios(
			tests.PodToCIDR(tests.WithRetryDestIP(ct.Params().ExternalIPv4)), // Denies all traffic to ExternalOtherIP, but allow ExternalIP
		).
		WithExpectations(func(a *check.Action) (egress, ingress check.Result) {
			if a.Destination().Address(features.GetIPFamily(ct.Params().ExternalOtherIPv4)) == ct.Params().ExternalOtherIPv4 ||
				a.Destination().Address(features.GetIPFamily(ct.Params().ExternalOtherIPv6)) == ct.Params().ExternalOtherIPv6 {
				return check.ResultPolicyDenyEgressDrop, check.ResultNone
			}
			if a.Destination().Address(features.GetIPFamily(ct.Params().ExternalIPv4)) == ct.Params().ExternalIPv4 ||
				a.Destination().Address(features.GetIPFamily(ct.Params().ExternalIPv6)) == ct.Params().ExternalIPv6 {
				return check.ResultOK, check.ResultNone
			}
			return check.ResultDrop, check.ResultDrop
		})
}

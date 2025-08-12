// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package builder

import (
	"fmt"
	"strings"

	"github.com/cilium/cilium/cilium-cli/connectivity/check"
	"github.com/cilium/cilium/cilium-cli/connectivity/tests"
	"github.com/cilium/cilium/cilium-cli/utils/features"
)

type clientEgressTlsSni struct{}

func (t clientEgressTlsSni) build(ct *check.ConnectivityTest, templates map[string]string) {
	clientEgressTlsSniTest(ct, templates)
	clientEgressL7TlsSniTest(ct, templates)
}

func clientEgressTlsSniTest(ct *check.ConnectivityTest, templates map[string]string) {
	testName := "client-egress-tls-sni"
	yamlFile := templates["clientEgressTLSSNIPolicyYAML"]
	// Test TLS SNI enforcement using an egress policy on the clients.
	newTest(testName, ct).
		WithCiliumVersion("!1.14.15 !1.14.16 !1.15.9 !1.15.10 !1.16.2 !1.16.3").
		WithFeatureRequirements(features.RequireEnabled(features.L7Proxy)).
		WithCiliumPolicy(yamlFile).                                   // L7 allow policy TLS SNI enforcement for external target
		WithCiliumPolicy(templates["clientEgressOnlyDNSPolicyYAML"]). // DNS resolution only
		WithScenarios(tests.PodToWorld(ct.Params().ExternalTargetIPv6Capable)).
		WithExpectations(func(a *check.Action) (egress, ingress check.Result) {
			if a.Destination().Port() == 443 {
				return check.ResultOK, check.ResultNone
			}
			return check.ResultDefaultDenyEgressDrop, check.ResultNone
		})

	yamlFile = templates["clientEgressTLSSNIOtherPolicyYAML"]
	newTest(fmt.Sprintf("%s-denied", testName), ct).
		WithCiliumVersion("!1.14.15 !1.14.16 !1.15.9 !1.15.10 !1.16.2 !1.16.3").
		WithFeatureRequirements(features.RequireEnabled(features.L7Proxy)).
		WithCiliumPolicy(yamlFile).                                             // L7 allow policy TLS SNI enforcement for external target
		WithCiliumPolicy(templates["clientEgressOnlyDNSPolicyYAML"]).           // DNS resolution only
		WithScenarios(tests.PodToWorld(ct.Params().ExternalTargetIPv6Capable)). // External Target is not allowed
		WithExpectations(func(a *check.Action) (egress, ingress check.Result) {
			if a.Destination().Port() == 443 {
				// SSL error as another external target (e.g. cilium.io) SNI is not allowed
				return check.ResultCurlSSLError, check.ResultNone
			}
			return check.ResultDefaultDenyEgressDrop, check.ResultNone
		})

	yamlFile = templates["clientEgressTLSSNIWildcardPolicyYAML"]
	newTest(fmt.Sprintf("%s-wildcard", testName), ct).
		WithCiliumVersion(">=1.18.0").
		WithFeatureRequirements(features.RequireEnabled(features.L7Proxy)).
		WithCiliumPolicy(yamlFile).                                   // L7 allow policy TLS SNI enforcement for external target
		WithCiliumPolicy(templates["clientEgressOnlyDNSPolicyYAML"]). // DNS resolution only
		WithScenarios(tests.PodToWorld(ct.Params().ExternalTargetIPv6Capable)).
		WithExpectations(func(a *check.Action) (egress, ingress check.Result) {
			if a.Destination().Port() == 443 {
				return check.ResultOK, check.ResultNone
			}
			return check.ResultDefaultDenyEgressDrop, check.ResultNone
		})

	yamlFile = templates["clientEgressTLSSNIWildcardPolicyYAML"]
	newTest(fmt.Sprintf("%s-wildcard-denied", testName), ct).
		WithCiliumVersion(">=1.18.0").
		WithFeatureRequirements(features.RequireEnabled(features.L7Proxy)).
		WithCiliumPolicy(yamlFile).                                   // L7 allow policy TLS SNI enforcement for external target
		WithCiliumPolicy(templates["clientEgressOnlyDNSPolicyYAML"]). // DNS resolution only
		WithScenarios(tests.PodToWorld2(ct.Params().ExternalTargetIPv6Capable)).
		WithExpectations(func(a *check.Action) (egress, ingress check.Result) {
			if a.Destination().Port() == 443 {
				// SSL error as another external target (e.g. cilium.io) SNI is not allowed
				return check.ResultCurlSSLError, check.ResultNone
			}
			return check.ResultDefaultDenyEgressDrop, check.ResultNone
		})

	// Only the double wildcard related tests if the external is long enough
	// e.g. google.com. or k8s.io. will be skipped
	if len(strings.Split(ct.Params().ExternalTarget, ".")) > 3 {
		yamlFile = templates["clientEgressTLSSNIDoubleWildcardPolicyYAML"]
		newTest(fmt.Sprintf("%s-double-wildcard", testName), ct).
			WithCiliumVersion(">=1.18.0").
			WithFeatureRequirements(features.RequireEnabled(features.L7Proxy)).
			WithCiliumPolicy(yamlFile).                                   // L7 allow policy TLS SNI enforcement for external target
			WithCiliumPolicy(templates["clientEgressOnlyDNSPolicyYAML"]). // DNS resolution only
			WithScenarios(tests.PodToWorld(ct.Params().ExternalTargetIPv6Capable)).
			WithExpectations(func(a *check.Action) (egress, ingress check.Result) {
				if a.Destination().Port() == 443 {
					return check.ResultOK, check.ResultNone
				}
				return check.ResultDefaultDenyEgressDrop, check.ResultNone
			})

		yamlFile = templates["clientEgressTLSSNIDoubleWildcardPolicyYAML"]
		newTest(fmt.Sprintf("%s-double-wildcard-denied", testName), ct).
			WithCiliumVersion(">=1.18.0").
			WithFeatureRequirements(features.RequireEnabled(features.L7Proxy)).
			WithCiliumPolicy(yamlFile).                                   // L7 allow policy TLS SNI enforcement for external target
			WithCiliumPolicy(templates["clientEgressOnlyDNSPolicyYAML"]). // DNS resolution only
			WithScenarios(tests.PodToWorld2(ct.Params().ExternalTargetIPv6Capable)).
			WithExpectations(func(a *check.Action) (egress, ingress check.Result) {
				if a.Destination().Port() == 443 {
					// SSL error as another external target (e.g. cilium.io) SNI is not allowed
					return check.ResultCurlSSLError, check.ResultNone
				}
				return check.ResultDefaultDenyEgressDrop, check.ResultNone
			})
	}
}

func clientEgressL7TlsSniTest(ct *check.ConnectivityTest, templates map[string]string) {
	testName := "client-egress-l7-tls-headers-sni"
	yamlFile := templates["clientEgressL7TLSSNIPolicyYAML"]
	// Test TLS SNI enforcement using an egress policy on the clients.
	newTest(testName, ct).
		WithCiliumVersion("!1.14.15 !1.14.16 !1.15.9 !1.15.10 !1.16.2 !1.16.3").
		WithFeatureRequirements(features.RequireEnabled(features.L7Proxy)).
		WithFeatureRequirements(features.RequireEnabled(features.PolicySecretsOnlyFromSecretsNamespace)).
		WithCABundleSecret().
		WithCertificate("externaltarget-tls", ct.Params().ExternalTarget).
		WithCiliumPolicy(yamlFile).                                   // L7 allow policy TLS SNI enforcement
		WithCiliumPolicy(templates["clientEgressOnlyDNSPolicyYAML"]). // DNS resolution only
		WithScenarios(tests.PodToWorldWithTLSIntercept("-H", "X-Very-Secret-Token: 42")).
		WithExpectations(func(a *check.Action) (egress, ingress check.Result) {
			return check.ResultOK, check.ResultNone
		})

	// This test is similar to the previous one, but with a different SNI.
	// So the expectation is curl ssl error (e.g. exit code 35) instead.
	testName = "client-egress-l7-tls-headers-other-sni"
	yamlFile = templates["clientEgressL7TLSOtherSNIPolicyYAML"]
	newTest(testName, ct).
		WithCiliumVersion("!1.14.15 !1.14.16 !1.15.9 !1.15.10 !1.16.2 !1.16.3").
		WithFeatureRequirements(features.RequireEnabled(features.L7Proxy)).
		WithFeatureRequirements(features.RequireEnabled(features.PolicySecretsOnlyFromSecretsNamespace)).
		WithCABundleSecret().
		WithCertificate("externaltarget-tls", ct.Params().ExternalTarget).
		WithCiliumPolicy(yamlFile).                                   // L7 allow policy TLS SNI enforcement
		WithCiliumPolicy(templates["clientEgressOnlyDNSPolicyYAML"]). // DNS resolution only
		WithScenarios(tests.PodToWorldWithTLSIntercept("-H", "X-Very-Secret-Token: 42")).
		WithExpectations(func(a *check.Action) (egress, ingress check.Result) {
			if a.Destination().Port() == 443 {
				// SSL error as another external target (e.g. cilium.io) SNI is not allowed
				return check.ResultCurlSSLError, check.ResultNone
			}
			return check.ResultDefaultDenyEgressDrop, check.ResultNone
		})
}

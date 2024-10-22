// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package builder

import (
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/cilium/cilium/cilium-cli/connectivity/check"
	"github.com/cilium/cilium/cilium-cli/connectivity/tests"
	"github.com/cilium/cilium/cilium-cli/utils/features"
)

type clientEgressL7SetHeader struct{}

func (t clientEgressL7SetHeader) build(ct *check.ConnectivityTest, templates map[string]string) {
	clientEgressL7SetHeaderTest(ct, templates, false)
	if ct.Features[features.PortRanges].Enabled {
		clientEgressL7SetHeaderTest(ct, templates, true)
	}
}

func clientEgressL7SetHeaderTest(ct *check.ConnectivityTest, templates map[string]string, portRanges bool) {
	testName := "client-egress-l7-set-header"
	templateName := "clientEgressL7HTTPMatchheaderSecretYAML"
	if portRanges {
		testName = "client-egress-l7-set-header-port-range"
		templateName = "clientEgressL7HTTPMatchheaderSecretPortRangeYAML"
	}
	// Test L7 HTTP with a header replace set in the policy
	newTest(testName, ct).
		WithFeatureRequirements(features.RequireEnabled(features.L7Proxy)).
		WithFeatureRequirements(features.RequireEnabled(features.SecretBackendK8s)).
		WithSecret(&corev1.Secret{
			ObjectMeta: metav1.ObjectMeta{
				Name: "header-match",
			},
			Data: map[string][]byte{
				"value": []byte("Bearer 123456"),
			},
		}).
		WithCiliumPolicy(templates[templateName]). // L7 allow policy with HTTP introspection (POST only)
		WithScenarios(
			tests.PodToPodWithEndpoints(tests.WithMethod("POST"), tests.WithPath("auth-header-required"), tests.WithDestinationLabelsOption(map[string]string{"other": "echo"})),
			tests.PodToPodWithEndpoints(tests.WithMethod("POST"), tests.WithPath("auth-header-required"), tests.WithDestinationLabelsOption(map[string]string{"first": "echo"})),
		).
		WithExpectations(func(a *check.Action) (egress, ingress check.Result) {
			if a.Source().HasLabel("other", "client") && // Only client2 has the header policy.
				(a.Destination().Port() == 8080) { // port 8080 is traffic to echo Pod.
				return check.ResultOK, check.ResultNone
			}
			return check.ResultCurlHTTPError, check.ResultNone // if the header is not set the request will get a 401
		})
}

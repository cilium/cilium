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

type toFqdns struct{}

func (t toFqdns) build(ct *check.ConnectivityTest, templates map[string]string) {
	// This policy only allows port 80 to domain-name, default one.one.one.one., DNS proxy enabled.
	newTest("to-fqdns", ct).
		WithCiliumPolicy(templates["clientEgressToFQDNsPolicyYAML"]).
		WithFeatureRequirements(features.RequireEnabled(features.L7Proxy)).
		WithScenarios(
			tests.PodToWorld(tests.WithRetryDestPort(80)),
			tests.PodToWorld2(), // resolves cilium.io.
		).
		WithExpectations(func(a *check.Action) (egress, ingress check.Result) {
			if a.Destination().Address(features.IPFamilyAny) == "cilium.io." {
				if a.Destination().Path() == "/" || a.Destination().Path() == "" {
					egress = check.ResultDNSOK
					egress.HTTP = check.HTTP{
						Method: "GET",
						URL:    "https://cilium.io",
					}
					// Expect packets for cilium.io / 104.198.14.52 to be dropped.
					return check.ResultDropCurlTimeout, check.ResultNone
				}
				// Else expect HTTP drop by proxy
				return check.ResultDNSOKDropCurlHTTPError, check.ResultNone
			}

			extTarget := ct.Params().ExternalTarget
			if a.Destination().Port() == 80 && a.Destination().Address(features.GetIPFamily(extTarget)) == extTarget {
				if a.Destination().Path() == "/" || a.Destination().Path() == "" {
					egress = check.ResultDNSOK
					egress.HTTP = check.HTTP{
						Method: "GET",
						// Trim the trailing dot, if any, to match the behavior of the curl
						// action and make sure that flow validation can succeed.
						URL: fmt.Sprintf("http://%s/", strings.TrimSuffix(extTarget, ".")),
					}
					return egress, check.ResultNone
				}
				// Else expect HTTP drop by proxy
				return check.ResultDNSOKDropCurlHTTPError, check.ResultNone
			}
			// No HTTP proxy on other ports
			return check.ResultDNSOKDropCurlTimeout, check.ResultNone
		})
}

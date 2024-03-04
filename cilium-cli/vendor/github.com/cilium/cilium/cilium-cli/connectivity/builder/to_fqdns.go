// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package builder

import (
	"fmt"
	check2 "github.com/cilium/cilium/cilium-cli/connectivity/check"
	tests2 "github.com/cilium/cilium/cilium-cli/connectivity/tests"
	"strings"

	"github.com/cilium/cilium-cli/utils/features"
)

type toFqdns struct{}

func (t toFqdns) build(ct *check2.ConnectivityTest, templates map[string]string) {
	// This policy only allows port 80 to domain-name, default one.one.one.one., DNS proxy enabled.
	newTest("to-fqdns", ct).
		WithCiliumPolicy(templates["clientEgressToFQDNsPolicyYAML"]).
		WithFeatureRequirements(features.RequireEnabled(features.L7Proxy)).
		WithScenarios(
			tests2.PodToWorld(tests2.WithRetryDestPort(80)),
			tests2.PodToWorld2(), // resolves cilium.io.
		).
		WithExpectations(func(a *check2.Action) (egress, ingress check2.Result) {
			if a.Destination().Address(features.IPFamilyAny) == "cilium.io." {
				if a.Destination().Path() == "/" || a.Destination().Path() == "" {
					egress = check2.ResultDNSOK
					egress.HTTP = check2.HTTP{
						Method: "GET",
						URL:    "https://cilium.io",
					}
					// Expect packets for cilium.io / 104.198.14.52 to be dropped.
					return check2.ResultDropCurlTimeout, check2.ResultNone
				}
				// Else expect HTTP drop by proxy
				return check2.ResultDNSOKDropCurlHTTPError, check2.ResultNone
			}

			extTarget := ct.Params().ExternalTarget
			if a.Destination().Port() == 80 && a.Destination().Address(features.GetIPFamily(extTarget)) == extTarget {
				if a.Destination().Path() == "/" || a.Destination().Path() == "" {
					egress = check2.ResultDNSOK
					egress.HTTP = check2.HTTP{
						Method: "GET",
						// Trim the trailing dot, if any, to match the behavior of the curl
						// action and make sure that flow validation can succeed.
						URL: fmt.Sprintf("http://%s/", strings.TrimSuffix(extTarget, ".")),
					}
					return egress, check2.ResultNone
				}
				// Else expect HTTP drop by proxy
				return check2.ResultDNSOKDropCurlHTTPError, check2.ResultNone
			}
			// No HTTP proxy on other ports
			return check2.ResultDNSOKDropCurlTimeout, check2.ResultNone
		})
}

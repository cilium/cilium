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
		WithCiliumPolicy(templates["clientEgressOnlyDNSPolicyYAML"]).
		WithScenarios(
			tests.PodToWorld(ct.Params().ExternalTargetIPv6Capable, tests.WithRetryDestPort(80)),
			tests.PodToWorld2(ct.Params().ExternalTargetIPv6Capable), // resolves to ExternalOtherTarget
		).
		WithExpectations(func(a *check.Action) (egress, ingress check.Result) {
			if a.Destination().Address(features.IPFamilyAny) == ct.Params().ExternalOtherTarget {
				if a.Destination().Path() == "/" || a.Destination().Path() == "" {
					// Expect packets to other external target to be dropped.
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

type toFqdnsWithProxy struct{}

func (t toFqdnsWithProxy) build(ct *check.ConnectivityTest, templates map[string]string) {
	// This policy only allows port 80 to domain-name, default one.one.one.one., DNS proxy enabled.
	newTest("to-fqdns-with-proxy", ct).
		WithCiliumPolicy(templates["clientEgressToFQDNsAndHTTPGetPolicyYAML"]).
		WithCiliumPolicy(templates["clientEgressOnlyDNSPolicyYAML"]).
		WithFeatureRequirements(features.RequireEnabled(features.L7Proxy)).
		WithScenarios(
			// TODO: Reenable IPv6 for this test once the kernel with the bugfix is released:
			// https://patchwork.kernel.org/project/netdevbpf/patch/20250318161516.3791383-1-maxim@isovalent.com/
			tests.PodToWorld(false, tests.WithRetryDestPort(80)),
			tests.PodToWorld2(false), // resolves to ExternalOtherTarget
		).
		WithExpectations(func(a *check.Action) (egress, ingress check.Result) {
			if a.Destination().Address(features.IPFamilyAny) == ct.Params().ExternalOtherTarget {
				if a.Destination().Path() == "/" || a.Destination().Path() == "" {
					// Expect packets to other external target to be dropped.
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

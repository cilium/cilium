// Copyright 2020-2021 Authors of Cilium
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package connectivity

import (
	"context"
	_ "embed"

	"github.com/cilium/cilium-cli/connectivity/check"
	"github.com/cilium/cilium-cli/connectivity/tests"
)

var (
	//go:embed manifests/allow-all.yaml
	allowAllPolicyYAML string

	//go:embed manifests/client-egress-only-dns.yaml
	clientEgressOnlyDNSPolicyYAML string

	//go:embed manifests/client-egress-to-echo.yaml
	clientEgressToEchoPolicyYAML string

	//go:embed manifests/client-ingress-from-client2.yaml
	clientIngressFromClient2PolicyYAML string

	//go:embed manifests/client-egress-to-fqdns-google.yaml
	clientEgressToFQDNsGooglePolicyYAML string
)

func Run(ctx context.Context, k *check.K8sConnectivityCheck) error {
	return k.Run(ctx,
		// First all tests without policies
		&tests.PodToPod{},
		&tests.ClientToClient{},
		&tests.PodToService{},
		&tests.PodToNodePort{},
		&tests.PodToLocalNodePort{},
		&tests.PodToWorld{},
		&tests.PodToHost{},
		&tests.PodToExternalWorkload{},

		// Then test with an allow-all policy
		(&check.PolicyContext{}).WithPolicy(allowAllPolicyYAML),
		&tests.PodToPod{Variant: "-allow-all"},
		&tests.ClientToClient{Variant: "-allow-all"},
		&tests.PodToService{Variant: "-allow-all"},
		&tests.PodToNodePort{Variant: "-allow-all"},
		&tests.PodToLocalNodePort{Variant: "-allow-all"},
		&tests.PodToWorld{Variant: "-allow-all"},
		&tests.PodToHost{Variant: "-allow-all"},
		&tests.PodToExternalWorkload{Variant: "-allow-all"},
		// By itself this should fail, but allow-all policy is in effect so this succeeds
		(&tests.PodToPod{Variant: "-client-egress-only-dns-with-allow-all"}).WithPolicy(clientEgressOnlyDNSPolicyYAML),
		(&check.PolicyContext{}).WithPolicy(""), // delete all applied policies

		// This policy allows ingress from client2 to client only
		(&tests.ClientToClient{Variant: "-client-ingress-from-client"}).
			WithPolicy(clientIngressFromClient2PolicyYAML).
			WithExpectations(func(t *check.TestRun) (egress, ingress check.Result) {
				if t.Src.HasLabel("other", "client") {
					return check.ResultOK, check.ResultOK
				} else {
					return check.ResultOK, check.ResultDrop
				}
			}),

		// Now this should fail as allow-all policy is not in effect any more
		(&tests.PodToPod{Variant: "-client-egress-only-dns"}).
			WithPolicy(clientEgressOnlyDNSPolicyYAML).
			WithExpectations(func(t *check.TestRun) (egress, ingress check.Result) {
				return check.ResultDrop, check.ResultNone
			}),

		// Policy installed with 'WithPolicy()' is automatically removed, so this should succeed:
		&tests.PodToPod{Variant: "-no-policy"},

		// This policy allows port 8080 from client to echo, so this should succeed
		(&tests.PodToPod{Variant: "-client-egress-to-echo"}).WithPolicy(clientEgressToEchoPolicyYAML),

		// This policy only allows port 80 to "google.com"
		(&tests.PodToWorld{Variant: "-toFQDNs"}).
			WithPolicy(clientEgressToFQDNsGooglePolicyYAML).
			WithExpectations(func(t *check.TestRun) (egress, ingress check.Result) {
				if t.DstPort == 80 && t.Dst.Address() == "google.com" {
					egress = check.ResultDNSOK
					egress.HTTP = check.HTTP{
						Method: "GET",
						URL:    "http://google.com/",
					}
					return egress, check.ResultNone
				}
				return check.ResultDNSDrop, check.ResultNone
			}),
	)
}

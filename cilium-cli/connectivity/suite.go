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

	//go:embed manifests/echo-ingress-from-other-client.yaml
	echoIngressFromOtherClientPolicyYAML string

	//go:embed manifests/client-egress-to-entities-world.yaml
	clientEgressToEntitiesWorldPolicyYAML string

	//go:embed manifests/client-egress-to-cidr-1111.yaml
	clientEgressToCIDR1111PolicyYAML string
)

func Run(ctx context.Context, ct *check.ConnectivityTest) error {
	// Run all tests without any policies in place.
	ct.NewTest("no-policies").WithScenarios(
		tests.PodToPod(""),
		tests.ClientToClient(""),
		tests.PodToService(""),
		tests.PodToRemoteNodePort(""),
		tests.PodToLocalNodePort(""),
		tests.PodToWorld(""),
		tests.PodToHost(""),
		tests.PodToExternalWorkload(""),
		tests.PodToCIDR(""),
	)

	// Test with an allow-all policy.
	ct.NewTest("allow-all").WithPolicy(allowAllPolicyYAML).
		WithScenarios(
			tests.PodToPod(""),
			tests.ClientToClient(""),
			tests.PodToService(""),
			tests.PodToRemoteNodePort(""),
			tests.PodToLocalNodePort(""),
			tests.PodToWorld(""),
			tests.PodToHost(""),
			tests.PodToExternalWorkload(""),
		)

	// Only allow UDP:53 to kube-dns, no DNS proxy enabled.
	ct.NewTest("dns-only").WithPolicy(clientEgressOnlyDNSPolicyYAML).
		WithScenarios(
			tests.PodToPod(""),   // connects to other Pods directly, no DNS
			tests.PodToWorld(""), // resolves google.com
		).
		WithExpectations(
			func(a *check.Action) (egress check.Result, ingress check.Result) {
				return check.ResultDrop, check.ResultNone
			})

	// This policy only allows ingress into client from client2.
	ct.NewTest("client-ingress").WithPolicy(clientIngressFromClient2PolicyYAML).
		WithScenarios(
			tests.ClientToClient(""),
		).WithExpectations(func(a *check.Action) (egress, ingress check.Result) {
		if a.Source().HasLabel("other", "client") {
			return check.ResultOK, check.ResultOK
		}
		return check.ResultOK, check.ResultDrop
	})

	// This policy allows ingress to echo only from client with a label 'other:client'.
	ct.NewTest("echo-ingress").WithPolicy(echoIngressFromOtherClientPolicyYAML).
		WithScenarios(
			tests.PodToPod(""),
		).
		WithExpectations(func(a *check.Action) (egress, ingress check.Result) {
			if a.Destination().HasLabel("kind", "echo") && !a.Source().HasLabel("other", "client") {
				// TCP handshake fails both in egress and ingress when
				// L3(/L4) policy drops at either location.
				return check.ResultDrop, check.ResultDrop
			}
			return check.ResultOK, check.ResultOK
		})

	// This policy allows port 8080 from client to echo, so this should succeed
	ct.NewTest("client-egress").WithPolicy(clientEgressToEchoPolicyYAML).
		WithScenarios(
			tests.PodToPod(""),
		)

	// This policy only allows port 80 to "google.com". DNS proxy enabled.
	ct.NewTest("to-fqdns").WithPolicy(clientEgressToFQDNsGooglePolicyYAML).
		WithScenarios(
			tests.PodToWorld(""),
		).WithExpectations(func(a *check.Action) (egress, ingress check.Result) {

		if a.Destination().Port() == 80 && a.Destination().Address() == "google.com" {
			egress = check.ResultDNSOK
			egress.HTTP = check.HTTP{
				Method: "GET",
				URL:    "http://google.com/",
			}
			return egress, check.ResultNone
		}

		return check.ResultDNSOKRequestDrop, check.ResultNone
	})

	// This policy allows UDP to kube-dns and port 80 TCP to all 'world' endpoints.
	ct.NewTest("to-entities-world").
		WithPolicy(clientEgressToEntitiesWorldPolicyYAML).
		WithScenarios(
			tests.PodToWorld(""),
		).
		WithExpectations(func(a *check.Action) (egress, ingress check.Result) {
			if a.Destination().Port() == 80 {
				return check.ResultOK, check.ResultNone
			}
			// PodToWorld traffic to port 443 will be dropped by the policy
			return check.ResultDrop, check.ResultNone
		})

	// This policy allows L3 traffic to 1.0.0.0/24 (including 1.1.1.1), with the
	// exception of 1.0.0.1.
	ct.NewTest("to-cidr-1111").
		WithPolicy(clientEgressToCIDR1111PolicyYAML).
		WithScenarios(
			tests.PodToCIDR(""),
		).
		WithExpectations(func(a *check.Action) (egress, ingress check.Result) {
			if a.Destination().Address() == "1.0.0.1" {
				// Expect packets for 1.0.0.1 to be dropped.
				return check.ResultDrop, check.ResultNone
			}
			return check.ResultOK, check.ResultNone
		})

	// Dummy tests for debugging the testing harness.
	// ct.NewTest("dummy-1").WithScenarios(tests.Dummy("dummy-scenario-1"))
	// ct.NewTest("dummy-2").WithScenarios(tests.Dummy("dummy-scenario-2"))

	return ct.Run(ctx)
}

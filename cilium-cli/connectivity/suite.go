// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package connectivity

import (
	"context"
	_ "embed"

	"github.com/blang/semver/v4"

	"github.com/cilium/cilium/pkg/versioncheck"

	"github.com/cilium/cilium-cli/connectivity/check"
	"github.com/cilium/cilium-cli/connectivity/tests"
	"github.com/cilium/cilium-cli/defaults"
	"github.com/cilium/cilium-cli/internal/utils"
)

var (
	//go:embed manifests/allow-all-egress.yaml
	allowAllEgressPolicyYAML string

	//go:embed manifests/allow-all-ingress.yaml
	allowAllIngressPolicyYAML string

	//go:embed manifests/deny-all-egress.yaml
	denyAllEgressPolicyYAML string

	//go:embed manifests/deny-all-ingress.yaml
	denyAllIngressPolicyYAML string

	//go:embed manifests/deny-all-entities.yaml
	denyAllEntitiesPolicyYAML string

	//go:embed manifests/allow-cluster-entity.yaml
	allowClusterEntityPolicyYAML string

	//go:embed manifests/allow-host-entity.yaml
	allowHostEntityPolicyYAML string

	//go:embed manifests/allow-all-except-world.yaml
	allowAllExceptWorldPolicyYAML string
	//go:embed manifests/allow-all-except-world-pre-v1.11.yaml
	allowAllExceptWorldPolicyPre1_11YAML string

	//go:embed manifests/client-egress-only-dns.yaml
	clientEgressOnlyDNSPolicyYAML string

	//go:embed manifests/client-egress-to-echo.yaml
	clientEgressToEchoPolicyYAML string

	//go:embed manifests/client-egress-to-echo-service-account.yaml
	clientEgressToEchoServiceAccountPolicyYAML string

	//go:embed manifests/client-egress-to-echo-expression.yaml
	clientEgressToEchoExpressionPolicyYAML string

	//go:embed manifests/client-egress-to-echo-deny.yaml
	clientEgressToEchoDenyPolicyYAML string

	//go:embed manifests/client-egress-to-echo-expression-deny.yaml
	clientEgressToEchoExpressionDenyPolicyYAML string

	//go:embed manifests/client-egress-to-echo-service-account-deny.yaml
	clientEgressToEchoServiceAccountDenyPolicyYAML string

	//go:embed manifests/client-egress-to-echo-named-port-deny.yaml
	clientEgressToEchoDenyNamedPortPolicyYAML string

	//go:embed manifests/client-ingress-from-client2.yaml
	clientIngressFromClient2PolicyYAML string

	//go:embed manifests/client-egress-to-fqdns-one-one-one-one.yaml
	clientEgressToFQDNsCiliumIOPolicyYAML string

	//go:embed manifests/echo-ingress-from-other-client.yaml
	echoIngressFromOtherClientPolicyYAML string

	//go:embed manifests/echo-ingress-from-other-client-deny.yaml
	echoIngressFromOtherClientDenyPolicyYAML string

	//go:embed manifests/client-egress-to-entities-world.yaml
	clientEgressToEntitiesWorldPolicyYAML string

	//go:embed manifests/client-egress-to-cidr-1111.yaml
	clientEgressToCIDR1111PolicyYAML string

	//go:embed manifests/client-egress-to-cidr-1111-deny.yaml
	clientEgressToCIDR1111DenyPolicyYAML string

	//go:embed manifests/client-egress-l7-http.yaml
	clientEgressL7HTTPPolicyYAML string

	//go:embed manifests/client-egress-l7-http-method.yaml
	clientEgressL7HTTPMethodPolicyYAML string

	//go:embed manifests/client-egress-l7-http-named-port.yaml
	clientEgressL7HTTPNamedPortPolicyYAML string

	//go:embed manifests/echo-ingress-l7-http.yaml
	echoIngressL7HTTPPolicyYAML string

	//go:embed manifests/echo-ingress-l7-http-named-port.yaml
	echoIngressL7HTTPNamedPortPolicyYAML string

	//go:embed manifests/echo-ingress-icmp.yaml
	echoIngressICMPPolicyYAML string

	//go:embed manifests/echo-ingress-icmp-deny.yaml
	echoIngressICMPDenyPolicyYAML string
)

func Run(ctx context.Context, ct *check.ConnectivityTest) error {
	if err := ct.SetupAndValidate(ctx); err != nil {
		return err
	}

	var v semver.Version
	if assumeCiliumVersion := ct.Params().AssumeCiliumVersion; assumeCiliumVersion != "" {
		ct.Warnf("Assuming Cilium version %s for connectivity tests", assumeCiliumVersion)
		var err error
		v, err = utils.ParseCiliumVersion(assumeCiliumVersion)
		if err != nil {
			return err
		}
	} else if minVersion, err := ct.DetectMinimumCiliumVersion(ctx); err != nil {
		ct.Warnf("Unable to detect Cilium version, assuming %v for connectivity tests: %s", defaults.Version, err)
		v, err = utils.ParseCiliumVersion(defaults.Version)
		if err != nil {
			return err
		}
	} else {
		v = *minVersion
	}

	ct.Infof("Cilium version: %v", v)

	// Network Performance Test
	if ct.Params().Perf {
		ct.NewTest("network-perf").WithScenarios(
			tests.NetperfPodtoPod(""),
		)
		return ct.Run(ctx)
	}

	// Datapath Conformance Tests
	if ct.Params().Datapath {
		ct.NewTest("north-south-loadbalancing").
			WithFeatureRequirements(check.RequireFeatureEnabled(check.FeatureNodeWithoutCilium)).
			WithScenarios(
				tests.OutsideToNodePort(),
			)

		return ct.Run(ctx)
	}

	// Run all tests without any policies in place.
	ct.NewTest("no-policies").WithScenarios(
		tests.PodToPod(),
		tests.ClientToClient(),
		tests.PodToService(),
		tests.PodToRemoteNodePort(),
		tests.PodToLocalNodePort(),
		tests.PodToHostPort(),
		tests.PodToWorld(),
		tests.PodToHost(),
		tests.PodToExternalWorkload(),
		tests.PodToCIDR(),
	)

	// Test with an allow-all-except-world (and unmanaged) policy.
	if v.GTE(versioncheck.MustVersion("1.11.0")) {
		ct.NewTest("allow-all-except-world").WithPolicy(allowAllExceptWorldPolicyYAML).
			WithScenarios(
				tests.PodToPod(),
				tests.ClientToClient(),
				tests.PodToService(),
				// We are skipping the following checks because NodePort is
				// intended to be used for N-S traffic, which conflicts with
				// policies. See GH-17144.
				// tests.PodToRemoteNodePort(),
				// tests.PodToLocalNodePort(),
				tests.PodToHost(),
				tests.PodToExternalWorkload(),
			)
	} else {
		ct.NewTest("allow-all-except-world").WithPolicy(allowAllExceptWorldPolicyPre1_11YAML).
			WithScenarios(
				tests.PodToPod(),
				tests.ClientToClient(),
				tests.PodToService(),
				// We are skipping the following checks because NodePort is
				// intended to be used for N-S traffic, which conflicts with
				// policies. See GH-17144.
				// tests.PodToRemoteNodePort(),
				// tests.PodToLocalNodePort(),
				tests.PodToHost(),
				tests.PodToExternalWorkload(),
			)
	}

	// This policy only allows ingress into client from client2.
	ct.NewTest("client-ingress").WithPolicy(clientIngressFromClient2PolicyYAML).
		WithScenarios(
			tests.ClientToClient(),
		).
		WithExpectations(func(a *check.Action) (egress, ingress check.Result) {
			if a.Source().HasLabel("other", "client") {
				return check.ResultOK, check.ResultOK
			}
			return check.ResultOK, check.ResultDrop
		})

	// This policy denies all ingresses by default
	ct.NewTest("all-ingress-deny").
		WithPolicy(denyAllIngressPolicyYAML).
		WithScenarios(
			// Pod to Pod fails because there is no egress policy (so egress traffic originating from a pod is allowed),
			// but then at the destination there is ingress policy that denies the traffic.
			tests.PodToPod(),
			// Egress to world works because there is no egress policy (so egress traffic originating from a pod is allowed),
			// then when replies come back, they are considered as "replies" to the outbound connection.
			// so they are not subject to ingress policy.
			tests.PodToCIDR(),
		).
		WithExpectations(func(a *check.Action) (egress, ingress check.Result) {
			if a.Destination().Address() == "1.0.0.1" || a.Destination().Address() == "1.1.1.1" {
				return check.ResultOK, check.ResultNone
			}
			return check.ResultDrop, check.ResultNone
		})

	// This policy denies all egresses by default
	ct.NewTest("all-egress-deny").
		WithPolicy(denyAllEgressPolicyYAML).
		WithScenarios(
			tests.PodToPod(),
			tests.PodToPodWithEndpoints(),
		).
		WithExpectations(func(a *check.Action) (egress, ingress check.Result) {
			return check.ResultDrop, check.ResultNone
		})

	// This policy denies all entities by default
	ct.NewTest("all-entities-deny").
		WithPolicy(denyAllEntitiesPolicyYAML).
		WithScenarios(
			tests.PodToPod(),
			tests.PodToCIDR(),
		).
		WithExpectations(func(a *check.Action) (egress, ingress check.Result) {
			return check.ResultDrop, check.ResultNone
		})

	// This policy allows cluster entity
	ct.NewTest("cluster-entity").
		WithPolicy(allowClusterEntityPolicyYAML).
		WithScenarios(
			// Only enable to local cluster for now due to the below
			// https://github.com/cilium/cilium/blob/88c4dddede2a3b5b9a7339c1316a0dedd7229a26/pkg/policy/api/entity.go#L126
			tests.PodToPod(tests.WithDestinationLabelsOption(map[string]string{"name": "echo-same-node"})),
		).
		WithExpectations(func(a *check.Action) (egress, ingress check.Result) {
			return check.ResultOK, check.ResultOK
		})

	if ct.Params().MultiCluster != "" {
		ct.NewTest("cluster-entity-multi-cluster").
			WithPolicy(allowClusterEntityPolicyYAML).
			WithScenarios(
				tests.PodToPod(tests.WithDestinationLabelsOption(map[string]string{"name": "echo-other-node"})),
			).
			WithExpectations(func(a *check.Action) (egress, ingress check.Result) {
				return check.ResultDrop, check.ResultNone
			})
	}

	// This policy allows host entity
	ct.NewTest("host-entity").
		WithPolicy(allowHostEntityPolicyYAML).
		WithScenarios(
			tests.PodToHost(),
		).
		WithExpectations(func(a *check.Action) (egress, ingress check.Result) {
			return check.ResultOK, check.ResultNone
		})

	// This policy allows ingress to echo only from client with a label 'other:client'.
	ct.NewTest("echo-ingress").WithPolicy(echoIngressFromOtherClientPolicyYAML).
		WithScenarios(
			tests.PodToPod(),
		).
		WithExpectations(func(a *check.Action) (egress, ingress check.Result) {
			if a.Destination().HasLabel("kind", "echo") && !a.Source().HasLabel("other", "client") {
				// TCP handshake fails both in egress and ingress when
				// L3(/L4) policy drops at either location.
				return check.ResultDropCurlTimeout, check.ResultDropCurlTimeout
			}
			return check.ResultOK, check.ResultOK
		})

	// This policy allowed ICMP traffic from client to another client.
	ct.NewTest("client-ingress-icmp").WithPolicy(echoIngressICMPPolicyYAML).
		WithFeatureRequirements(check.RequireFeatureEnabled(check.FeatureICMPPolicy)).
		WithScenarios(
			tests.ClientToClient(),
		).
		WithExpectations(func(a *check.Action) (egress, ingress check.Result) {
			if a.Source().HasLabel("other", "client") {
				return check.ResultOK, check.ResultOK
			}
			return check.ResultOK, check.ResultDrop
		})

	// This policy allows port 8080 from client to echo, so this should succeed
	ct.NewTest("client-egress").WithPolicy(clientEgressToEchoPolicyYAML).
		WithScenarios(
			tests.PodToPod(),
		)

	// This policy allows port 8080 from client to echo (using label match expression, so this should succeed
	ct.NewTest("client-egress-expression").WithPolicy(clientEgressToEchoExpressionPolicyYAML).
		WithScenarios(
			tests.PodToPod(),
		)

	// This policy allows port 8080 from client to echo (using service account)
	ct.NewTest("client-egress-to-echo-service-account").
		WithPolicy(clientEgressToEchoServiceAccountPolicyYAML).
		WithScenarios(
			tests.PodToPod(tests.WithSourceLabelsOption(map[string]string{"kind": "client"})),
		)

	// This policy allows UDP to kube-dns and port 80 TCP to all 'world' endpoints.
	ct.NewTest("to-entities-world").
		WithPolicy(clientEgressToEntitiesWorldPolicyYAML).
		WithScenarios(
			tests.PodToWorld(),
		).
		WithExpectations(func(a *check.Action) (egress, ingress check.Result) {
			if a.Destination().Port() == 80 {
				return check.ResultOK, check.ResultNone
			}
			// PodToWorld traffic to port 443 will be dropped by the policy
			return check.ResultDropCurlTimeout, check.ResultNone
		})

	// This policy allows L3 traffic to 1.0.0.0/24 (including 1.1.1.1), with the
	// exception of 1.0.0.1.
	ct.NewTest("to-cidr-1111").
		WithPolicy(clientEgressToCIDR1111PolicyYAML).
		WithScenarios(
			tests.PodToCIDR(),
		).
		WithExpectations(func(a *check.Action) (egress, ingress check.Result) {
			if a.Destination().Address() == "1.0.0.1" {
				// Expect packets for 1.0.0.1 to be dropped.
				return check.ResultDropCurlTimeout, check.ResultNone
			}
			return check.ResultOK, check.ResultNone
		})

	// Test L7 HTTP introspection using an ingress policy on echo pods.
	ct.NewTest("echo-ingress-l7").
		WithFeatureRequirements(check.RequireFeatureEnabled(check.FeatureL7Proxy)).
		WithPolicy(echoIngressL7HTTPPolicyYAML). // L7 allow policy with HTTP introspection
		WithScenarios(
			tests.PodToPodWithEndpoints(),
		).
		WithExpectations(func(a *check.Action) (egress, ingress check.Result) {
			if a.Source().HasLabel("other", "client") { // Only client2 is allowed to make HTTP calls.
				// Trying to access private endpoint without "secret" header set
				// should lead to a drop.
				if a.Destination().Path() == "/private" && !a.Destination().HasLabel("X-Very-Secret-Token", "42") {
					return check.ResultDropCurlHTTPError, check.ResultNone
				}
				egress = check.ResultOK
				// Expect all curls from client2 to be proxied and to be GET calls.
				egress.HTTP = check.HTTP{
					Method: "GET",
				}
				return egress, check.ResultNone
			}
			return check.ResultDrop, check.ResultNone
		})

	// Test L7 HTTP introspection using an ingress policy on echo pods.
	ct.NewTest("echo-ingress-l7-named-port").
		WithFeatureRequirements(check.RequireFeatureEnabled(check.FeatureL7Proxy)).
		WithPolicy(echoIngressL7HTTPNamedPortPolicyYAML). // L7 allow policy with HTTP introspection (named port)
		WithScenarios(
			tests.PodToPodWithEndpoints(),
		).
		WithExpectations(func(a *check.Action) (egress, ingress check.Result) {
			if a.Source().HasLabel("other", "client") { // Only client2 is allowed to make HTTP calls.
				// Trying to access private endpoint without "secret" header set
				// should lead to a drop.
				if a.Destination().Path() == "/private" && !a.Destination().HasLabel("X-Very-Secret-Token", "42") {
					return check.ResultDropCurlHTTPError, check.ResultNone
				}
				egress = check.ResultOK
				// Expect all curls from client2 to be proxied and to be GET calls.
				egress.HTTP = check.HTTP{
					Method: "GET",
				}
				return egress, check.ResultNone
			}
			return check.ResultDrop, check.ResultNone
		})

	// Tests with deny policy
	ct.NewTest("echo-ingress-from-other-client-deny").
		WithPolicy(allowAllEgressPolicyYAML).                 // Allow all egress traffic
		WithPolicy(allowAllIngressPolicyYAML).                // Allow all ingress traffic
		WithPolicy(echoIngressFromOtherClientDenyPolicyYAML). // Deny other client contact echo
		WithScenarios(
			tests.PodToPod(tests.WithSourceLabelsOption(map[string]string{"name": "client"})),  // Client to echo should be allowed
			tests.PodToPod(tests.WithSourceLabelsOption(map[string]string{"name": "client2"})), // Client2 to echo should be denied
			tests.ClientToClient(), // Client to client should be allowed
		).
		WithExpectations(func(a *check.Action) (egress, ingress check.Result) {
			if a.Source().HasLabel("other", "client") &&
				a.Destination().HasLabel("kind", "echo") {
				return check.ResultDrop, check.ResultNone
			}
			return check.ResultOK, check.ResultOK
		})

	// This policy denies ICMP ingress to client only from other client
	ct.NewTest("client-ingress-from-other-client-icmp-deny").
		WithPolicy(allowAllEgressPolicyYAML).      // Allow all egress traffic
		WithPolicy(allowAllIngressPolicyYAML).     // Allow all ingress traffic
		WithPolicy(echoIngressICMPDenyPolicyYAML). // Deny ICMP traffic from client to another client
		WithFeatureRequirements(check.RequireFeatureEnabled(check.FeatureICMPPolicy)).
		WithScenarios(
			tests.PodToPod(),       // Client to echo traffic should be allowed
			tests.ClientToClient(), // Client to client traffic should be denied
		).
		WithExpectations(func(a *check.Action) (egress, ingress check.Result) {
			if a.Source().HasLabel("other", "client") &&
				a.Destination().HasLabel("kind", "client") {
				return check.ResultDrop, check.ResultNone
			}
			return check.ResultOK, check.ResultNone
		})

	// This policy denies port 8080 from client to echo
	ct.NewTest("client-egress-to-echo-deny").
		WithPolicy(allowAllEgressPolicyYAML).         // Allow all egress traffic
		WithPolicy(allowAllIngressPolicyYAML).        // Allow all ingress traffic
		WithPolicy(clientEgressToEchoDenyPolicyYAML). // Deny client to echo traffic via port 8080
		WithScenarios(
			tests.ClientToClient(), // Client to client traffic should be allowed
			tests.PodToPod(),       // Client to echo traffic should be denied
		).
		WithExpectations(func(a *check.Action) (egress, ingress check.Result) {
			if a.Source().HasLabel("kind", "client") &&
				a.Destination().HasLabel("kind", "echo") &&
				a.Destination().Port() == 8080 {
				return check.ResultDrop, check.ResultNone
			}
			return check.ResultOK, check.ResultNone
		})

	//     This policy denies port http-8080 from client to echo, but allows traffic from client2 to echo
	ct.NewTest("client-ingress-to-echo-named-port-deny").
		WithPolicy(allowAllEgressPolicyYAML).  // Allow all egress traffic
		WithPolicy(allowAllIngressPolicyYAML). // Allow all ingress traffic
		WithPolicy(clientEgressToEchoDenyNamedPortPolicyYAML).
		WithScenarios(
			tests.PodToPod(tests.WithSourceLabelsOption(map[string]string{"name": "client"})),  // Client to echo should be denied
			tests.PodToPod(tests.WithSourceLabelsOption(map[string]string{"name": "client2"})), // Client2 to echo should be allowed
		).
		WithExpectations(func(a *check.Action) (egress, ingress check.Result) {
			if a.Destination().HasLabel("kind", "echo") &&
				a.Source().HasLabel("name", "client") {
				return check.ResultDropCurlTimeout, check.ResultNone
			}
			return check.ResultOK, check.ResultOK
		})

	// This policy denies port 8080 from client to echo (using label match expression), but allows traffic from client2
	ct.NewTest("client-egress-to-echo-expression-deny").
		WithPolicy(allowAllEgressPolicyYAML).  // Allow all egress traffic
		WithPolicy(allowAllIngressPolicyYAML). // Allow all ingress traffic
		WithPolicy(clientEgressToEchoExpressionDenyPolicyYAML).
		WithScenarios(
			tests.PodToPod(tests.WithSourceLabelsOption(map[string]string{"name": "client"})),  // Client to echo should be denied
			tests.PodToPod(tests.WithSourceLabelsOption(map[string]string{"name": "client2"})), // Client2 to echo should be allowed
		).
		WithExpectations(func(a *check.Action) (egress, ingress check.Result) {
			if a.Destination().HasLabel("kind", "echo") &&
				a.Source().HasLabel("name", "client") {
				return check.ResultDrop, check.ResultNone
			}
			return check.ResultOK, check.ResultOK
		})

	// This policy denies port 8080 from client to echo, but not from client2
	ct.NewTest("client-egress-to-echo-service-account-deny").
		WithPolicy(allowAllEgressPolicyYAML).  // Allow all egress traffic
		WithPolicy(allowAllIngressPolicyYAML). // Allow all ingress traffic
		WithPolicy(clientEgressToEchoServiceAccountDenyPolicyYAML).
		WithScenarios(
			tests.PodToPod(tests.WithSourceLabelsOption(map[string]string{"name": "client"})),  // Client to echo should be denied
			tests.PodToPod(tests.WithSourceLabelsOption(map[string]string{"name": "client2"})), // Client2 to echo should be allowed
		).
		WithExpectations(func(a *check.Action) (egress, ingress check.Result) {
			if a.Destination().HasLabel("kind", "echo") &&
				a.Source().HasLabel("name", "client") {
				return check.ResultDrop, check.ResultNone
			}
			return check.ResultOK, check.ResultOK
		})

	// This policy denies L3 traffic to 1.0.0.1/8 CIDR except 1.1.1.1/32
	ct.NewTest("client-egress-to-cidr-deny").
		WithPolicy(allowAllEgressPolicyYAML). // Allow all egress traffic
		WithPolicy(clientEgressToCIDR1111DenyPolicyYAML).
		WithScenarios(
			tests.PodToCIDR(), // Denies all traffic to 1.0.0.1, but allow 1.1.1.1
		).
		WithExpectations(func(a *check.Action) (egress, ingress check.Result) {
			if a.Destination().Address() == "1.0.0.1" {
				return check.ResultDrop, check.ResultNone
			}
			if a.Destination().Address() == "1.1.1.1" {
				return check.ResultOK, check.ResultNone
			}
			return check.ResultDrop, check.ResultDrop
		})

	// Health check tests.
	ct.NewTest("health").
		WithFeatureRequirements(check.RequireFeatureEnabled(check.FeatureHealthChecking)).
		WithScenarios(tests.CiliumHealth())

	// The following tests have DNS redirect policies. They should be executed last.

	// Test L7 HTTP with different methods introspection using an egress policy on the clients.
	ct.NewTest("client-egress-l7-method").
		WithFeatureRequirements(check.RequireFeatureEnabled(check.FeatureL7Proxy)).
		WithPolicy(clientEgressOnlyDNSPolicyYAML).      // DNS resolution only
		WithPolicy(clientEgressL7HTTPMethodPolicyYAML). // L7 allow policy with HTTP introspection (POST only)
		WithScenarios(
			tests.PodToPodWithEndpoints(tests.WithMethod("POST"), tests.WithDestinationLabelsOption(map[string]string{"other": "echo"})),
			tests.PodToPodWithEndpoints(tests.WithDestinationLabelsOption(map[string]string{"first": "echo"})),
		).
		WithExpectations(func(a *check.Action) (egress, ingress check.Result) {
			if a.Source().HasLabel("other", "client") && // Only client2 is allowed to make HTTP calls.
				(a.Destination().Port() == 8080) { // port 8080 is traffic to echo Pod.
				if a.Destination().HasLabel("other", "echo") { //we are POSTing only other echo
					egress = check.ResultOK

					egress.HTTP = check.HTTP{
						Method: "POST",
					}
					return egress, check.ResultNone
				}
				// Else expect HTTP drop by proxy
				return check.ResultDropCurlHTTPError, check.ResultNone
			}
			return check.ResultDrop, check.ResultNone
		})

	// Test L7 HTTP introspection using an egress policy on the clients.
	ct.NewTest("client-egress-l7").
		WithFeatureRequirements(check.RequireFeatureEnabled(check.FeatureL7Proxy)).
		WithPolicy(clientEgressOnlyDNSPolicyYAML). // DNS resolution only
		WithPolicy(clientEgressL7HTTPPolicyYAML).  // L7 allow policy with HTTP introspection
		WithScenarios(
			tests.PodToPod(),
			tests.PodToWorld(),
		).
		WithExpectations(func(a *check.Action) (egress, ingress check.Result) {
			if a.Source().HasLabel("other", "client") && // Only client2 is allowed to make HTTP calls.
				// Outbound HTTP to one.one.one.one is L7-introspected and allowed.
				(a.Destination().Port() == 80 && a.Destination().Address() == "one.one.one.one" ||
					a.Destination().Port() == 8080) { // 8080 is traffic to echo Pod.
				if a.Destination().Path() == "/" || a.Destination().Path() == "" {
					egress = check.ResultOK
					// Expect all curls from client2 to be proxied and to be GET calls.
					egress.HTTP = check.HTTP{
						Method: "GET",
					}
					return egress, check.ResultNone
				}
				// Else expect HTTP drop by proxy
				return check.ResultDNSOKDropCurlHTTPError, check.ResultNone
			}
			return check.ResultDrop, check.ResultNone
		})

	// Test L7 HTTP named port introspection using an egress policy on the clients.
	ct.NewTest("client-egress-l7-named-port").
		WithFeatureRequirements(check.RequireFeatureEnabled(check.FeatureL7Proxy)).
		WithPolicy(clientEgressOnlyDNSPolicyYAML).         // DNS resolution only
		WithPolicy(clientEgressL7HTTPNamedPortPolicyYAML). // L7 allow policy with HTTP introspection (named port)
		WithScenarios(
			tests.PodToPod(),
			tests.PodToWorld(),
		).
		WithExpectations(func(a *check.Action) (egress, ingress check.Result) {
			if a.Source().HasLabel("other", "client") && // Only client2 is allowed to make HTTP calls.
				// Outbound HTTP to one.one.one.one is L7-introspected and allowed.
				(a.Destination().Port() == 80 && a.Destination().Address() == "one.one.one.one" ||
					a.Destination().Port() == 8080) { // named port http-8080 is traffic to echo Pod.
				if a.Destination().Path() == "/" || a.Destination().Path() == "" {
					egress = check.ResultOK
					// Expect all curls from client2 to be proxied and to be GET calls.
					egress.HTTP = check.HTTP{
						Method: "GET",
					}
					return egress, check.ResultNone
				}
				// Else expect HTTP drop by proxy
				return check.ResultDNSOKDropCurlHTTPError, check.ResultNone
			}
			return check.ResultDrop, check.ResultNone
		})

	// Only allow UDP:53 to kube-dns, no DNS proxy enabled.
	ct.NewTest("dns-only").WithPolicy(clientEgressOnlyDNSPolicyYAML).
		WithFeatureRequirements(check.RequireFeatureEnabled(check.FeatureL7Proxy)).
		WithScenarios(
			tests.PodToPod(),   // connects to other Pods directly, no DNS
			tests.PodToWorld(), // resolves one.one.one.one
		).
		WithExpectations(func(a *check.Action) (egress check.Result, ingress check.Result) {
			return check.ResultDropCurlTimeout, check.ResultNone
		})

	// This policy only allows port 80 to "one.one.one.one". DNS proxy enabled.
	ct.NewTest("to-fqdns").WithPolicy(clientEgressToFQDNsCiliumIOPolicyYAML).
		WithFeatureRequirements(check.RequireFeatureEnabled(check.FeatureL7Proxy)).
		WithScenarios(
			tests.PodToWorld(),
			tests.PodToWorld2(), // resolves cilium.io
		).
		WithExpectations(func(a *check.Action) (egress, ingress check.Result) {
			if a.Destination().Address() == "cilium.io" {
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

			if a.Destination().Port() == 80 && a.Destination().Address() == "one.one.one.one" {
				if a.Destination().Path() == "/" || a.Destination().Path() == "" {
					egress = check.ResultDNSOK
					egress.HTTP = check.HTTP{
						Method: "GET",
						URL:    "http://one.one.one.one/",
					}
					return egress, check.ResultNone
				}
				// Else expect HTTP drop by proxy
				return check.ResultDNSOKDropCurlHTTPError, check.ResultNone
			}
			// No HTTP proxy on other ports
			return check.ResultDNSOKDropCurlTimeout, check.ResultNone
		})

	// Tests with DNS redirects to the proxy (e.g., client-egress-l7, dns-only,
	// and to-fqdns) should always be executed last. See #367 for details.

	return ct.Run(ctx)
}

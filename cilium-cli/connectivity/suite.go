// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package connectivity

import (
	"context"
	_ "embed"
	"fmt"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/cilium/cilium/pkg/versioncheck"

	"github.com/cilium/cilium-cli/connectivity/check"
	"github.com/cilium/cilium-cli/connectivity/manifests/template"
	"github.com/cilium/cilium-cli/connectivity/tests"
)

var (
	//go:embed manifests/allow-all-egress.yaml
	allowAllEgressPolicyYAML string

	//go:embed manifests/allow-all-ingress.yaml
	allowAllIngressPolicyYAML string

	//go:embed manifests/deny-all-egress.yaml
	denyAllEgressPolicyYAML string

	//go:embed manifests/deny-all-egress-knp.yaml
	denyAllEgressPolicyKNPYAML string

	//go:embed manifests/deny-all-ingress.yaml
	denyAllIngressPolicyYAML string

	//go:embed manifests/deny-all-ingress-knp.yaml
	denyAllIngressPolicyKNPYAML string

	//go:embed manifests/deny-all-entities.yaml
	denyAllEntitiesPolicyYAML string

	//go:embed manifests/allow-cluster-entity.yaml
	allowClusterEntityPolicyYAML string

	//go:embed manifests/allow-host-entity.yaml
	allowHostEntityPolicyYAML string

	//go:embed manifests/allow-all-except-world.yaml
	allowAllExceptWorldPolicyYAML string

	//go:embed manifests/allow-ingress-identity.yaml
	allowIngressIdentityPolicyYAML string

	//go:embed manifests/client-egress-only-dns.yaml
	clientEgressOnlyDNSPolicyYAML string

	//go:embed manifests/client-egress-to-echo.yaml
	clientEgressToEchoPolicyYAML string

	//go:embed manifests/client-egress-to-echo-knp.yaml
	clientEgressToEchoPolicyKNPYAML string

	//go:embed manifests/client-with-service-account-egress-to-echo.yaml
	clientWithServiceAccountEgressToEchoPolicyYAML string

	//go:embed manifests/client-egress-to-echo-service-account.yaml
	clientEgressToEchoServiceAccountPolicyYAML string

	//go:embed manifests/client-egress-to-echo-expression.yaml
	clientEgressToEchoExpressionPolicyYAML string

	//go:embed manifests/client-egress-to-echo-expression-knp.yaml
	clientEgressToEchoExpressionPolicyKNPYAML string

	//go:embed manifests/client-egress-to-echo-deny.yaml
	clientEgressToEchoDenyPolicyYAML string

	//go:embed manifests/client-egress-to-echo-expression-deny.yaml
	clientEgressToEchoExpressionDenyPolicyYAML string

	//go:embed manifests/client-with-service-account-egress-to-echo-deny.yaml
	clientWithServiceAccountEgressToEchoDenyPolicyYAML string

	//go:embed manifests/client-egress-to-echo-service-account-deny.yaml
	clientEgressToEchoServiceAccountDenyPolicyYAML string

	//go:embed manifests/client-egress-to-echo-named-port-deny.yaml
	clientEgressToEchoDenyNamedPortPolicyYAML string

	//go:embed manifests/client-ingress-from-client2.yaml
	clientIngressFromClient2PolicyYAML string

	//go:embed manifests/client-ingress-from-client2-knp.yaml
	clientIngressFromClient2PolicyKNPYAML string

	//go:embed manifests/client-egress-to-fqdns-one-one-one-one.yaml
	clientEgressToFQDNsCiliumIOPolicyYAML string

	//go:embed manifests/echo-ingress-from-other-client.yaml
	echoIngressFromOtherClientPolicyYAML string

	//go:embed manifests/echo-ingress-from-other-client-knp.yaml
	echoIngressFromOtherClientPolicyKNPYAML string

	//go:embed manifests/echo-ingress-from-other-client-deny.yaml
	echoIngressFromOtherClientDenyPolicyYAML string

	//go:embed manifests/client-egress-to-entities-world.yaml
	clientEgressToEntitiesWorldPolicyYAML string

	//go:embed manifests/client-egress-to-cidr-external.yaml
	clientEgressToCIDRExternalPolicyYAML string

	//go:embed manifests/client-egress-to-cidr-external-knp.yaml
	clientEgressToCIDRExternalPolicyKNPYAML string

	//go:embed manifests/client-egress-to-cidr-external-deny.yaml
	clientEgressToCIDRExternalDenyPolicyYAML string

	//go:embed manifests/client-egress-l7-http.yaml
	clientEgressL7HTTPPolicyYAML string

	//go:embed manifests/client-egress-l7-http-method.yaml
	clientEgressL7HTTPMethodPolicyYAML string

	//go:embed manifests/client-egress-l7-http-named-port.yaml
	clientEgressL7HTTPNamedPortPolicyYAML string

	//go:embed manifests/client-egress-l7-tls.yaml
	clientEgressL7TLSPolicyYAML string

	//go:embed manifests/client-egress-l7-http-matchheader-secret.yaml
	clientEgressL7HTTPMatchheaderSecretYAML string

	//go:embed manifests/echo-ingress-l7-http.yaml
	echoIngressL7HTTPPolicyYAML string

	//go:embed manifests/echo-ingress-l7-http-from-anywhere.yaml
	echoIngressL7HTTPFromAnywherePolicyYAML string

	//go:embed manifests/echo-ingress-l7-http-named-port.yaml
	echoIngressL7HTTPNamedPortPolicyYAML string

	//go:embed manifests/echo-ingress-icmp.yaml
	echoIngressICMPPolicyYAML string

	//go:embed manifests/echo-ingress-icmp-deny.yaml
	echoIngressICMPDenyPolicyYAML string

	//go:embed manifests/echo-ingress-from-cidr.yaml
	echoIngressFromCIDRYAML string

	//go:embed manifests/echo-ingress-mutual-authentication-fail.yaml
	echoIngressAuthFailPolicyYAML string

	//go:embed manifests/echo-ingress-mutual-authentication.yaml
	echoIngressMutualAuthPolicyYAML string

	//go:embed manifests/egress-gateway-policy.yaml
	egressGatewayPolicyYAML string

	//go:embed manifests/egress-gateway-policy-excluded-cidrs.yaml
	egressGatewayPolicyExcludedCIDRsYAML string
)

var (
	clientLabel  = map[string]string{"name": "client"}
	client2Label = map[string]string{"name": "client2"}
)

func Run(ctx context.Context, ct *check.ConnectivityTest, addExtraTests func(*check.ConnectivityTest) error,
	addExtraSetup func(context.Context, *check.ConnectivityTest) error) error {
	if err := ct.SetupAndValidate(ctx, addExtraSetup); err != nil {
		return err
	}

	renderedTemplates := map[string]string{}

	// render templates, if any problems fail early
	for key, temp := range map[string]string{
		"clientEgressToCIDRExternalPolicyYAML":     clientEgressToCIDRExternalPolicyYAML,
		"clientEgressToCIDRExternalPolicyKNPYAML":  clientEgressToCIDRExternalPolicyKNPYAML,
		"clientEgressToCIDRExternalDenyPolicyYAML": clientEgressToCIDRExternalDenyPolicyYAML,
		"clientEgressL7HTTPPolicyYAML":             clientEgressL7HTTPPolicyYAML,
		"clientEgressL7HTTPNamedPortPolicyYAML":    clientEgressL7HTTPNamedPortPolicyYAML,
		"clientEgressToFQDNsCiliumIOPolicyYAML":    clientEgressToFQDNsCiliumIOPolicyYAML,
		"clientEgressL7TLSPolicyYAML":              clientEgressL7TLSPolicyYAML,
		"clientEgressL7HTTPMatchheaderSecretYAML":  clientEgressL7HTTPMatchheaderSecretYAML,
		"echoIngressFromCIDRYAML":                  echoIngressFromCIDRYAML,
	} {
		val, err := template.Render(temp, ct.Params())
		if err != nil {
			return err
		}
		renderedTemplates[key] = val
	}

	ct.Infof("Cilium version: %v", ct.CiliumVersion)

	// Network Performance Test
	if ct.Params().Perf {
		ct.NewTest("network-perf").WithScenarios(
			tests.NetperfPodtoPod(""),
		)
		return ct.Run(ctx)
	}

	// Conn disrupt Test
	if ct.Params().IncludeConnDisruptTest {
		ct.NewTest("no-interrupted-connections").WithScenarios(
			tests.NoInterruptedConnections(),
		)

		ct.NewTest("no-ipsec-xfrm-errors").
			WithFeatureRequirements(check.RequireFeatureMode(check.FeatureEncryptionPod, "ipsec")).
			WithScenarios(tests.NoIPsecXfrmErrors())

		if ct.Params().ConnDisruptTestSetup {
			// Exit early, as --conn-disrupt-test-setup is only needed to deploy pods which
			// will be used by another invocation of "cli connectivity test" (with
			// include --include-conn-disrupt-test"
			return ct.Run(ctx)
		}

		ct.NewTest("no-missed-tail-calls").WithScenarios(tests.NoMissedTailCalls())
	}

	// Run all tests without any policies in place.
	noPoliciesScenarios := []check.Scenario{
		tests.PodToPod(),
		tests.ClientToClient(),
		tests.PodToService(),
		tests.PodToHostPort(),
		tests.PodToWorld(tests.WithRetryAll()),
		tests.PodToHost(),
		tests.PodToExternalWorkload(),
		tests.PodToCIDR(tests.WithRetryAll()),
	}

	ct.NewTest("no-policies").WithScenarios(noPoliciesScenarios...)

	if ct.Params().IncludeUnsafeTests {
		ct.NewTest("no-policies-from-outside").
			WithFeatureRequirements(check.RequireFeatureEnabled(check.FeatureNodeWithoutCilium)).
			WithIPRoutesFromOutsideToPodCIDRs().
			WithScenarios(tests.FromCIDRToPod())
	}

	// Skip the nodeport-related tests in the multicluster scenario if KPR is not
	// enabled, since global nodeport services are not supported in that case.
	var reqs []check.FeatureRequirement
	if ct.Params().MultiCluster != "" {
		reqs = append(reqs, check.RequireFeatureEnabled(check.FeatureKPRNodePort))
	}

	ct.NewTest("no-policies-extra").
		WithFeatureRequirements(reqs...).
		WithScenarios(
			tests.PodToRemoteNodePort(),
			tests.PodToLocalNodePort(),
		)

	// Test with an allow-all-except-world (and unmanaged) policy.
	ct.NewTest("allow-all-except-world").WithCiliumPolicy(allowAllExceptWorldPolicyYAML).
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

	// This policy only allows ingress into client from client2.
	ct.NewTest("client-ingress").WithCiliumPolicy(clientIngressFromClient2PolicyYAML).
		WithScenarios(
			tests.ClientToClient(),
		).
		WithExpectations(func(a *check.Action) (egress, ingress check.Result) {
			if a.Source().HasLabel("other", "client") {
				return check.ResultOK, check.ResultOK
			}
			return check.ResultOK, check.ResultDefaultDenyIngressDrop
		})

	// Run a simple test with k8s Network Policy.
	ct.NewTest("client-ingress-knp").WithK8SPolicy(clientIngressFromClient2PolicyKNPYAML).
		WithScenarios(
			tests.ClientToClient(),
		).
		WithExpectations(func(a *check.Action) (egress, ingress check.Result) {
			if a.Source().HasLabel("other", "client") {
				return check.ResultOK, check.ResultOK
			}
			return check.ResultOK, check.ResultDefaultDenyIngressDrop
		})

	// This policy allows traffic pod to pod and checks if the metric cilium_forward_count_total increases on cilium agent.
	ct.NewTest("allow-all-with-metrics-check").
		WithScenarios(
			tests.PodToPod(),
		).
		WithExpectations(func(a *check.Action) (egress, ingress check.Result) {
			return check.ResultOK.ExpectMetricsIncrease(ct.CiliumAgentMetrics(), "cilium_forward_count_total"),
				check.ResultOK.ExpectMetricsIncrease(ct.CiliumAgentMetrics(), "cilium_forward_count_total")
		})

	// This policy denies all ingresses by default.
	//
	// 1. Pod to Pod fails because there is no egress policy (so egress traffic originating from a pod is allowed),
	//    but then at the destination there is ingress policy that denies the traffic.
	// 2. Egress to world works because there is no egress policy (so egress traffic originating from a pod is allowed),
	//    then when replies come back, they are considered as "replies" to the outbound connection.
	//    so they are not subject to ingress policy.
	allIngressDenyScenarios := []check.Scenario{tests.PodToPod(), tests.PodToCIDR(tests.WithRetryAll())}
	ct.NewTest("all-ingress-deny").WithCiliumPolicy(denyAllIngressPolicyYAML).
		WithScenarios(allIngressDenyScenarios...).
		WithExpectations(func(a *check.Action) (egress, ingress check.Result) {
			if a.Destination().Address(check.GetIPFamily(ct.Params().ExternalOtherIP)) == ct.Params().ExternalOtherIP ||
				a.Destination().Address(check.GetIPFamily(ct.Params().ExternalIP)) == ct.Params().ExternalIP {
				return check.ResultOK, check.ResultNone
			}
			return check.ResultDrop, check.ResultDefaultDenyIngressDrop
		})

	if ct.Params().IncludeUnsafeTests {
		ct.NewTest("all-ingress-deny-from-outside").WithCiliumPolicy(denyAllIngressPolicyYAML).
			WithFeatureRequirements(check.RequireFeatureEnabled(check.FeatureNodeWithoutCilium)).
			WithIPRoutesFromOutsideToPodCIDRs().
			WithScenarios(tests.FromCIDRToPod()).
			WithExpectations(func(a *check.Action) (egress, ingress check.Result) {
				if a.Destination().Address(check.GetIPFamily(ct.Params().ExternalOtherIP)) == ct.Params().ExternalOtherIP ||
					a.Destination().Address(check.GetIPFamily(ct.Params().ExternalIP)) == ct.Params().ExternalIP {
					return check.ResultOK, check.ResultNone
				}
				return check.ResultDrop, check.ResultDefaultDenyIngressDrop
			})
	}

	// This policy denies all ingresses by default
	ct.NewTest("all-ingress-deny-knp").WithK8SPolicy(denyAllIngressPolicyKNPYAML).
		WithScenarios(
			// Pod to Pod fails because there is no egress policy (so egress traffic originating from a pod is allowed),
			// but then at the destination there is ingress policy that denies the traffic.
			tests.PodToPod(),
			// Egress to world works because there is no egress policy (so egress traffic originating from a pod is allowed),
			// then when replies come back, they are considered as "replies" to the outbound connection.
			// so they are not subject to ingress policy.
			tests.PodToCIDR(tests.WithRetryAll()),
		).
		WithExpectations(func(a *check.Action) (egress, ingress check.Result) {
			if a.Destination().Address(check.GetIPFamily(ct.Params().ExternalOtherIP)) == ct.Params().ExternalOtherIP ||
				a.Destination().Address(check.GetIPFamily(ct.Params().ExternalIP)) == ct.Params().ExternalIP {
				return check.ResultOK, check.ResultNone
			}
			return check.ResultDrop, check.ResultDefaultDenyIngressDrop
		})

	// This policy denies all egresses by default
	ct.NewTest("all-egress-deny").WithCiliumPolicy(denyAllEgressPolicyYAML).
		WithScenarios(
			tests.PodToPod(),
			tests.PodToPodWithEndpoints(),
		).
		WithExpectations(func(a *check.Action) (egress, ingress check.Result) {
			return check.ResultDefaultDenyEgressDrop, check.ResultNone
		})

	// This policy denies all egresses by default using KNP.
	ct.NewTest("all-egress-deny-knp").WithK8SPolicy(denyAllEgressPolicyKNPYAML).
		WithScenarios(
			tests.PodToPod(),
			tests.PodToPodWithEndpoints(),
		).
		WithExpectations(func(a *check.Action) (egress, ingress check.Result) {
			return check.ResultDefaultDenyEgressDrop, check.ResultNone
		})

	// This policy denies all entities by default
	ct.NewTest("all-entities-deny").WithCiliumPolicy(denyAllEntitiesPolicyYAML).
		WithScenarios(
			tests.PodToPod(),
			tests.PodToCIDR(),
		).
		WithExpectations(func(a *check.Action) (egress, ingress check.Result) {
			return check.ResultPolicyDenyEgressDrop, check.ResultNone
		})

	// This policy allows cluster entity
	ct.NewTest("cluster-entity").WithCiliumPolicy(allowClusterEntityPolicyYAML).
		WithScenarios(
			// Only enable to local cluster for now due to the below
			// https://github.com/cilium/cilium/blob/88c4dddede2a3b5b9a7339c1316a0dedd7229a26/pkg/policy/api/entity.go#L126
			tests.PodToPod(tests.WithDestinationLabelsOption(map[string]string{"name": "echo-same-node"})),
		).
		WithExpectations(func(a *check.Action) (egress, ingress check.Result) {
			return check.ResultOK, check.ResultOK
		})

	if ct.Params().MultiCluster != "" {
		ct.NewTest("cluster-entity-multi-cluster").WithCiliumPolicy(allowClusterEntityPolicyYAML).
			WithScenarios(
				tests.PodToPod(tests.WithDestinationLabelsOption(map[string]string{"name": "echo-other-node"})),
			).
			WithExpectations(func(a *check.Action) (egress, ingress check.Result) {
				return check.ResultDefaultDenyEgressDrop, check.ResultNone
			})
	}

	// This policy allows host entity
	ct.NewTest("host-entity").WithCiliumPolicy(allowHostEntityPolicyYAML).
		WithScenarios(
			tests.PodToHost(),
		).
		WithExpectations(func(a *check.Action) (egress, ingress check.Result) {
			return check.ResultOK, check.ResultNone
		})

	// This policy allows ingress to echo only from client with a label 'other:client'.
	echoIngressScenarios := []check.Scenario{tests.PodToPod()}
	ct.NewTest("echo-ingress").WithCiliumPolicy(echoIngressFromOtherClientPolicyYAML).
		WithScenarios(echoIngressScenarios...).
		WithExpectations(func(a *check.Action) (egress, ingress check.Result) {
			if a.Destination().HasLabel("kind", "echo") && !a.Source().HasLabel("other", "client") {
				// TCP handshake fails both in egress and ingress when
				// L3(/L4) policy drops at either location.
				return check.ResultDropCurlTimeout, check.ResultDropCurlTimeout
			}
			return check.ResultOK, check.ResultOK
		})

	if ct.Params().IncludeUnsafeTests {
		ct.NewTest("echo-ingress-from-outside").WithCiliumPolicy(echoIngressFromOtherClientPolicyYAML).
			WithFeatureRequirements(check.RequireFeatureEnabled(check.FeatureNodeWithoutCilium)).
			WithIPRoutesFromOutsideToPodCIDRs().
			WithScenarios(tests.FromCIDRToPod()).
			WithExpectations(func(a *check.Action) (egress, ingress check.Result) {
				if a.Destination().HasLabel("kind", "echo") && !a.Source().HasLabel("other", "client") {
					// TCP handshake fails both in egress and ingress when
					// L3(/L4) policy drops at either location.
					return check.ResultDropCurlTimeout, check.ResultDropCurlTimeout
				}
				return check.ResultOK, check.ResultOK
			})
	}

	// This k8s policy allows ingress to echo only from client with a label 'other:client'.
	ct.NewTest("echo-ingress-knp").WithK8SPolicy(echoIngressFromOtherClientPolicyKNPYAML).
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
	ct.NewTest("client-ingress-icmp").WithCiliumPolicy(echoIngressICMPPolicyYAML).
		WithFeatureRequirements(check.RequireFeatureEnabled(check.FeatureICMPPolicy)).
		WithScenarios(
			tests.ClientToClient(),
		).
		WithExpectations(func(a *check.Action) (egress, ingress check.Result) {
			if a.Source().HasLabel("other", "client") {
				return check.ResultOK, check.ResultOK
			}
			return check.ResultOK, check.ResultDefaultDenyIngressDrop
		})

	// This policy allows port 8080 from client to echo, so this should succeed
	ct.NewTest("client-egress").WithCiliumPolicy(clientEgressToEchoPolicyYAML).
		WithScenarios(
			tests.PodToPod(),
		)

	// This policy allows port 8080 from client to echo, so this should succeed
	ct.NewTest("client-egress-knp").WithK8SPolicy(clientEgressToEchoPolicyKNPYAML).
		WithScenarios(
			tests.PodToPod(),
		)

	// This policy allows port 8080 from client to echo (using label match expression, so this should succeed
	ct.NewTest("client-egress-expression").WithCiliumPolicy(clientEgressToEchoExpressionPolicyYAML).
		WithScenarios(
			tests.PodToPod(),
		)

	// This policy allows port 8080 from client to echo (using label match expression, so this should succeed
	ct.NewTest("client-egress-expression-knp").WithK8SPolicy(clientEgressToEchoExpressionPolicyKNPYAML).
		WithScenarios(
			tests.PodToPod(),
		)

	// This policy allows port 8080 from client with service account label to echo
	ct.NewTest("client-with-service-account-egress-to-echo").WithCiliumPolicy(clientWithServiceAccountEgressToEchoPolicyYAML).
		WithScenarios(
			tests.PodToPod(tests.WithSourceLabelsOption(map[string]string{"kind": "client"})),
		)

	// This policy allows port 8080 from client to endpoint with service account label as echo-same-node
	ct.NewTest("client-egress-to-echo-service-account").WithCiliumPolicy(clientEgressToEchoServiceAccountPolicyYAML).
		WithScenarios(
			tests.PodToPod(
				tests.WithSourceLabelsOption(map[string]string{"kind": "client"}),
			)).
		WithExpectations(func(a *check.Action) (egress, ingress check.Result) {
			if a.Destination().HasLabel("name", "echo-same-node") {
				return check.ResultOK, check.ResultOK
			}
			return check.ResultDefaultDenyEgressDrop, check.ResultNone
		})

	// This policy allows UDP to kube-dns and port 80 TCP to all 'world' endpoints.
	ct.NewTest("to-entities-world").WithCiliumPolicy(clientEgressToEntitiesWorldPolicyYAML).
		WithScenarios(
			tests.PodToWorld(tests.WithRetryDestPort(80)),
		).
		WithExpectations(func(a *check.Action) (egress, ingress check.Result) {
			if a.Destination().Port() == 80 {
				return check.ResultOK, check.ResultNone
			}
			// PodToWorld traffic to port 443 will be dropped by the policy
			return check.ResultDropCurlTimeout, check.ResultNone
		})

	// This policy allows L3 traffic to ExternalCIDR/24 (including ExternalIP), with the
	// exception of ExternalOtherIP.
	ct.NewTest("to-cidr-external").
		WithCiliumPolicy(renderedTemplates["clientEgressToCIDRExternalPolicyYAML"]).
		WithScenarios(
			tests.PodToCIDR(tests.WithRetryDestIP(ct.Params().ExternalIP)),
		).
		WithExpectations(func(a *check.Action) (egress, ingress check.Result) {
			if a.Destination().Address(check.IPFamilyV4) == ct.Params().ExternalOtherIP {
				// Expect packets for ExternalOtherIP to be dropped.
				return check.ResultDropCurlTimeout, check.ResultNone
			}
			return check.ResultOK, check.ResultNone
		})

	// This policy allows L3 traffic to ExternalCIDR/24 (including ExternalIP), with the
	// exception of ExternalOtherIP.
	ct.NewTest("to-cidr-external-knp").
		WithK8SPolicy(renderedTemplates["clientEgressToCIDRExternalPolicyKNPYAML"]).
		WithScenarios(
			tests.PodToCIDR(tests.WithRetryDestIP(ct.Params().ExternalIP)),
		).
		WithExpectations(func(a *check.Action) (egress, ingress check.Result) {
			if a.Destination().Address(check.IPFamilyV4) == ct.Params().ExternalOtherIP {
				// Expect packets for ExternalOtherIP to be dropped.
				return check.ResultDropCurlTimeout, check.ResultNone
			}
			return check.ResultOK, check.ResultNone
		})

	if ct.Params().IncludeUnsafeTests {
		ct.NewTest("from-cidr-host-netns").
			WithFeatureRequirements(check.RequireFeatureEnabled(check.FeatureNodeWithoutCilium)).
			WithCiliumPolicy(renderedTemplates["echoIngressFromCIDRYAML"]).
			WithIPRoutesFromOutsideToPodCIDRs().
			WithScenarios(
				tests.FromCIDRToPod(),
			).
			WithExpectations(func(a *check.Action) (egress, ingress check.Result) {
				return check.ResultOK, check.ResultNone
			})
	}

	// Tests with deny policy
	ct.NewTest("echo-ingress-from-other-client-deny").
		WithCiliumPolicy(allowAllEgressPolicyYAML).                 // Allow all egress traffic
		WithCiliumPolicy(allowAllIngressPolicyYAML).                // Allow all ingress traffic
		WithCiliumPolicy(echoIngressFromOtherClientDenyPolicyYAML). // Deny other client contact echo
		WithScenarios(
			tests.PodToPod(tests.WithSourceLabelsOption(clientLabel)),  // Client to echo should be allowed
			tests.PodToPod(tests.WithSourceLabelsOption(client2Label)), // Client2 to echo should be denied
			tests.ClientToClient(), // Client to client should be allowed
		).
		WithExpectations(func(a *check.Action) (egress, ingress check.Result) {
			if a.Source().HasLabel("other", "client") &&
				a.Destination().HasLabel("kind", "echo") {
				return check.ResultDrop, check.ResultPolicyDenyIngressDrop
			}
			return check.ResultOK, check.ResultOK
		})

	// This policy denies ICMP ingress to client only from other client
	ct.NewTest("client-ingress-from-other-client-icmp-deny").
		WithCiliumPolicy(allowAllEgressPolicyYAML).      // Allow all egress traffic
		WithCiliumPolicy(allowAllIngressPolicyYAML).     // Allow all ingress traffic
		WithCiliumPolicy(echoIngressICMPDenyPolicyYAML). // Deny ICMP traffic from client to another client
		WithFeatureRequirements(check.RequireFeatureEnabled(check.FeatureICMPPolicy)).
		WithScenarios(
			tests.PodToPod(),       // Client to echo traffic should be allowed
			tests.ClientToClient(), // Client to client traffic should be denied
		).
		WithExpectations(func(a *check.Action) (egress, ingress check.Result) {
			if a.Source().HasLabel("other", "client") &&
				a.Destination().HasLabel("kind", "client") {
				return check.ResultDrop, check.ResultPolicyDenyIngressDrop
			}
			return check.ResultOK, check.ResultNone
		})

	// This policy denies port 8080 from client to echo
	ct.NewTest("client-egress-to-echo-deny").
		WithCiliumPolicy(allowAllEgressPolicyYAML).         // Allow all egress traffic
		WithCiliumPolicy(allowAllIngressPolicyYAML).        // Allow all ingress traffic
		WithCiliumPolicy(clientEgressToEchoDenyPolicyYAML). // Deny client to echo traffic via port 8080
		WithScenarios(
			tests.ClientToClient(), // Client to client traffic should be allowed
			tests.PodToPod(),       // Client to echo traffic should be denied
		).
		WithExpectations(func(a *check.Action) (egress, ingress check.Result) {
			if a.Source().HasLabel("kind", "client") &&
				a.Destination().HasLabel("kind", "echo") &&
				a.Destination().Port() == 8080 {
				return check.ResultPolicyDenyEgressDrop, check.ResultNone
			}
			return check.ResultOK, check.ResultNone
		})

	// This policy denies port http-8080 from client to echo, but allows traffic from client2 to echo
	ct.NewTest("client-ingress-to-echo-named-port-deny").
		WithCiliumPolicy(allowAllEgressPolicyYAML).  // Allow all egress traffic
		WithCiliumPolicy(allowAllIngressPolicyYAML). // Allow all ingress traffic
		WithCiliumPolicy(clientEgressToEchoDenyNamedPortPolicyYAML).
		WithScenarios(
			tests.PodToPod(tests.WithSourceLabelsOption(clientLabel)),  // Client to echo should be denied
			tests.PodToPod(tests.WithSourceLabelsOption(client2Label)), // Client2 to echo should be allowed
		).
		WithExpectations(func(a *check.Action) (egress, ingress check.Result) {
			if a.Destination().HasLabel("kind", "echo") &&
				a.Source().HasLabel("name", "client") {
				return check.ResultDropCurlTimeout, check.ResultPolicyDenyIngressDrop
			}
			return check.ResultOK, check.ResultOK
		})

	// This policy denies port 8080 from client to echo (using label match expression), but allows traffic from client2
	ct.NewTest("client-egress-to-echo-expression-deny").
		WithCiliumPolicy(allowAllEgressPolicyYAML).  // Allow all egress traffic
		WithCiliumPolicy(allowAllIngressPolicyYAML). // Allow all ingress traffic
		WithCiliumPolicy(clientEgressToEchoExpressionDenyPolicyYAML).
		WithScenarios(
			tests.PodToPod(tests.WithSourceLabelsOption(clientLabel)),  // Client to echo should be denied
			tests.PodToPod(tests.WithSourceLabelsOption(client2Label)), // Client2 to echo should be allowed
		).
		WithExpectations(func(a *check.Action) (egress, ingress check.Result) {
			if a.Destination().HasLabel("kind", "echo") &&
				a.Source().HasLabel("name", "client") {
				return check.ResultPolicyDenyEgressDrop, check.ResultNone
			}
			return check.ResultOK, check.ResultOK
		})

	// This policy denies port 8080 from client with service account selector to echo, but not from client2
	ct.NewTest("client-with-service-account-egress-to-echo-deny").
		WithCiliumPolicy(allowAllEgressPolicyYAML).  // Allow all egress traffic
		WithCiliumPolicy(allowAllIngressPolicyYAML). // Allow all ingress traffic
		WithCiliumPolicy(clientWithServiceAccountEgressToEchoDenyPolicyYAML).
		WithScenarios(
			tests.PodToPod(tests.WithSourceLabelsOption(map[string]string{"name": "client"})),  // Client to echo should be denied
			tests.PodToPod(tests.WithSourceLabelsOption(map[string]string{"name": "client2"})), // Client2 to echo should be allowed
		).
		WithExpectations(func(a *check.Action) (egress, ingress check.Result) {
			if a.Destination().HasLabel("kind", "echo") &&
				a.Source().HasLabel("name", "client") {
				return check.ResultPolicyDenyEgressDrop, check.ResultNone
			}
			return check.ResultOK, check.ResultOK
		})

	// This policy denies port 8080 from client to endpoint with service account, but not from client2
	ct.NewTest("client-egress-to-echo-service-account-deny").
		WithCiliumPolicy(allowAllEgressPolicyYAML).  // Allow all egress traffic
		WithCiliumPolicy(allowAllIngressPolicyYAML). // Allow all ingress traffic
		WithCiliumPolicy(clientEgressToEchoServiceAccountDenyPolicyYAML).
		WithScenarios(
			tests.PodToPod(tests.WithSourceLabelsOption(map[string]string{"name": "client"})),
		).
		WithExpectations(func(a *check.Action) (egress, ingress check.Result) {
			if a.Destination().HasLabel("name", "echo-same-node") {
				return check.ResultPolicyDenyEgressDrop, check.ResultNone
			}
			return check.ResultOK, check.ResultOK
		})

	// This policy denies L3 traffic to ExternalCIDR except ExternalIP/32
	ct.NewTest("client-egress-to-cidr-deny").
		WithCiliumPolicy(allowAllEgressPolicyYAML). // Allow all egress traffic
		WithCiliumPolicy(renderedTemplates["clientEgressToCIDRExternalDenyPolicyYAML"]).
		WithScenarios(
			tests.PodToCIDR(tests.WithRetryDestIP(ct.Params().ExternalIP)), // Denies all traffic to ExternalOtherIP, but allow ExternalIP
		).
		WithExpectations(func(a *check.Action) (egress, ingress check.Result) {
			if a.Destination().Address(check.GetIPFamily(ct.Params().ExternalOtherIP)) == ct.Params().ExternalOtherIP {
				return check.ResultPolicyDenyEgressDrop, check.ResultNone
			}
			if a.Destination().Address(check.GetIPFamily(ct.Params().ExternalIP)) == ct.Params().ExternalIP {
				return check.ResultOK, check.ResultNone
			}
			return check.ResultDrop, check.ResultDrop
		})

	// This test is same as the previous one, but there is no allowed policy.
	// The goal is to test default deny policy
	ct.NewTest("client-egress-to-cidr-deny-default").
		WithCiliumPolicy(renderedTemplates["clientEgressToCIDRExternalDenyPolicyYAML"]).
		WithScenarios(
			tests.PodToCIDR(), // Denies all traffic to ExternalOtherIP, but allow ExternalIP
		).
		WithExpectations(func(a *check.Action) (egress, ingress check.Result) {
			if a.Destination().Address(check.GetIPFamily(ct.Params().ExternalOtherIP)) == ct.Params().ExternalOtherIP {
				return check.ResultPolicyDenyEgressDrop, check.ResultNone
			}
			if a.Destination().Address(check.GetIPFamily(ct.Params().ExternalIP)) == ct.Params().ExternalIP {
				return check.ResultDefaultDenyEgressDrop, check.ResultNone
			}
			return check.ResultDrop, check.ResultDrop
		})

	// Health check tests.
	ct.NewTest("health").
		WithFeatureRequirements(check.RequireFeatureEnabled(check.FeatureHealthChecking)).
		WithScenarios(tests.CiliumHealth())

	ct.NewTest("north-south-loadbalancing").
		WithFeatureRequirements(check.RequireFeatureEnabled(check.FeatureNodeWithoutCilium)).
		WithScenarios(
			tests.OutsideToNodePort(),
		)

	ct.NewTest("pod-to-pod-encryption").
		WithFeatureRequirements(check.RequireFeatureEnabled(check.FeatureEncryptionPod)).
		WithScenarios(
			tests.PodToPodEncryption(),
		)
	ct.NewTest("node-to-node-encryption").
		WithFeatureRequirements(check.RequireFeatureEnabled(check.FeatureEncryptionPod),
			check.RequireFeatureEnabled(check.FeatureEncryptionNode)).
		WithScenarios(
			tests.NodeToNodeEncryption(),
		)

	if ct.Params().IncludeUnsafeTests {
		ct.NewTest("egress-gateway").
			WithCiliumEgressGatewayPolicy(egressGatewayPolicyYAML, check.CiliumEgressGatewayPolicyParams{}).
			WithIPRoutesFromOutsideToPodCIDRs().
			WithFeatureRequirements(check.RequireFeatureEnabled(check.FeatureEgressGateway),
				check.RequireFeatureEnabled(check.FeatureNodeWithoutCilium)).
			WithScenarios(
				tests.EgressGateway(),
			)
	}

	if versioncheck.MustCompile(">=1.14.0")(ct.CiliumVersion) {
		ct.NewTest("egress-gateway-excluded-cidrs").
			WithCiliumEgressGatewayPolicy(egressGatewayPolicyExcludedCIDRsYAML,
				check.CiliumEgressGatewayPolicyParams{ExcludedCIDRs: check.ExternalNodeExcludedCIDRs}).
			WithFeatureRequirements(check.RequireFeatureEnabled(check.FeatureEgressGateway),
				check.RequireFeatureEnabled(check.FeatureNodeWithoutCilium)).
			WithScenarios(
				tests.EgressGatewayExcludedCIDRs(),
			)
	}

	// The following tests have DNS redirect policies. They should be executed last.

	ct.NewTest("north-south-loadbalancing-with-l7-policy").
		WithFeatureRequirements(check.RequireFeatureEnabled(check.FeatureNodeWithoutCilium),
			check.RequireFeatureEnabled(check.FeatureL7Proxy)).
		WithCiliumVersion(">1.13.2").
		WithCiliumPolicy(echoIngressL7HTTPFromAnywherePolicyYAML).
		WithScenarios(
			tests.OutsideToNodePort(),
		)

	// Test L7 HTTP introspection using an ingress policy on echo pods.
	ct.NewTest("echo-ingress-l7").
		WithFeatureRequirements(check.RequireFeatureEnabled(check.FeatureL7Proxy)).
		WithCiliumPolicy(echoIngressL7HTTPPolicyYAML). // L7 allow policy with HTTP introspection
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
			return check.ResultDrop, check.ResultDefaultDenyIngressDrop
		})

	// Test L7 HTTP introspection using an ingress policy on echo pods.
	ct.NewTest("echo-ingress-l7-named-port").
		WithFeatureRequirements(check.RequireFeatureEnabled(check.FeatureL7Proxy)).
		WithCiliumPolicy(echoIngressL7HTTPNamedPortPolicyYAML). // L7 allow policy with HTTP introspection (named port)
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
			return check.ResultDrop, check.ResultDefaultDenyIngressDrop
		})

	// Test L7 HTTP with different methods introspection using an egress policy on the clients.
	ct.NewTest("client-egress-l7-method").
		WithFeatureRequirements(check.RequireFeatureEnabled(check.FeatureL7Proxy)).
		WithCiliumPolicy(clientEgressOnlyDNSPolicyYAML).      // DNS resolution only
		WithCiliumPolicy(clientEgressL7HTTPMethodPolicyYAML). // L7 allow policy with HTTP introspection (POST only)
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
			return check.ResultDefaultDenyEgressDrop, check.ResultNone
		})

	// Test L7 HTTP introspection using an egress policy on the clients.
	ct.NewTest("client-egress-l7").
		WithFeatureRequirements(check.RequireFeatureEnabled(check.FeatureL7Proxy)).
		WithCiliumPolicy(clientEgressOnlyDNSPolicyYAML).                     // DNS resolution only
		WithCiliumPolicy(renderedTemplates["clientEgressL7HTTPPolicyYAML"]). // L7 allow policy with HTTP introspection
		WithScenarios(
			tests.PodToPod(),
			tests.PodToWorld(tests.WithRetryDestPort(80), tests.WithRetryPodLabel("other", "client")),
		).
		WithExpectations(func(a *check.Action) (egress, ingress check.Result) {
			if a.Source().HasLabel("other", "client") && // Only client2 is allowed to make HTTP calls.
				// Outbound HTTP to set domain-name defaults to one.one.one.one is L7-introspected and allowed.
				(a.Destination().Port() == 80 && a.Destination().Address(check.GetIPFamily(ct.Params().ExternalTarget)) == ct.Params().ExternalTarget ||
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
			return check.ResultDefaultDenyEgressDrop, check.ResultNone
		})

	// Test L7 HTTP named port introspection using an egress policy on the clients.
	ct.NewTest("client-egress-l7-named-port").
		WithFeatureRequirements(check.RequireFeatureEnabled(check.FeatureL7Proxy)).
		WithCiliumPolicy(clientEgressOnlyDNSPolicyYAML).                              // DNS resolution only
		WithCiliumPolicy(renderedTemplates["clientEgressL7HTTPNamedPortPolicyYAML"]). // L7 allow policy with HTTP introspection (named port)
		WithScenarios(
			tests.PodToPod(),
			tests.PodToWorld(tests.WithRetryDestPort(80), tests.WithRetryPodLabel("other", "client")),
		).
		WithExpectations(func(a *check.Action) (egress, ingress check.Result) {
			if a.Source().HasLabel("other", "client") && // Only client2 is allowed to make HTTP calls.
				// Outbound HTTP to domain-name, default one.one.one.one, is L7-introspected and allowed.
				(a.Destination().Port() == 80 && a.Destination().Address(check.GetIPFamily(ct.Params().ExternalTarget)) == ct.Params().ExternalTarget ||
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
			return check.ResultDefaultDenyEgressDrop, check.ResultNone
		})

	// Test L7 HTTPS interception using an egress policy on the clients.
	// Fail to load site due to missing headers.
	ct.NewTest("client-egress-l7-tls-deny-without-headers").
		WithFeatureRequirements(check.RequireFeatureEnabled(check.FeatureL7Proxy)).
		WithFeatureRequirements(check.RequireFeatureEnabled(check.FeatureSecretBackendK8s)).
		WithCABundleSecret().
		WithCertificate("externaltarget-tls", ct.Params().ExternalTarget).
		WithCiliumPolicy(renderedTemplates["clientEgressL7TLSPolicyYAML"]). // L7 allow policy with TLS interception
		WithScenarios(
			tests.PodToWorldWithTLSIntercept(),
		).
		WithExpectations(func(a *check.Action) (egress, ingress check.Result) {
			return check.ResultDropCurlHTTPError, check.ResultNone
		})

	// Test L7 HTTPS interception using an egress policy on the clients.
	ct.NewTest("client-egress-l7-tls-headers").
		WithFeatureRequirements(check.RequireFeatureEnabled(check.FeatureL7Proxy)).
		WithFeatureRequirements(check.RequireFeatureEnabled(check.FeatureSecretBackendK8s)).
		WithCABundleSecret().
		WithCertificate("externaltarget-tls", ct.Params().ExternalTarget).
		WithCiliumPolicy(renderedTemplates["clientEgressL7TLSPolicyYAML"]). // L7 allow policy with TLS interception
		WithScenarios(
			tests.PodToWorldWithTLSIntercept("-H", "X-Very-Secret-Token: 42"),
		).
		WithExpectations(func(a *check.Action) (egress, ingress check.Result) {
			return check.ResultOK, check.ResultNone
		})

	// Test L7 HTTP with a header replace set in the policy
	ct.NewTest("client-egress-l7-set-header").
		WithFeatureRequirements(check.RequireFeatureEnabled(check.FeatureL7Proxy)).
		WithFeatureRequirements(check.RequireFeatureEnabled(check.FeatureSecretBackendK8s)).
		WithSecret(&corev1.Secret{
			ObjectMeta: metav1.ObjectMeta{
				Name: "header-match",
			},
			Data: map[string][]byte{
				"value": []byte("Bearer 123456"),
			},
		}).
		WithCiliumPolicy(renderedTemplates["clientEgressL7HTTPMatchheaderSecretYAML"]). // L7 allow policy with HTTP introspection (POST only)
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

	// Test mutual auth with always-fail
	ct.NewTest("echo-ingress-auth-always-fail").WithCiliumPolicy(echoIngressAuthFailPolicyYAML).
		// this test is only useful when auth is supported in the Cilium version and it is enabled
		// currently this is tested spiffe as that is the only functional auth method
		WithFeatureRequirements(check.RequireFeatureEnabled(check.FeatureAuthSpiffe)).
		WithScenarios(
			tests.PodToPod(),
		).
		WithExpectations(func(a *check.Action) (egress, ingress check.Result) {
			return check.ResultDropCurlTimeout, check.ResultDropAuthRequired
		})

	// Test mutual auth with SPIFFE
	ct.NewTest("echo-ingress-mutual-auth-spiffe").WithCiliumPolicy(echoIngressMutualAuthPolicyYAML).
		WithFeatureRequirements(check.RequireFeatureEnabled(check.FeatureAuthSpiffe)).
		WithScenarios(
			tests.PodToPod(),
		)

	// Test Ingress controller
	ct.NewTest("pod-to-ingress-service").
		WithFeatureRequirements(check.RequireFeatureEnabled(check.FeatureIngressController)).
		WithScenarios(
			tests.PodToIngress(),
		)

	ct.NewTest("pod-to-ingress-service-deny-all").
		WithFeatureRequirements(check.RequireFeatureEnabled(check.FeatureIngressController)).
		WithCiliumPolicy(denyAllIngressPolicyYAML).
		WithScenarios(
			tests.PodToIngress(),
		).
		WithExpectations(func(a *check.Action) (egress check.Result, ingress check.Result) {
			return check.ResultDefaultDenyEgressDrop, check.ResultNone
		})

	ct.NewTest("pod-to-ingress-service-allow-ingress-identity").
		WithFeatureRequirements(check.RequireFeatureEnabled(check.FeatureIngressController)).
		WithCiliumPolicy(denyAllIngressPolicyYAML).
		WithCiliumPolicy(allowIngressIdentityPolicyYAML).
		WithScenarios(
			tests.PodToIngress(),
		)

	// Only allow UDP:53 to kube-dns, no DNS proxy enabled.
	ct.NewTest("dns-only").WithCiliumPolicy(clientEgressOnlyDNSPolicyYAML).
		WithFeatureRequirements(check.RequireFeatureEnabled(check.FeatureL7Proxy)).
		WithScenarios(
			tests.PodToPod(),   // connects to other Pods directly, no DNS
			tests.PodToWorld(), // resolves set domain-name defaults to one.one.one.one
		).
		WithExpectations(func(a *check.Action) (egress check.Result, ingress check.Result) {
			return check.ResultDropCurlTimeout, check.ResultNone
		})

	// This policy only allows port 80 to domain-name, default one.one.one.one,. DNS proxy enabled.
	ct.NewTest("to-fqdns").WithCiliumPolicy(renderedTemplates["clientEgressToFQDNsCiliumIOPolicyYAML"]).
		WithFeatureRequirements(check.RequireFeatureEnabled(check.FeatureL7Proxy)).
		WithScenarios(
			tests.PodToWorld(tests.WithRetryDestPort(80)),
			tests.PodToWorld2(), // resolves cilium.io
		).
		WithExpectations(func(a *check.Action) (egress, ingress check.Result) {
			if a.Destination().Address(check.IPFamilyAny) == "cilium.io" {
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
			if a.Destination().Port() == 80 && a.Destination().Address(check.GetIPFamily(extTarget)) == extTarget {
				if a.Destination().Path() == "/" || a.Destination().Path() == "" {
					egress = check.ResultDNSOK
					egress.HTTP = check.HTTP{
						Method: "GET",
						URL:    fmt.Sprintf("http://%s/", extTarget),
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

	if err := addExtraTests(ct); err != nil {
		return err
	}

	if ct.Params().IncludeUnsafeTests {
		ct.NewTest("check-log-errors").WithScenarios(tests.NoErrorsInLogs(ct.CiliumVersion))
	}

	return ct.Run(ctx)
}

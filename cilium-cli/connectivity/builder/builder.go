// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package builder

import (
	_ "embed"

	"github.com/cilium/cilium-cli/connectivity/builder/manifests/template"
	"github.com/cilium/cilium-cli/connectivity/check"
	"github.com/cilium/cilium-cli/utils/features"
)

var (
	//go:embed manifests/allow-all-egress.yaml
	allowAllEgressPolicyYAML string

	//go:embed manifests/allow-all-ingress.yaml
	allowAllIngressPolicyYAML string

	//go:embed manifests/deny-all-ingress.yaml
	denyAllIngressPolicyYAML string

	//go:embed manifests/deny-cidr.yaml
	denyCIDRPolicyYAML string

	//go:embed manifests/allow-cluster-entity.yaml
	allowClusterEntityPolicyYAML string

	//go:embed manifests/client-egress-only-dns.yaml
	clientEgressOnlyDNSPolicyYAML string

	//go:embed manifests/client-egress-to-fqdns.yaml
	clientEgressToFQDNsPolicyYAML string

	//go:embed manifests/echo-ingress-from-other-client.yaml
	echoIngressFromOtherClientPolicyYAML string

	//go:embed manifests/client-egress-to-cidr-cp-host-knp.yaml
	clientEgressToCIDRCPHostPolicyYAML string

	//go:embed manifests/client-egress-to-cidr-external.yaml
	clientEgressToCIDRExternalPolicyYAML string

	//go:embed manifests/client-egress-to-cidr-external-knp.yaml
	clientEgressToCIDRExternalPolicyKNPYAML string

	//go:embed manifests/client-egress-to-cidr-k8s.yaml
	clientEgressToCIDRK8sPolicyYAML string

	//go:embed manifests/client-egress-to-cidr-node-knp.yaml
	clientEgressToCIDRNodeKNPYAML string

	//go:embed manifests/client-egress-to-cidr-external-deny.yaml
	clientEgressToCIDRExternalDenyPolicyYAML string

	//go:embed manifests/client-egress-l7-http.yaml
	clientEgressL7HTTPPolicyYAML string

	//go:embed manifests/client-egress-l7-http-named-port.yaml
	clientEgressL7HTTPNamedPortPolicyYAML string

	//go:embed manifests/client-egress-l7-tls.yaml
	clientEgressL7TLSPolicyYAML string

	//go:embed manifests/client-egress-l7-http-matchheader-secret.yaml
	clientEgressL7HTTPMatchheaderSecretYAML string

	//go:embed manifests/echo-ingress-from-cidr.yaml
	echoIngressFromCIDRYAML string
)

var (
	clientLabel  = map[string]string{"name": "client"}
	client2Label = map[string]string{"name": "client2"}
)

type testBuilder interface {
	build(ct *check.ConnectivityTest, templates map[string]string)
}

// GetTestSuites returns a slice of functions, that when invoked, result in a
// collection of tests being built. These functions use helper methods to add various
// collections of test builders depending upon the provided parameters.
func GetTestSuites(params check.Parameters) ([]func(connTests []*check.ConnectivityTest, extraTests func(ct *check.ConnectivityTest) error) error, error) {
	switch {
	case params.Perf:
		return []func(connTests []*check.ConnectivityTest, extraTests func(ct *check.ConnectivityTest) error) error{
			func(connTests []*check.ConnectivityTest, _ func(ct *check.ConnectivityTest) error) error {
				return networkPerformanceTests(connTests[0])
			},
		}, nil
	case params.IncludeConnDisruptTest && params.ConnDisruptTestSetup:
		// Exit early, as --conn-disrupt-test-setup is only needed to deploy pods which
		// will be used by another invocation of "cli connectivity test"
		// with include --include-conn-disrupt-test"
		return []func(connTests []*check.ConnectivityTest, extraTests func(ct *check.ConnectivityTest) error) error{
			func(connTests []*check.ConnectivityTest, _ func(ct *check.ConnectivityTest) error) error {
				return connDisruptTests(connTests[0])
			},
		}, nil
	case params.TestConcurrency > 1:
		return []func(connTests []*check.ConnectivityTest, extraTests func(ct *check.ConnectivityTest) error) error{
			func(connTests []*check.ConnectivityTest, _ func(ct *check.ConnectivityTest) error) error {
				if connTests[0].Params().IncludeConnDisruptTest {
					if err := connDisruptTests(connTests[0]); err != nil {
						return err
					}
				}
				return concurrentTests(connTests)
			},
			func(connTests []*check.ConnectivityTest, extraTests func(ct *check.ConnectivityTest) error) error {
				if err := sequentialTests(connTests[0]); err != nil {
					return err
				}
				if err := extraTests(connTests[0]); err != nil {
					return err
				}
				return finalTests(connTests[0])
			},
		}, nil
	default: // fallback to the sequential run
		return []func(connTests []*check.ConnectivityTest, extraTests func(ct *check.ConnectivityTest) error) error{
			func(connTests []*check.ConnectivityTest, extraTests func(ct *check.ConnectivityTest) error) error {
				if connTests[0].Params().IncludeConnDisruptTest {
					if err := connDisruptTests(connTests[0]); err != nil {
						return err
					}
				}
				if err := concurrentTests(connTests); err != nil {
					return err
				}
				if err := sequentialTests(connTests[0]); err != nil {
					return err
				}
				if err := extraTests(connTests[0]); err != nil {
					return err
				}
				return finalTests(connTests[0])
			},
		}, nil
	}
}

// networkPerformanceTests injects the network performance connectivity tests.
func networkPerformanceTests(ct *check.ConnectivityTest) error {
	tests := []testBuilder{networkPerf{}}
	return injectTests(tests, ct)
}

// connDisruptTests injects the conn-disrupt connectivity tests.
func connDisruptTests(ct *check.ConnectivityTest) error {
	tests := []testBuilder{
		noInterruptedConnections{},
		noIpsecXfrmErrors{},
	}
	return injectTests(tests, ct)
}

// concurrentTests injects the all connectivity tests that can be run concurrently.
// Each test should be run in a separate namespace.
func concurrentTests(connTests []*check.ConnectivityTest) error {
	tests := []testBuilder{
		noUnexpectedPacketDrops{},
		noPolicies{},
		noPoliciesFromOutside{},
		noPoliciesExtra{},
		allowAllExceptWorld{},
		clientIngress{},
		clientIngressKnp{},
		allowAllWithMetricsCheck{},
		allIngressDeny{},
		allIngressDenyFromOutside{},
		allIngressDenyKnp{},
		allEgressDeny{},
		allEgressDenyKnp{},
		allEntitiesDeny{},
		clusterEntity{},
		clusterEntityMultiCluster{},
		hostEntityEgress{},
		hostEntityIngress{},
		echoIngress{},
		echoIngressFromOutside{},
		echoIngressKnp{},
		clientIngressIcmp{},
		clientEgress{},
		clientEgressKnp{},
		clientEgressExpression{},
		clientEgressExpressionKnp{},
		clientWithServiceAccountEgressToEcho{},
		clientEgressToEchoServiceAccount{},
		toEntitiesWorld{},
		toCidrExternal{},
		toCidrExternalKnp{},
		fromCidrHostNetns{},
		echoIngressFromOtherClientDeny{},
		clientIngressFromOtherClientIcmpDeny{},
		clientEgressToEchoDeny{},
		clientIngressToEchoNamedPortDeny{},
		clientEgressToEchoExpressionDeny{},
		clientWithServiceAccountEgressToEchoDeny{},
		clientEgressToEchoServiceAccountDeny{},
		clientEgressToCidrDeny{},
		clientEgressToCidrDenyDefault{},
		clusterMeshEndpointSliceSync{},
		health{},
		northSouthLoadbalancing{},
		podToPodEncryption{},
		nodeToNodeEncryption{},
		egressGateway{},
		egressGatewayExcludedCidrs{},
		egressGatewayWithL7Policy{},
		podToNodeCidrpolicy{},
		northSouthLoadbalancingWithL7Policy{},
		echoIngressL7{},
		echoIngressL7NamedPort{},
		clientEgressL7Method{},
		clientEgressL7{},
		clientEgressL7NamedPort{},
		clientEgressL7TlsDenyWithoutHeaders{},
		clientEgressL7TlsHeaders{},
		clientEgressL7SetHeader{},
		echoIngressAuthAlwaysFail{},
		echoIngressMutualAuthSpiffe{},
		podToIngressService{},
		podToIngressServiceDenyAll{},
		podToIngressServiceDenyIngressIdentity{},
		podToIngressServiceDenyBackendService{},
		podToIngressServiceAllowIngressIdentity{},
		outsideToIngressService{},
		outsideToIngressServiceDenyWorldIdentity{},
		outsideToIngressServiceDenyCidr{},
		outsideToIngressServiceDenyAllIngress{},
		dnsOnly{},
		toFqdns{},
		podToControlplaneHost{},
		podToK8sOnControlplane{},
		podToControlplaneHostCidr{},
		podToK8sOnControlplaneCidr{},
	}
	return injectTests(tests, connTests...)
}

// sequentialTests injects the all connectivity tests that must be run sequentially.
func sequentialTests(ct *check.ConnectivityTest) error {
	tests := []testBuilder{
		hostFirewallIngress{},
		hostFirewallEgress{},
	}
	return injectTests(tests, ct)
}

// finalTests injects the all connectivity tests that must be run as the last tests sequentially.
func finalTests(ct *check.ConnectivityTest) error {
	return injectTests([]testBuilder{checkLogErrors{}}, ct)
}

func renderTemplates(param check.Parameters) (map[string]string, error) {
	templates := map[string]string{
		"clientEgressToCIDRExternalPolicyYAML":     clientEgressToCIDRExternalPolicyYAML,
		"clientEgressToCIDRExternalPolicyKNPYAML":  clientEgressToCIDRExternalPolicyKNPYAML,
		"clientEgressToCIDRNodeKNPYAML":            clientEgressToCIDRNodeKNPYAML,
		"clientEgressToCIDRExternalDenyPolicyYAML": clientEgressToCIDRExternalDenyPolicyYAML,
		"clientEgressL7HTTPPolicyYAML":             clientEgressL7HTTPPolicyYAML,
		"clientEgressL7HTTPNamedPortPolicyYAML":    clientEgressL7HTTPNamedPortPolicyYAML,
		"clientEgressToFQDNsPolicyYAML":            clientEgressToFQDNsPolicyYAML,
		"clientEgressL7TLSPolicyYAML":              clientEgressL7TLSPolicyYAML,
		"clientEgressL7HTTPMatchheaderSecretYAML":  clientEgressL7HTTPMatchheaderSecretYAML,
		"echoIngressFromCIDRYAML":                  echoIngressFromCIDRYAML,
		"denyCIDRPolicyYAML":                       denyCIDRPolicyYAML,
	}
	if param.K8sLocalHostTest {
		templates["clientEgressToCIDRCPHostPolicyYAML"] = clientEgressToCIDRCPHostPolicyYAML
		templates["clientEgressToCIDRK8sPolicyKNPYAML"] = clientEgressToCIDRK8sPolicyYAML
	}

	renderedTemplates := map[string]string{}
	for key, temp := range templates {
		val, err := template.Render(temp, param)
		if err != nil {
			return nil, err
		}
		renderedTemplates[key] = val
	}
	return renderedTemplates, nil
}

func injectTests(tests []testBuilder, connTests ...*check.ConnectivityTest) error {
	// templates must be compiled per test namespace due to
	// namespace specific placeholders in the network policies
	templates := make(map[string]map[string]string, len(connTests))
	id := 0
	for i := range tests {
		if _, ok := templates[connTests[id].Params().TestNamespace]; !ok {
			nsTemplates, err := renderTemplates(connTests[id].Params())
			if err != nil {
				return err
			}
			templates[connTests[id].Params().TestNamespace] = nsTemplates
		}
		tests[i].build(connTests[id], templates[connTests[id].Params().TestNamespace])
		id++
		if id == len(connTests) {
			id = 0
		}
	}
	return nil
}

func newTest(name string, ct *check.ConnectivityTest) *check.Test {
	test := check.NewTest(name, ct.Params().Verbose, ct.Params().Debug)
	return ct.AddTest(test)
}

func withKPRReqForMultiCluster(ct *check.ConnectivityTest, reqs ...features.Requirement) []features.Requirement {
	// Skip the nodeport-related tests in the multicluster scenario if KPR is not
	// enabled, since global nodeport services are not supported in that case.
	if ct.Params().MultiCluster != "" {
		reqs = append(reqs, features.RequireEnabled(features.KPRNodePort))
	}
	return reqs
}

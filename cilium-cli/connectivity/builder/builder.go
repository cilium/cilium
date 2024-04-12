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

// NetworkPerformanceTests builds the network performance connectivity tests.
func NetworkPerformanceTests(ct *check.ConnectivityTest) error {
	return getTests(ct, []testBuilder{networkPerf{}})
}

// ConnDisruptTests builds the conn disrupt connectivity tests.
func ConnDisruptTests(ct *check.ConnectivityTest) error {
	tests := []testBuilder{
		noInterruptedConnections{},
		noIpsecXfrmErrors{},
	}
	return getTests(ct, tests)
}

// ConcurrentTests builds the all connectivity tests that can be run concurrently.
// Each test should be run in a separate namespace.
func ConcurrentTests(ct *check.ConnectivityTest) error {
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
	return getTests(ct, tests)
}

// SequentialTests builds the all connectivity tests that must be run sequentially.
func SequentialTests(ct *check.ConnectivityTest) error {
	tests := []testBuilder{
		hostFirewallIngress{},
		hostFirewallEgress{},
	}
	return getTests(ct, tests)
}

// FinalTests builds the all connectivity tests that must be run as the last tests sequentially.
func FinalTests(ct *check.ConnectivityTest) error {
	return getTests(ct, []testBuilder{checkLogErrors{}})
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

func getTests(ct *check.ConnectivityTest, tests []testBuilder) error {
	templates, err := renderTemplates(ct.Params())
	if err != nil {
		return err
	}

	for i := range tests {
		tests[i].build(ct, templates)
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

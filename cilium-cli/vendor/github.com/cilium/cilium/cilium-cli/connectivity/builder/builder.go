// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package builder

import (
	_ "embed"
	"github.com/cilium/cilium/cilium-cli/connectivity/builder/manifests/template"
	check2 "github.com/cilium/cilium/cilium-cli/connectivity/check"

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

	primaryTests = []testBuilder{
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
)

type testBuilder interface {
	build(ct *check2.ConnectivityTest, templates map[string]string)
}

// InjectTests function injects needed connectivity tests in a proper order.
func InjectTests(ct *check2.ConnectivityTest, extraTests func(ct *check2.ConnectivityTest) error) error {
	templates, err := renderTemplates(ct.Params())
	if err != nil {
		return err
	}

	// Network Performance Test
	if ct.Params().Perf {
		injectTests(ct, templates, networkPerf{})
		return nil
	}

	// Conn disrupt Test
	if ct.Params().IncludeConnDisruptTest {
		injectTests(ct, templates, noInterruptedConnections{}, noIpsecXfrmErrors{})
		if ct.Params().ConnDisruptTestSetup {
			// Exit early, as --conn-disrupt-test-setup is only needed to deploy pods which
			// will be used by another invocation of "cli connectivity test" (with
			// include --include-conn-disrupt-test"
			return nil
		}
	}

	injectTests(ct, templates, primaryTests...)

	if err := extraTests(ct); err != nil {
		return err
	}

	injectTests(ct, templates, checkLogErrors{})
	return nil
}

func renderTemplates(param check2.Parameters) (map[string]string, error) {
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

func newTest(name string, ct *check2.ConnectivityTest) *check2.Test {
	test := check2.NewTest(name, ct.Params().Verbose, ct.Params().Debug)
	return ct.AddTest(test)
}

func injectTests(ct *check2.ConnectivityTest, templates map[string]string, tests ...testBuilder) {
	for _, t := range tests {
		t.build(ct, templates)
	}
}

func withKPRReqForMultiCluster(ct *check2.ConnectivityTest, reqs ...features.Requirement) []features.Requirement {
	// Skip the nodeport-related tests in the multicluster scenario if KPR is not
	// enabled, since global nodeport services are not supported in that case.
	if ct.Params().MultiCluster != "" {
		reqs = append(reqs, features.RequireEnabled(features.KPRNodePort))
	}
	return reqs
}

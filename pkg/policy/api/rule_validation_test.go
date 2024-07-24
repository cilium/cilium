// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package api

import (
	"fmt"
	"testing"

	"github.com/cilium/proxy/pkg/policy/api/kafka"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"k8s.io/apimachinery/pkg/util/intstr"

	slim_metav1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/apis/meta/v1"
	"github.com/cilium/cilium/pkg/labels"
	"github.com/cilium/cilium/pkg/option"
)

// This test ensures that only PortRules which have L7Rules associated with them
// are invalid if any protocol except TCP is used as a protocol for any port
// in the list of PortProtocol supplied to the rule.
func TestL7RulesWithNonTCPProtocols(t *testing.T) {
	setUpSuite(t)

	// Rule is valid because only ProtoTCP is allowed for L7 rules (except with ToFQDNs, below).
	validPortRule := Rule{
		EndpointSelector: WildcardEndpointSelector,
		Ingress: []IngressRule{
			{
				IngressCommonRule: IngressCommonRule{
					FromEndpoints: []EndpointSelector{WildcardEndpointSelector},
				},
				ToPorts: []PortRule{{
					Ports: []PortProtocol{
						{Port: "80", Protocol: ProtoTCP},
						{Port: "81", Protocol: ProtoTCP},
					},
					Rules: &L7Rules{
						HTTP: []PortRuleHTTP{
							{Method: "GET", Path: "/"},
						},
					},
				}},
			},
		},
	}

	err := validPortRule.Sanitize()
	require.Nil(t, err)

	// Rule is invalid because no port is specified for DNS proxy rule.
	validPortRule = Rule{
		EndpointSelector: WildcardEndpointSelector,
		Egress: []EgressRule{
			{
				EgressCommonRule: EgressCommonRule{
					ToEndpoints: []EndpointSelector{WildcardEndpointSelector},
				},
				ToPorts: []PortRule{{
					Rules: &L7Rules{
						DNS: []PortRuleDNS{
							{MatchName: "domain.com"},
						},
					},
				}},
			},
		},
	}

	err = validPortRule.Sanitize()
	require.Error(t, err, "Port 53 must be specified for DNS rules")

	// Rule is valid because all protocols are allowed for L7 rules with ToFQDNs.
	validPortRule = Rule{
		EndpointSelector: WildcardEndpointSelector,
		Egress: []EgressRule{
			{
				EgressCommonRule: EgressCommonRule{
					ToEndpoints: []EndpointSelector{WildcardEndpointSelector},
				},
				ToPorts: []PortRule{{
					Ports: []PortProtocol{
						{Port: "53", Protocol: ProtoTCP},
						{Port: "53", Protocol: ProtoUDP},
					},
					Rules: &L7Rules{
						DNS: []PortRuleDNS{
							{MatchName: "domain.com"},
						},
					},
				}},
			},
		},
	}

	err = validPortRule.Sanitize()
	require.NoError(t, err, "Saw an error for a L7 rule with DNS rules. This should be allowed.")

	validSCTPRule := Rule{
		EndpointSelector: WildcardEndpointSelector,
		Egress: []EgressRule{
			{
				EgressCommonRule: EgressCommonRule{
					ToEndpoints: []EndpointSelector{WildcardEndpointSelector},
				},
				ToPorts: []PortRule{{
					Ports: []PortProtocol{
						{Port: "4000", Protocol: ProtoSCTP},
					},
				}},
			},
		},
	}

	err = validSCTPRule.Sanitize()
	require.NoError(t, err, "Saw an error for an SCTP rule.")

	// Rule is invalid because only ProtoTCP is allowed for L7 rules (except with DNS, below).
	invalidPortRule := Rule{
		EndpointSelector: WildcardEndpointSelector,
		Ingress: []IngressRule{
			{
				IngressCommonRule: IngressCommonRule{
					FromEndpoints: []EndpointSelector{WildcardEndpointSelector},
				},
				ToPorts: []PortRule{{
					Ports: []PortProtocol{
						{Port: "80", Protocol: ProtoUDP},
					},
					Rules: &L7Rules{
						HTTP: []PortRuleHTTP{
							{Method: "GET", Path: "/"},
						},
					},
				}},
			},
		},
	}

	err = invalidPortRule.Sanitize()
	require.ErrorContains(t, err, "L7 rules can only apply to TCP (not UDP) except for DNS rules")

	// Rule is invalid because DNS proxy rules are not allowed on ingress rules.
	invalidPortRule = Rule{
		EndpointSelector: WildcardEndpointSelector,
		Ingress: []IngressRule{
			{
				IngressCommonRule: IngressCommonRule{
					FromEndpoints: []EndpointSelector{WildcardEndpointSelector},
				},
				ToPorts: []PortRule{{
					Ports: []PortProtocol{
						{Port: "53", Protocol: ProtoAny},
					},
					Rules: &L7Rules{
						DNS: []PortRuleDNS{
							{MatchName: "domain.com"},
						},
					},
				}},
			},
		},
	}

	err = invalidPortRule.Sanitize()
	require.Error(t, err, "DNS rule should not be allowed on ingress")

	// Rule is invalid because only ProtoTCP is allowed for L7 rules (except with DNS, below).
	invalidPortRule = Rule{
		EndpointSelector: WildcardEndpointSelector,
		Ingress: []IngressRule{
			{
				IngressCommonRule: IngressCommonRule{
					FromEndpoints: []EndpointSelector{WildcardEndpointSelector},
				},
				ToPorts: []PortRule{{
					Ports: []PortProtocol{
						{Port: "80", Protocol: ProtoAny},
					},
					Rules: &L7Rules{
						HTTP: []PortRuleHTTP{
							{Method: "GET", Path: "/"},
						},
					},
				}},
			},
		},
	}

	err = invalidPortRule.Sanitize()
	require.NotNil(t, err)
	require.Equal(t, "L7 rules can only apply to TCP (not ANY) except for DNS rules", err.Error())

	// Rule is invalid because only ProtoTCP is allowed for L7 rules (except with DNS, below).
	invalidPortRule = Rule{
		EndpointSelector: WildcardEndpointSelector,
		Ingress: []IngressRule{
			{
				IngressCommonRule: IngressCommonRule{
					FromEndpoints: []EndpointSelector{WildcardEndpointSelector},
				},
				ToPorts: []PortRule{{
					Ports: []PortProtocol{
						{Port: "80", Protocol: ProtoTCP},
						{Port: "12345", Protocol: ProtoUDP},
					},
					Rules: &L7Rules{
						HTTP: []PortRuleHTTP{
							{Method: "GET", Path: "/"},
						},
					},
				}},
			},
		},
	}

	err = invalidPortRule.Sanitize()
	require.NotNil(t, err)
	require.Equal(t, "L7 rules can only apply to TCP (not UDP) except for DNS rules", err.Error())

	// Same as previous rule, but ensure ordering doesn't affect validation.
	invalidPortRule = Rule{
		EndpointSelector: WildcardEndpointSelector,
		Ingress: []IngressRule{
			{
				IngressCommonRule: IngressCommonRule{
					FromEndpoints: []EndpointSelector{WildcardEndpointSelector},
				},
				ToPorts: []PortRule{{
					Ports: []PortProtocol{
						{Port: "80", Protocol: ProtoUDP},
						{Port: "12345", Protocol: ProtoTCP},
					},
					Rules: &L7Rules{
						HTTP: []PortRuleHTTP{
							{Method: "GET", Path: "/"},
						},
					},
				}},
			},
		},
	}

	err = invalidPortRule.Sanitize()
	require.NotNil(t, err)
	require.Equal(t, "L7 rules can only apply to TCP (not UDP) except for DNS rules", err.Error())

	// Rule is valid because ServerNames are allowed for SNI enforcement.
	validPortRule = Rule{
		EndpointSelector: WildcardEndpointSelector,
		Egress: []EgressRule{
			{
				EgressCommonRule: EgressCommonRule{
					ToEndpoints: []EndpointSelector{WildcardEndpointSelector},
				},
				ToPorts: []PortRule{{
					Ports: []PortProtocol{
						{Port: "443", Protocol: ProtoTCP},
					},
					ServerNames: []string{"foo.bar.com", "bar.foo.com"},
				}},
			},
		},
	}
	err = validPortRule.Sanitize()
	require.Nil(t, err)

	// Rule is invalid because empty ServerNames are not allowed
	invalidPortRule = Rule{
		EndpointSelector: WildcardEndpointSelector,
		Egress: []EgressRule{
			{
				EgressCommonRule: EgressCommonRule{
					ToEndpoints: []EndpointSelector{WildcardEndpointSelector},
				},
				ToPorts: []PortRule{{
					Ports: []PortProtocol{
						{Port: "443", Protocol: ProtoTCP},
					},
					ServerNames: []string{""},
				}},
			},
		},
	}
	err = invalidPortRule.Sanitize()
	require.NotNil(t, err)
	require.Equal(t, "Empty server name is not allowed", err.Error())

	//  Rule is invalid because ServerNames with L7 rules are not allowed without TLS termination.
	invalidPortRule = Rule{
		EndpointSelector: WildcardEndpointSelector,
		Egress: []EgressRule{
			{
				EgressCommonRule: EgressCommonRule{
					ToEndpoints: []EndpointSelector{WildcardEndpointSelector},
				},
				ToPorts: []PortRule{{
					Ports: []PortProtocol{
						{Port: "443", Protocol: ProtoTCP},
					},
					ServerNames: []string{"foo.bar.com", "bar.foo.com"},
					Rules: &L7Rules{
						HTTP: []PortRuleHTTP{
							{Method: "GET", Path: "/"},
						},
					},
				}},
			},
		},
	}
	err = invalidPortRule.Sanitize()
	require.NotNil(t, err)
	require.Equal(t, "ServerNames are not allowed with L7 rules without TLS termination", err.Error())

	// Rule is valid because ServerNames with L7 rules are allowed with TLS termination.
	validPortRule = Rule{
		EndpointSelector: WildcardEndpointSelector,
		Egress: []EgressRule{
			{
				EgressCommonRule: EgressCommonRule{
					ToEndpoints: []EndpointSelector{WildcardEndpointSelector},
				},
				ToPorts: []PortRule{{
					Ports: []PortProtocol{
						{Port: "443", Protocol: ProtoTCP},
					},
					TerminatingTLS: &TLSContext{
						Secret: &Secret{
							Name: "test-secret",
						},
					},
					ServerNames: []string{"foo.bar.com", "bar.foo.com"},
					Rules: &L7Rules{
						HTTP: []PortRuleHTTP{
							{Method: "GET", Path: "/"},
						},
					},
				}},
			},
		},
	}
	err = validPortRule.Sanitize()
	require.Nil(t, err)

	// Rule is valid because Listener is allowed on egress, default Kind
	validPortRule = Rule{
		EndpointSelector: WildcardEndpointSelector,
		Egress: []EgressRule{
			{
				EgressCommonRule: EgressCommonRule{
					ToEndpoints: []EndpointSelector{WildcardEndpointSelector},
				},
				ToPorts: []PortRule{{
					Ports: []PortProtocol{
						{Port: "443", Protocol: ProtoTCP},
					},
					Listener: &Listener{
						EnvoyConfig: &EnvoyConfig{
							Name: "test-config",
						},
						Name: "myCustomListener",
					},
				}},
			},
		},
	}
	err = validPortRule.Sanitize()
	require.Nil(t, err)

	// Rule is valid because Listener is allowed on egress, Kind CiliumClusterwideEnvoyConfig
	validPortRule = Rule{
		EndpointSelector: WildcardEndpointSelector,
		Egress: []EgressRule{
			{
				EgressCommonRule: EgressCommonRule{
					ToEndpoints: []EndpointSelector{WildcardEndpointSelector},
				},
				ToPorts: []PortRule{{
					Ports: []PortProtocol{
						{Port: "443", Protocol: ProtoTCP},
					},
					Listener: &Listener{
						EnvoyConfig: &EnvoyConfig{
							Kind: "CiliumClusterwideEnvoyConfig",
							Name: "shared-config",
						},
						Name: "myCustomListener",
					},
				}},
			},
		},
	}
	err = validPortRule.Sanitize()
	require.Nil(t, err)

	// Rule is valid because Listener is allowed on egress, Kind CiliumEnvoyConfig
	validPortRule = Rule{
		EndpointSelector: WildcardEndpointSelector,
		Egress: []EgressRule{
			{
				EgressCommonRule: EgressCommonRule{
					ToEndpoints: []EndpointSelector{WildcardEndpointSelector},
				},
				ToPorts: []PortRule{{
					Ports: []PortProtocol{
						{Port: "443", Protocol: ProtoTCP},
					},
					Listener: &Listener{
						EnvoyConfig: &EnvoyConfig{
							Kind: "CiliumEnvoyConfig",
							Name: "shared-config",
						},
						Name: "myCustomListener",
					},
				}},
			},
		},
	}
	err = validPortRule.Sanitize()
	require.Nil(t, err)

	// Rule is invalid because Listener is not allowed on ingress (yet)
	invalidPortRule = Rule{
		EndpointSelector: WildcardEndpointSelector,
		Ingress: []IngressRule{
			{
				IngressCommonRule: IngressCommonRule{
					FromEndpoints: []EndpointSelector{WildcardEndpointSelector},
				},
				ToPorts: []PortRule{{
					Ports: []PortProtocol{
						{Port: "443", Protocol: ProtoTCP},
					},
					Listener: &Listener{
						EnvoyConfig: &EnvoyConfig{
							Name: "test-config",
						},
						Name: "myCustomListener",
					},
				}},
			},
		},
	}
	err = invalidPortRule.Sanitize()
	require.NotNil(t, err)
	require.Equal(t, "Listener is not allowed on ingress (myCustomListener)", err.Error())

	// Rule is invalid because Listener is not allowed with L7 rules
	invalidPortRule = Rule{
		EndpointSelector: WildcardEndpointSelector,
		Egress: []EgressRule{
			{
				EgressCommonRule: EgressCommonRule{
					ToEndpoints: []EndpointSelector{WildcardEndpointSelector},
				},
				ToPorts: []PortRule{{
					Ports: []PortProtocol{
						{Port: "443", Protocol: ProtoTCP},
					},
					Listener: &Listener{
						EnvoyConfig: &EnvoyConfig{
							Name: "test-config",
						},
						Name: "myCustomListener",
					},
					Rules: &L7Rules{
						HTTP: []PortRuleHTTP{
							{Method: "GET", Path: "/"},
						},
					},
				}},
			},
		},
	}
	err = invalidPortRule.Sanitize()
	require.NotNil(t, err)
	require.Equal(t, "Listener is not allowed with L7 rules (myCustomListener)", err.Error())
}

// This test ensures that L7 rules reject unspecified ports.
func TestL7RuleRejectsEmptyPort(t *testing.T) {
	setUpSuite(t)

	invalidL7PortRule := Rule{
		EndpointSelector: WildcardEndpointSelector,
		Ingress: []IngressRule{
			{
				IngressCommonRule: IngressCommonRule{
					FromEndpoints: []EndpointSelector{WildcardEndpointSelector},
				},
				ToPorts: []PortRule{{
					Ports: []PortProtocol{
						{Port: "0", Protocol: ProtoTCP},
					},
					Rules: &L7Rules{
						HTTP: []PortRuleHTTP{
							{},
						},
					},
				}},
			},
		},
	}

	err := invalidL7PortRule.Sanitize()
	require.NotNil(t, err)
}

// This test ensures that PortRules using the HTTP protocol have valid regular
// expressions for the method and path fields.
func TestHTTPRuleRegexes(t *testing.T) {
	setUpSuite(t)

	invalidHTTPRegexPathRule := Rule{
		EndpointSelector: WildcardEndpointSelector,
		Ingress: []IngressRule{
			{
				IngressCommonRule: IngressCommonRule{
					FromEndpoints: []EndpointSelector{WildcardEndpointSelector},
				},
				ToPorts: []PortRule{{
					Ports: []PortProtocol{
						{Port: "80", Protocol: ProtoTCP},
						{Port: "81", Protocol: ProtoTCP},
					},
					Rules: &L7Rules{
						HTTP: []PortRuleHTTP{
							{Method: "GET", Path: "*"},
						},
					},
				}},
			},
		},
	}

	err := invalidHTTPRegexPathRule.Sanitize()
	require.NotNil(t, err)

	invalidHTTPRegexMethodRule := Rule{
		EndpointSelector: WildcardEndpointSelector,
		Ingress: []IngressRule{
			{
				IngressCommonRule: IngressCommonRule{
					FromEndpoints: []EndpointSelector{WildcardEndpointSelector},
				},
				ToPorts: []PortRule{{
					Ports: []PortProtocol{
						{Port: "80", Protocol: ProtoTCP},
						{Port: "81", Protocol: ProtoTCP},
					},
					Rules: &L7Rules{
						HTTP: []PortRuleHTTP{
							{Method: "*", Path: "/"},
						},
					},
				}},
			},
		},
	}

	err = invalidHTTPRegexMethodRule.Sanitize()
	require.NotNil(t, err)
}

// Test the validation of CIDR rule prefix definitions
func TestCIDRsanitize(t *testing.T) {
	setUpSuite(t)

	// IPv4
	cidr := CIDRRule{Cidr: "0.0.0.0/0"}
	err := cidr.sanitize()
	require.Nil(t, err)

	cidr = CIDRRule{Cidr: "10.0.0.0/24"}
	err = cidr.sanitize()
	require.Nil(t, err)

	cidr = CIDRRule{Cidr: "192.0.2.3/32"}
	err = cidr.sanitize()
	require.Nil(t, err)

	// IPv6
	cidr = CIDRRule{Cidr: "::/0"}
	err = cidr.sanitize()
	require.Nil(t, err)

	cidr = CIDRRule{Cidr: "ff02::/64"}
	err = cidr.sanitize()
	require.Nil(t, err)

	cidr = CIDRRule{Cidr: "2001:0db8:85a3:0000:0000:8a2e:0370:7334/128"}
	err = cidr.sanitize()
	require.Nil(t, err)

	// Non-contiguous mask.
	cidr = CIDRRule{Cidr: "10.0.0.0/254.0.0.255"}
	err = cidr.sanitize()
	require.Error(t, err)
}

func TestToServicesSanitize(t *testing.T) {
	setUpSuite(t)

	svcLabels := map[string]string{
		"app": "tested-service",
	}
	selector := ServiceSelector(NewESFromMatchRequirements(svcLabels, nil))
	toServicesL3L4 := Rule{
		EndpointSelector: WildcardEndpointSelector,
		Egress: []EgressRule{
			{
				EgressCommonRule: EgressCommonRule{
					ToServices: []Service{
						{
							K8sServiceSelector: &K8sServiceSelectorNamespace{
								Selector:  selector,
								Namespace: "",
							},
						},
					},
				},
				ToPorts: []PortRule{{
					Ports: []PortProtocol{
						{Port: "80", Protocol: ProtoTCP},
						{Port: "81", Protocol: ProtoTCP},
					},
				}},
			},
		},
	}

	err := toServicesL3L4.Sanitize()
	require.Error(t, err)
}

// This test ensures that PortRules using key-value pairs do not have empty keys
func TestL7Rules(t *testing.T) {
	setUpSuite(t)

	validL7Rule := Rule{
		EndpointSelector: WildcardEndpointSelector,
		Ingress: []IngressRule{
			{
				IngressCommonRule: IngressCommonRule{
					FromEndpoints: []EndpointSelector{WildcardEndpointSelector},
				},
				ToPorts: []PortRule{{
					Ports: []PortProtocol{
						{Port: "80", Protocol: ProtoTCP},
						{Port: "81", Protocol: ProtoTCP},
					},
					Rules: &L7Rules{
						L7Proto: "test.lineparser",
						L7: []PortRuleL7{
							{"method": "PUT", "path": "/"},
							{"method": "GET", "path": "/"},
						},
					},
				}},
			},
		},
	}

	err := validL7Rule.Sanitize()
	require.Nil(t, err)

	validL7Rule2 := Rule{
		EndpointSelector: WildcardEndpointSelector,
		Ingress: []IngressRule{
			{
				IngressCommonRule: IngressCommonRule{
					FromEndpoints: []EndpointSelector{WildcardEndpointSelector},
				},
				ToPorts: []PortRule{{
					Ports: []PortProtocol{
						{Port: "80", Protocol: ProtoTCP},
						{Port: "81", Protocol: ProtoTCP},
					},
					Rules: &L7Rules{
						L7Proto: "test.lineparser",
						// No L7 rules
					},
				}},
			},
		},
	}

	err = validL7Rule2.Sanitize()
	require.Nil(t, err)

	invalidL7Rule := Rule{
		EndpointSelector: WildcardEndpointSelector,
		Ingress: []IngressRule{
			{
				IngressCommonRule: IngressCommonRule{
					FromEndpoints: []EndpointSelector{WildcardEndpointSelector},
				},
				ToPorts: []PortRule{{
					Ports: []PortProtocol{
						{Port: "80", Protocol: ProtoTCP},
						{Port: "81", Protocol: ProtoTCP},
					},
					Rules: &L7Rules{
						L7Proto: "test.lineparser",
						L7: []PortRuleL7{
							map[string]string{
								"method": "PUT",
								"":       "Foo"},
						},
					},
				}},
			},
		},
	}

	err = invalidL7Rule.Sanitize()
	require.NotNil(t, err)
}

// This test ensures that host policies with L7 rules (except for DNS egress) are rejected.
func TestL7RulesWithNodeSelector(t *testing.T) {
	setUpSuite(t)

	toPortsHTTP := []PortRule{{
		Ports: []PortProtocol{
			{Port: "80", Protocol: ProtoTCP},
		},
		Rules: &L7Rules{
			HTTP: []PortRuleHTTP{
				{Method: "PUT", Path: "/"},
			},
		},
	}}

	invalidL7RuleIngress := Rule{
		NodeSelector: WildcardEndpointSelector,
		Ingress: []IngressRule{
			{
				IngressCommonRule: IngressCommonRule{
					FromEndpoints: []EndpointSelector{WildcardEndpointSelector},
				},
				ToPorts: toPortsHTTP,
			},
		},
	}
	err := invalidL7RuleIngress.Sanitize()
	require.Equal(t, "L7 policy is not supported on host ingress yet", err.Error())

	invalidL7RuleEgress := Rule{
		NodeSelector: WildcardEndpointSelector,
		Egress: []EgressRule{
			{
				EgressCommonRule: EgressCommonRule{
					ToEndpoints: []EndpointSelector{WildcardEndpointSelector},
				},
				ToPorts: toPortsHTTP,
			},
		},
	}

	err = invalidL7RuleEgress.Sanitize()
	Assert(err.Error(), Equals, "L7 protocol HTTP is not supported on host egress yet")

	validL7RuleEgress := Rule{
		NodeSelector: WildcardEndpointSelector,
		Egress: []EgressRule{
			{
				EgressCommonRule: EgressCommonRule{
					ToEndpoints: []EndpointSelector{WildcardEndpointSelector},
				},
				ToPorts: []PortRule{{
					Ports: []PortProtocol{
						{Port: "53", Protocol: ProtoUDP},
					},
					Rules: &L7Rules{
						DNS: []PortRuleDNS{
							{MatchName: "domain.com"},
						},
					},
				}},
			},
		},
	}
	err = validL7RuleEgress.Sanitize()
	require.Nil(t, err)

	validL7RuleIngress := Rule{
		NodeSelector: WildcardEndpointSelector,
		Ingress: []IngressRule{
			{
				IngressCommonRule: IngressCommonRule{
					FromEndpoints: []EndpointSelector{WildcardEndpointSelector},
				},
			},
		},
	}
	err = validL7RuleIngress.Sanitize()
	require.Nil(t, err)
}

func TestInvalidEndpointSelectors(t *testing.T) {
	setUpSuite(t)

	// Operator in MatchExpressions is invalid, so sanitization should fail.
	labelSel := &slim_metav1.LabelSelector{
		MatchLabels: map[string]string{
			"any.foo": "bar",
			"k8s.baz": "alice",
		},
		MatchExpressions: []slim_metav1.LabelSelectorRequirement{
			{
				Key:      "any.foo",
				Operator: "asdfasdfasdf",
				Values:   []string{"default"},
			},
		},
	}

	invalidSel := NewESFromK8sLabelSelector(labels.LabelSourceK8sKeyPrefix, labelSel)

	invalidEpSelectorRule := Rule{
		EndpointSelector: invalidSel,
	}

	err := invalidEpSelectorRule.Sanitize()
	require.NotNil(t, err)

	invalidEpSelectorIngress := Rule{
		EndpointSelector: WildcardEndpointSelector,
		Ingress: []IngressRule{
			{
				IngressCommonRule: IngressCommonRule{
					FromEndpoints: []EndpointSelector{invalidSel},
				},
			},
		},
	}

	err = invalidEpSelectorIngress.Sanitize()
	require.NotNil(t, err)

	invalidEpSelectorIngressFromReq := Rule{
		EndpointSelector: WildcardEndpointSelector,
		Ingress: []IngressRule{
			{
				IngressCommonRule: IngressCommonRule{
					FromRequires: []EndpointSelector{invalidSel},
				},
			},
		},
	}

	err = invalidEpSelectorIngressFromReq.Sanitize()
	require.NotNil(t, err)

	invalidEpSelectorEgress := Rule{
		EndpointSelector: WildcardEndpointSelector,
		Egress: []EgressRule{
			{
				EgressCommonRule: EgressCommonRule{
					ToEndpoints: []EndpointSelector{invalidSel},
				},
			},
		},
	}

	err = invalidEpSelectorEgress.Sanitize()
	require.NotNil(t, err)

	invalidEpSelectorEgressToReq := Rule{
		EndpointSelector: WildcardEndpointSelector,
		Egress: []EgressRule{
			{
				EgressCommonRule: EgressCommonRule{
					ToRequires: []EndpointSelector{invalidSel},
				},
			},
		},
	}

	err = invalidEpSelectorEgressToReq.Sanitize()
	require.NotNil(t, err)

}

func TestNodeSelector(t *testing.T) {
	setUpSuite(t)

	// Operator in MatchExpressions is invalid, so sanitization should fail.
	labelSel := &slim_metav1.LabelSelector{
		MatchLabels: map[string]string{
			"any.foo": "bar",
			"k8s.baz": "alice",
		},
		MatchExpressions: []slim_metav1.LabelSelectorRequirement{
			{
				Key:      "any.foo",
				Operator: "asdfasdfasdf",
				Values:   []string{"default"},
			},
		},
	}
	invalidSel := NewESFromK8sLabelSelector(labels.LabelSourceK8sKeyPrefix, labelSel)
	invalidNodeSelectorRule := Rule{
		NodeSelector: invalidSel,
	}
	err := invalidNodeSelectorRule.Sanitize()
	require.EqualError(t, err, "invalid label selector: matchExpressions[0].operator: Invalid value: \"asdfasdfasdf\": not a valid selector operator")

	invalidRuleBothSelectors := Rule{
		EndpointSelector: WildcardEndpointSelector,
		NodeSelector:     WildcardEndpointSelector,
	}
	err = invalidRuleBothSelectors.Sanitize()
	require.Equal(t, "rule cannot have both EndpointSelector and NodeSelector", err.Error())

	invalidRuleNoSelector := Rule{}
	err = invalidRuleNoSelector.Sanitize()
	require.Equal(t, "rule must have one of EndpointSelector or NodeSelector", err.Error())
}

func TestTooManyPortsRule(t *testing.T) {
	setUpSuite(t)

	var portProtocols []PortProtocol

	for i := 80; i <= 80+maxPorts; i++ {
		portProtocols = append(portProtocols, PortProtocol{
			Port:     fmt.Sprintf("%d", i),
			Protocol: ProtoTCP,
		})
	}

	tooManyPortsRule := Rule{
		EndpointSelector: WildcardEndpointSelector,
		Ingress: []IngressRule{
			{
				IngressCommonRule: IngressCommonRule{
					FromEndpoints: []EndpointSelector{WildcardEndpointSelector},
				},
				ToPorts: []PortRule{{
					Ports: portProtocols,
				}},
			},
		},
	}
	err := tooManyPortsRule.Sanitize()
	require.Error(t, err)
}

func TestTooManyICMPFields(t *testing.T) {
	setUpSuite(t)

	var fields []ICMPField

	for i := 1; i <= 1+maxICMPFields; i++ {
		icmpType := intstr.FromInt(i)
		fields = append(fields, ICMPField{
			Type: &icmpType,
		})
	}

	tooManyICMPRule := Rule{
		EndpointSelector: WildcardEndpointSelector,
		Ingress: []IngressRule{
			{
				IngressCommonRule: IngressCommonRule{
					FromEndpoints: []EndpointSelector{WildcardEndpointSelector},
				},
				ICMPs: ICMPRules{{
					Fields: fields,
				}},
			},
		},
	}
	err := tooManyICMPRule.Sanitize()
	require.Error(t, err)
}

func TestWrongICMPFieldFamily(t *testing.T) {
	setUpSuite(t)

	icmpType := intstr.FromInt(0)
	wrongFamilyICMPRule := Rule{
		EndpointSelector: WildcardEndpointSelector,
		Ingress: []IngressRule{
			{
				IngressCommonRule: IngressCommonRule{
					FromEndpoints: []EndpointSelector{WildcardEndpointSelector},
				},
				ICMPs: ICMPRules{{
					Fields: []ICMPField{{
						Family: "hoge",
						Type:   &icmpType,
					}},
				}},
			},
		},
	}
	err := wrongFamilyICMPRule.Sanitize()
	require.Error(t, err)
}

func TestICMPRuleWithOtherRuleFailed(t *testing.T) {
	setUpSuite(t)

	icmpType := intstr.FromInt(8)
	ingressICMPWithPort := Rule{
		EndpointSelector: WildcardEndpointSelector,
		Ingress: []IngressRule{
			{
				IngressCommonRule: IngressCommonRule{
					FromEndpoints: []EndpointSelector{WildcardEndpointSelector},
				},
				ToPorts: []PortRule{{
					Ports: []PortProtocol{
						{Port: "80", Protocol: ProtoTCP},
					},
				}},
				ICMPs: ICMPRules{{
					Fields: []ICMPField{{
						Type: &icmpType,
					}},
				}},
			},
		},
	}

	egressICMPWithPort := Rule{
		EndpointSelector: WildcardEndpointSelector,
		Egress: []EgressRule{
			{
				EgressCommonRule: EgressCommonRule{
					ToEndpoints: []EndpointSelector{WildcardEndpointSelector},
				},
				ToPorts: []PortRule{{
					Ports: []PortProtocol{
						{Port: "80", Protocol: ProtoTCP},
					},
				}},
				ICMPs: ICMPRules{{
					Fields: []ICMPField{{
						Type: &icmpType,
					}},
				}},
			},
		},
	}

	option.Config.EnableICMPRules = true
	errStr := "The ICMPs block may only be present without ToPorts. Define a separate rule to use ToPorts."
	err := ingressICMPWithPort.Sanitize()
	require.ErrorContains(t, err, errStr)
	err = egressICMPWithPort.Sanitize()
	require.ErrorContains(t, err, errStr)
}

// This test ensures that PortRules aren't configured in the wrong direction,
// which ends up being a no-op with only vague error messages rather than a
// clear indication that something is wrong in the policy.
func TestL7RuleDirectionalitySupport(t *testing.T) {
	setUpSuite(t)

	// Kafka egress is now supported.
	egressKafkaRule := Rule{
		EndpointSelector: WildcardEndpointSelector,
		Egress: []EgressRule{
			{
				ToPorts: []PortRule{{
					Ports: []PortProtocol{
						{Port: "80", Protocol: ProtoTCP},
						{Port: "81", Protocol: ProtoTCP},
					},
					Rules: &L7Rules{
						Kafka: []kafka.PortRule{{
							Role:  "consume",
							Topic: "deathstar-plans",
						}},
					},
				}},
			},
		},
	}

	err := egressKafkaRule.Sanitize()
	require.Nil(t, err)

	// DNS ingress is not supported.
	invalidDNSRule := Rule{
		EndpointSelector: WildcardEndpointSelector,
		Ingress: []IngressRule{
			{
				ToPorts: []PortRule{{
					Ports: []PortProtocol{
						{Port: "53", Protocol: ProtoTCP},
						{Port: "53", Protocol: ProtoUDP},
					},
					Rules: &L7Rules{
						DNS: []PortRuleDNS{{
							MatchName: "empire.gov",
						}},
					},
				}},
			},
		},
	}

	err = invalidDNSRule.Sanitize()
	require.NotNil(t, err)

}

func BenchmarkCIDRSanitize(b *testing.B) {
	cidr4 := CIDRRule{Cidr: "192.168.100.200/24"}
	cidr6 := CIDRRule{Cidr: "2001:0db8:85a3:0000:0000:8a2e:0370:7334/128"}

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		err := cidr4.sanitize()
		if err != nil {
			b.Fatal(err)
		}
		err = cidr6.sanitize()
		if err != nil {
			b.Fatal(err)
		}
	}
}

func TestSanitizeDefaultDeny(t *testing.T) {
	for _, tc := range []struct {
		before      Rule
		wantIngress bool
		wantEgress  bool
	}{
		{
			before: Rule{},
		},
		{
			before: Rule{
				Ingress: []IngressRule{{}},
			},
			wantIngress: true,
		},
		{
			before: Rule{
				IngressDeny: []IngressDenyRule{{}},
			},
			wantIngress: true,
		},
		{
			before: Rule{
				Ingress:     []IngressRule{{}},
				IngressDeny: []IngressDenyRule{{}},
			},
			wantIngress: true,
		},
		{
			before: Rule{
				Egress:     []EgressRule{{}},
				EgressDeny: []EgressDenyRule{{}},
			},
			wantEgress: true,
		}, {
			before: Rule{
				EgressDeny: []EgressDenyRule{{}},
			},
			wantEgress: true,
		},
		{
			before: Rule{
				Egress: []EgressRule{{}},
			},
			wantEgress: true,
		},
		{
			before: Rule{
				Egress:  []EgressRule{{}},
				Ingress: []IngressRule{{}},
			},
			wantEgress:  true,
			wantIngress: true,
		},
	} {
		b := tc.before
		b.EndpointSelector = EndpointSelector{LabelSelector: &slim_metav1.LabelSelector{}}

		err := b.Sanitize()
		assert.Nil(t, err)
		assert.NotNil(t, b.EnableDefaultDeny.Egress)
		assert.NotNil(t, b.EnableDefaultDeny.Ingress)

		assert.Equal(t, tc.wantEgress, *b.EnableDefaultDeny.Egress, "Rule.EnableDefaultDeny.Egress should match")
		assert.Equal(t, tc.wantIngress, *b.EnableDefaultDeny.Ingress, "Rule.EnableDefaultDeny.Ingress should match")
	}
}

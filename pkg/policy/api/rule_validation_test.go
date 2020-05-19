// Copyright 2018-2020 Authors of Cilium
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

// +build !privileged_tests

package api

import (
	"fmt"

	slim_metav1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/apis/meta/v1"
	"github.com/cilium/cilium/pkg/labels"

	. "gopkg.in/check.v1"
)

// This test ensures that only PortRules which have L7Rules associated with them
// are invalid if any protocol except TCP is used as a protocol for any port
// in the list of PortProtocol supplied to the rule.
func (s *PolicyAPITestSuite) TestL7RulesWithNonTCPProtocols(c *C) {

	// Rule is valid because only ProtoTCP is allowed for L7 rules (except with ToFQDNs, below).
	validPortRule := Rule{
		EndpointSelector: WildcardEndpointSelector,
		Ingress: []IngressRule{
			{
				FromEndpoints: []EndpointSelector{WildcardEndpointSelector},
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
	c.Assert(err, IsNil)

	// Rule is invalid because no port is specified for DNS proxy rule.
	validPortRule = Rule{
		EndpointSelector: WildcardEndpointSelector,
		Egress: []EgressRule{
			{
				ToEndpoints: []EndpointSelector{WildcardEndpointSelector},
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
	c.Assert(err, Not(IsNil), Commentf("Port 53 must be specified for DNS rules"))

	// Rule is valid because all protocols are allowed for L7 rules with ToFQDNs.
	validPortRule = Rule{
		EndpointSelector: WildcardEndpointSelector,
		Egress: []EgressRule{
			{
				ToEndpoints: []EndpointSelector{WildcardEndpointSelector},
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
	c.Assert(err, IsNil, Commentf("Saw an error for a L7 rule with DNS rules. This should be allowed."))

	// Rule is invalid because only ProtoTCP is allowed for L7 rules (except with DNS, below).
	invalidPortRule := Rule{
		EndpointSelector: WildcardEndpointSelector,
		Ingress: []IngressRule{
			{
				FromEndpoints: []EndpointSelector{WildcardEndpointSelector},
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
	c.Assert(err.Error(), Equals, "L7 rules can only apply to TCP (not UDP) except for DNS rules")

	// Rule is invalid because DNS proxy rules are not allowed on ingress rules.
	invalidPortRule = Rule{
		EndpointSelector: WildcardEndpointSelector,
		Ingress: []IngressRule{
			{
				FromEndpoints: []EndpointSelector{WildcardEndpointSelector},
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
	c.Assert(err, Not(IsNil), Commentf("DNS rule should not be allowed on ingress"))

	// Rule is invalid because only ProtoTCP is allowed for L7 rules (except with DNS, below).
	invalidPortRule = Rule{
		EndpointSelector: WildcardEndpointSelector,
		Ingress: []IngressRule{
			{
				FromEndpoints: []EndpointSelector{WildcardEndpointSelector},
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
	c.Assert(err, Not(IsNil))
	c.Assert(err.Error(), Equals, "L7 rules can only apply to TCP (not ANY) except for DNS rules")

	// Rule is invalid because only ProtoTCP is allowed for L7 rules (except with DNS, below).
	invalidPortRule = Rule{
		EndpointSelector: WildcardEndpointSelector,
		Ingress: []IngressRule{
			{
				FromEndpoints: []EndpointSelector{WildcardEndpointSelector},
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
	c.Assert(err, Not(IsNil))
	c.Assert(err.Error(), Equals, "L7 rules can only apply to TCP (not UDP) except for DNS rules")

	// Same as previous rule, but ensure ordering doesn't affect validation.
	invalidPortRule = Rule{
		EndpointSelector: WildcardEndpointSelector,
		Ingress: []IngressRule{
			{
				FromEndpoints: []EndpointSelector{WildcardEndpointSelector},
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
	c.Assert(err, Not(IsNil))
	c.Assert(err.Error(), Equals, "L7 rules can only apply to TCP (not UDP) except for DNS rules")

}

// This test ensures that PortRules using the HTTP protocol have valid regular
// expressions for the method and path fields.
func (s *PolicyAPITestSuite) TestHTTPRuleRegexes(c *C) {

	invalidHTTPRegexPathRule := Rule{
		EndpointSelector: WildcardEndpointSelector,
		Ingress: []IngressRule{
			{
				FromEndpoints: []EndpointSelector{WildcardEndpointSelector},
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
	c.Assert(err, Not(IsNil))

	invalidHTTPRegexMethodRule := Rule{
		EndpointSelector: WildcardEndpointSelector,
		Ingress: []IngressRule{
			{
				FromEndpoints: []EndpointSelector{WildcardEndpointSelector},
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
	c.Assert(err, Not(IsNil))
}

// Test the validation of CIDR rule prefix definitions
func (s *PolicyAPITestSuite) TestCIDRsanitize(c *C) {
	// IPv4
	cidr := CIDRRule{Cidr: "0.0.0.0/0"}
	length, err := cidr.sanitize()
	c.Assert(err, IsNil)
	c.Assert(length, Equals, 0)

	cidr = CIDRRule{Cidr: "10.0.0.0/24"}
	length, err = cidr.sanitize()
	c.Assert(err, IsNil)
	c.Assert(length, Equals, 24)

	cidr = CIDRRule{Cidr: "192.0.2.3/32"}
	length, err = cidr.sanitize()
	c.Assert(err, IsNil)
	c.Assert(length, Equals, 32)

	// IPv6
	cidr = CIDRRule{Cidr: "::/0"}
	length, err = cidr.sanitize()
	c.Assert(err, IsNil)
	c.Assert(length, Equals, 0)

	cidr = CIDRRule{Cidr: "ff02::/64"}
	length, err = cidr.sanitize()
	c.Assert(err, IsNil)
	c.Assert(length, Equals, 64)

	cidr = CIDRRule{Cidr: "2001:0db8:85a3:0000:0000:8a2e:0370:7334/128"}
	length, err = cidr.sanitize()
	c.Assert(err, IsNil)
	c.Assert(length, Equals, 128)

	// Non-contiguous mask.
	cidr = CIDRRule{Cidr: "10.0.0.0/254.0.0.255"}
	_, err = cidr.sanitize()
	c.Assert(err, NotNil)
}

func (s *PolicyAPITestSuite) TestToServicesSanitize(c *C) {

	svcLabels := map[string]string{
		"app": "tested-service",
	}
	selector := ServiceSelector(NewESFromMatchRequirements(svcLabels, nil))
	toServicesL3L4 := Rule{
		EndpointSelector: WildcardEndpointSelector,
		Egress: []EgressRule{
			{
				ToServices: []Service{
					{
						K8sServiceSelector: &K8sServiceSelectorNamespace{
							Selector:  selector,
							Namespace: "",
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
	c.Assert(err, IsNil)

}

// This test ensures that PortRules using key-value pairs do not have empty keys
func (s *PolicyAPITestSuite) TestL7Rules(c *C) {

	validL7Rule := Rule{
		EndpointSelector: WildcardEndpointSelector,
		Ingress: []IngressRule{
			{
				FromEndpoints: []EndpointSelector{WildcardEndpointSelector},
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
	c.Assert(err, IsNil)

	validL7Rule2 := Rule{
		EndpointSelector: WildcardEndpointSelector,
		Ingress: []IngressRule{
			{
				FromEndpoints: []EndpointSelector{WildcardEndpointSelector},
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
	c.Assert(err, IsNil)

	invalidL7Rule := Rule{
		EndpointSelector: WildcardEndpointSelector,
		Ingress: []IngressRule{
			{
				FromEndpoints: []EndpointSelector{WildcardEndpointSelector},
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
	c.Assert(err, Not(IsNil))
}

// This test ensures that host policies with L7 rules are rejected.
func (s *PolicyAPITestSuite) TestL7RulesWithNodeSelector(c *C) {
	invalidL7RuleIngress := Rule{
		NodeSelector: WildcardEndpointSelector,
		Ingress: []IngressRule{
			{
				FromEndpoints: []EndpointSelector{WildcardEndpointSelector},
				ToPorts: []PortRule{{
					Ports: []PortProtocol{
						{Port: "80", Protocol: ProtoTCP},
					},
					Rules: &L7Rules{
						HTTP: []PortRuleHTTP{
							{Method: "PUT", Path: "/"},
						},
					},
				}},
			},
		},
	}
	err := invalidL7RuleIngress.Sanitize()
	c.Assert(err.Error(), Equals, "host policies do not support L7 rules yet")

	invalidL7RuleEgress := Rule{
		NodeSelector: WildcardEndpointSelector,
		Egress: []EgressRule{
			{
				ToEndpoints: []EndpointSelector{WildcardEndpointSelector},
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
	err = invalidL7RuleEgress.Sanitize()
	c.Assert(err.Error(), Equals, "host policies do not support L7 rules yet")

	validL7RuleIngress := Rule{
		NodeSelector: WildcardEndpointSelector,
		Ingress: []IngressRule{
			{
				FromEndpoints: []EndpointSelector{WildcardEndpointSelector},
			},
		},
	}
	err = validL7RuleIngress.Sanitize()
	c.Assert(err, IsNil)
}

func (s *PolicyAPITestSuite) TestInvalidEndpointSelectors(c *C) {

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
	c.Assert(err, Not(IsNil))

	invalidEpSelectorIngress := Rule{
		EndpointSelector: WildcardEndpointSelector,
		Ingress: []IngressRule{
			{
				FromEndpoints: []EndpointSelector{invalidSel},
			},
		},
	}

	err = invalidEpSelectorIngress.Sanitize()
	c.Assert(err, Not(IsNil))

	invalidEpSelectorIngressFromReq := Rule{
		EndpointSelector: WildcardEndpointSelector,
		Ingress: []IngressRule{
			{
				FromRequires: []EndpointSelector{invalidSel},
			},
		},
	}

	err = invalidEpSelectorIngressFromReq.Sanitize()
	c.Assert(err, Not(IsNil))

	invalidEpSelectorEgress := Rule{
		EndpointSelector: WildcardEndpointSelector,
		Egress: []EgressRule{
			{
				ToEndpoints: []EndpointSelector{invalidSel},
			},
		},
	}

	err = invalidEpSelectorEgress.Sanitize()
	c.Assert(err, Not(IsNil))

	invalidEpSelectorEgressToReq := Rule{
		EndpointSelector: WildcardEndpointSelector,
		Egress: []EgressRule{
			{
				ToRequires: []EndpointSelector{invalidSel},
			},
		},
	}

	err = invalidEpSelectorEgressToReq.Sanitize()
	c.Assert(err, Not(IsNil))

}

func (s *PolicyAPITestSuite) TestNodeSelector(c *C) {
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
	c.Assert(err.Error(), Equals,
		"invalid label selector: matchExpressions[0].operator: Invalid value: \"asdfasdfasdf\": not a valid selector operator")

	invalidRuleBothSelectors := Rule{
		EndpointSelector: WildcardEndpointSelector,
		NodeSelector:     WildcardEndpointSelector,
	}
	err = invalidRuleBothSelectors.Sanitize()
	c.Assert(err.Error(), Equals, "rule cannot have both EndpointSelector and NodeSelector")

	invalidRuleNoSelector := Rule{}
	err = invalidRuleNoSelector.Sanitize()
	c.Assert(err.Error(), Equals, "rule must have one of EndpointSelector or NodeSelector")
}

func (s *PolicyAPITestSuite) TestTooManyPortsRule(c *C) {

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
				FromEndpoints: []EndpointSelector{WildcardEndpointSelector},
				ToPorts: []PortRule{{
					Ports: portProtocols,
				}},
			},
		},
	}
	err := tooManyPortsRule.Sanitize()
	c.Assert(err, NotNil)
}

// This test ensures that PortRules aren't configured in the wrong direction,
// which ends up being a no-op with only vague error messages rather than a
// clear indication that something is wrong in the policy.
func (s *PolicyAPITestSuite) TestL7RuleDirectionalitySupport(c *C) {

	// Kafka egress is not supported.
	invalidKafkaRule := Rule{
		EndpointSelector: WildcardEndpointSelector,
		Egress: []EgressRule{
			{
				ToPorts: []PortRule{{
					Ports: []PortProtocol{
						{Port: "80", Protocol: ProtoTCP},
						{Port: "81", Protocol: ProtoTCP},
					},
					Rules: &L7Rules{
						Kafka: []PortRuleKafka{{
							Role:  "consume",
							Topic: "deathstar-plans",
						}},
					},
				}},
			},
		},
	}

	err := invalidKafkaRule.Sanitize()
	c.Assert(err, Not(IsNil))

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
	c.Assert(err, Not(IsNil))

}

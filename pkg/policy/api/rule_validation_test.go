// Copyright 2018 Authors of Cilium
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

package api

import (
	. "gopkg.in/check.v1"
)

// This test ensures that only PortRules which have L7Rules associated with them
// are invalid if any protocol except TCP is used as a protocol for any port
// in the list of PortProtocol supplied to the rule.
func (s *PolicyAPITestSuite) TestL7RulesWithNonTCPProtocols(c *C) {

	// Rule is valid because L7 rules are only allowed for ProtoTCP.
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

	// Rule is invalid because L7 rules are only allowed for ProtoTCP.
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
	c.Assert(err.Error(), Equals, "L7 rules can only apply exclusively to TCP, not UDP")

	// Rule is invalid because L7 rules are only allowed for ProtoTCP.
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
	c.Assert(err.Error(), Equals, "L7 rules can only apply exclusively to TCP, not ANY")

	// Rule is invalid because L7 rules are only allowed for ProtoTCP.
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
	c.Assert(err.Error(), Equals, "L7 rules can only apply exclusively to TCP, not UDP")

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
	c.Assert(err.Error(), Equals, "L7 rules can only apply exclusively to TCP, not UDP")

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
							map[string]string{
								"method": "PUT",
								"path":   "/"},
							map[string]string{
								"method": "GET",
								"path":   "/"},
						},
					},
				}},
			},
		},
	}

	err := validL7Rule.Sanitize()
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

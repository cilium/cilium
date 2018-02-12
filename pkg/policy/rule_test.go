// Copyright 2016-2017 Authors of Cilium
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

package policy

import (
	"net"

	"github.com/cilium/cilium/pkg/comparator"
	"github.com/cilium/cilium/pkg/labels"
	"github.com/cilium/cilium/pkg/policy/api"

	. "gopkg.in/check.v1"
)

func (ds *PolicyTestSuite) TestRuleCanReach(c *C) {
	fooFoo2ToBar := &SearchContext{
		From: labels.ParseSelectLabelArray("foo", "foo2"),
		To:   labels.ParseSelectLabelArray("bar"),
	}
	fooToBar := &SearchContext{
		From: labels.ParseSelectLabelArray("foo"),
		To:   labels.ParseSelectLabelArray("bar"),
	}

	rule1 := rule{
		Rule: api.Rule{
			EndpointSelector: api.NewESFromLabels(labels.ParseSelectLabel("bar")),
			Ingress: []api.IngressRule{
				{
					FromEndpoints: []api.EndpointSelector{
						api.NewESFromLabels(
							labels.ParseSelectLabel("foo"),
							labels.ParseSelectLabel("foo2"),
						),
					},
				},
			},
		},
	}

	state := traceState{}
	c.Assert(rule1.canReachIngress(fooFoo2ToBar, &state), Equals, api.Allowed)
	c.Assert(state.selectedRules, Equals, 1)
	c.Assert(state.matchedRules, Equals, 1)
	state = traceState{}
	c.Assert(rule1.canReachIngress(fooToBar, &traceState{}), Equals, api.Undecided)
	c.Assert(state.selectedRules, Equals, 0)
	c.Assert(state.matchedRules, Equals, 0)

	// selector: bar
	// allow: foo
	// require: baz
	rule2 := rule{
		Rule: api.Rule{
			EndpointSelector: api.NewESFromLabels(labels.ParseSelectLabel("bar")),
			Ingress: []api.IngressRule{
				{
					FromEndpoints: []api.EndpointSelector{
						api.NewESFromLabels(labels.ParseSelectLabel("foo")),
					},
					FromRequires: []api.EndpointSelector{
						api.NewESFromLabels(labels.ParseSelectLabel("baz")),
					},
				},
			},
		},
	}

	fooBazToBar := &SearchContext{
		From: labels.ParseSelectLabelArray("foo", "baz"),
		To:   labels.ParseSelectLabelArray("bar"),
	}
	bazToBar := &SearchContext{
		From: labels.ParseSelectLabelArray("baz"),
		To:   labels.ParseSelectLabelArray("bar"),
	}

	state = traceState{}
	c.Assert(rule2.canReachIngress(fooToBar, &state), Equals, api.Denied)
	c.Assert(state.selectedRules, Equals, 1)
	c.Assert(state.matchedRules, Equals, 0)

	state = traceState{}
	c.Assert(rule2.canReachIngress(bazToBar, &state), Equals, api.Undecided)
	c.Assert(state.selectedRules, Equals, 1)
	c.Assert(state.matchedRules, Equals, 0)

	state = traceState{}
	c.Assert(rule2.canReachIngress(fooBazToBar, &state), Equals, api.Allowed)
	c.Assert(state.selectedRules, Equals, 1)
	c.Assert(state.matchedRules, Equals, 1)
}

func (ds *PolicyTestSuite) TestL4Policy(c *C) {
	toBar := &SearchContext{To: labels.ParseSelectLabelArray("bar")}
	toFoo := &SearchContext{To: labels.ParseSelectLabelArray("foo")}

	rule1 := &rule{
		Rule: api.Rule{
			EndpointSelector: api.NewESFromLabels(labels.ParseSelectLabel("bar")),
			Ingress: []api.IngressRule{
				{
					ToPorts: []api.PortRule{{
						Ports: []api.PortProtocol{
							{Port: "80", Protocol: api.ProtoTCP},
							{Port: "8080", Protocol: api.ProtoTCP},
						},
						Rules: &api.L7Rules{
							HTTP: []api.PortRuleHTTP{
								{Method: "GET", Path: "/"},
							},
						},
					}},
				},
			},
			Egress: []api.EgressRule{
				{
					ToPorts: []api.PortRule{{
						Ports: []api.PortProtocol{
							{Port: "3000", Protocol: api.ProtoAny},
						},
					}},
				},
			},
		},
	}

	l7rules := api.L7Rules{
		HTTP: []api.PortRuleHTTP{{Path: "/", Method: "GET"}},
	}
	l7map := L7DataMap{
		WildcardEndpointSelector: l7rules,
	}

	expected := NewL4Policy()
	expected.Ingress["80/TCP"] = L4Filter{
		Port: 80, Protocol: api.ProtoTCP, U8Proto: 6, FromEndpoints: nil,
		L7Parser: "http", L7RulesPerEp: l7map, Ingress: true,
		DerivedFromRules: labels.LabelArrayList{nil},
	}
	expected.Ingress["8080/TCP"] = L4Filter{
		Port: 8080, Protocol: api.ProtoTCP, U8Proto: 6, FromEndpoints: nil,
		L7Parser: "http", L7RulesPerEp: l7map, Ingress: true,
		DerivedFromRules: labels.LabelArrayList{nil},
	}

	expected.Egress["3000/TCP"] = L4Filter{
		Port: 3000, Protocol: api.ProtoTCP, U8Proto: 6, Ingress: false,
		L7RulesPerEp:     L7DataMap{},
		DerivedFromRules: labels.LabelArrayList{nil},
	}
	expected.Egress["3000/UDP"] = L4Filter{
		Port: 3000, Protocol: api.ProtoUDP, U8Proto: 17, Ingress: false,
		L7RulesPerEp:     L7DataMap{},
		DerivedFromRules: labels.LabelArrayList{nil},
	}

	state := traceState{}
	res, err := rule1.resolveL4Policy(toBar, &state, NewL4Policy())
	c.Assert(err, IsNil)
	c.Assert(res, Not(IsNil))
	c.Assert(*res, comparator.DeepEquals, *expected)
	c.Assert(state.selectedRules, Equals, 1)
	c.Assert(state.matchedRules, Equals, 0)

	// Foo isn't selected in the rule1's policy.
	state = traceState{}
	res, err = rule1.resolveL4Policy(toFoo, &state, NewL4Policy())
	c.Assert(res, IsNil)
	c.Assert(state.selectedRules, Equals, 0)
	c.Assert(state.matchedRules, Equals, 0)

	// This rule actually overlaps with the existing ingress "http" rule,
	// so we'd expect it to merge.
	rule2 := &rule{
		Rule: api.Rule{
			EndpointSelector: api.NewESFromLabels(labels.ParseSelectLabel("bar")),
			Ingress: []api.IngressRule{
				{
					ToPorts: []api.PortRule{{
						Ports: []api.PortProtocol{
							{Port: "80", Protocol: api.ProtoTCP},
						},
					}},
				},
				{
					ToPorts: []api.PortRule{{
						Ports: []api.PortProtocol{
							{Port: "80", Protocol: api.ProtoTCP},
						},
						Rules: &api.L7Rules{
							HTTP: []api.PortRuleHTTP{
								{Method: "GET", Path: "/"},
							},
						},
					}},
				},
			},
			Egress: []api.EgressRule{
				{
					ToPorts: []api.PortRule{{
						Ports: []api.PortProtocol{
							{Port: "3000", Protocol: api.ProtoAny},
						},
					}},
				},
			},
		},
	}

	expected = NewL4Policy()
	expected.Ingress["80/TCP"] = L4Filter{
		Port: 80, Protocol: api.ProtoTCP, U8Proto: 6, FromEndpoints: nil,
		L7Parser: "http", L7RulesPerEp: l7map, Ingress: true,
		DerivedFromRules: labels.LabelArrayList{nil, nil},
	}
	expected.Egress["3000/TCP"] = L4Filter{
		Port: 3000, Protocol: api.ProtoTCP, U8Proto: 6, Ingress: false,
		L7RulesPerEp:     L7DataMap{},
		DerivedFromRules: labels.LabelArrayList{nil},
	}
	expected.Egress["3000/UDP"] = L4Filter{
		Port: 3000, Protocol: api.ProtoUDP, U8Proto: 17, Ingress: false,
		L7RulesPerEp:     L7DataMap{},
		DerivedFromRules: labels.LabelArrayList{nil},
	}

	state = traceState{}
	res, err = rule2.resolveL4Policy(toBar, &state, NewL4Policy())
	c.Assert(err, IsNil)
	c.Assert(res, Not(IsNil))
	c.Assert(len(res.Ingress), Equals, 1)
	c.Assert(*res, comparator.DeepEquals, *expected)
	c.Assert(state.selectedRules, Equals, 1)
	c.Assert(state.matchedRules, Equals, 0)

	state = traceState{}
	res, err = rule2.resolveL4Policy(toFoo, &state, NewL4Policy())
	c.Assert(res, IsNil)
	c.Assert(state.selectedRules, Equals, 0)
	c.Assert(state.matchedRules, Equals, 0)
}

func (ds *PolicyTestSuite) TestMergeL4Policy(c *C) {
	toBar := &SearchContext{To: labels.ParseSelectLabelArray("bar")}
	//toFoo := &SearchContext{To: labels.ParseSelectLabelArray("foo")}

	fooSelector := api.NewESFromLabels(labels.ParseSelectLabel("foo"))
	bazSelector := api.NewESFromLabels(labels.ParseSelectLabel("baz"))
	rule1 := &rule{
		Rule: api.Rule{
			EndpointSelector: api.NewESFromLabels(labels.ParseSelectLabel("bar")),
			Ingress: []api.IngressRule{
				{
					FromEndpoints: []api.EndpointSelector{fooSelector},
					ToPorts: []api.PortRule{{
						Ports: []api.PortProtocol{
							{Port: "80", Protocol: api.ProtoTCP},
						},
					}},
				},
				{
					FromEndpoints: []api.EndpointSelector{bazSelector},
					ToPorts: []api.PortRule{{
						Ports: []api.PortProtocol{
							{Port: "80", Protocol: api.ProtoTCP},
						},
					}},
				},
			},
		},
	}

	mergedES := []api.EndpointSelector{fooSelector, bazSelector}
	expected := NewL4Policy()
	expected.Ingress["80/TCP"] = L4Filter{
		Port: 80, Protocol: api.ProtoTCP, U8Proto: 6, FromEndpoints: mergedES,
		L7Parser: "", L7RulesPerEp: L7DataMap{}, Ingress: true,
		DerivedFromRules: labels.LabelArrayList{nil, nil},
	}

	state := traceState{}
	res, err := rule1.resolveL4Policy(toBar, &state, NewL4Policy())
	c.Assert(err, IsNil)
	c.Assert(res, Not(IsNil))
	c.Assert(*res, comparator.DeepEquals, *expected)
	c.Assert(state.selectedRules, Equals, 1)
	c.Assert(state.matchedRules, Equals, 0)
}

func (ds *PolicyTestSuite) TestMergeL7Policy(c *C) {
	toBar := &SearchContext{To: labels.ParseSelectLabelArray("bar")}
	toFoo := &SearchContext{To: labels.ParseSelectLabelArray("foo")}

	fooSelector := []api.EndpointSelector{
		api.NewESFromLabels(labels.ParseSelectLabel("foo")),
	}
	rule1 := &rule{
		Rule: api.Rule{
			EndpointSelector: api.NewESFromLabels(labels.ParseSelectLabel("bar")),
			Ingress: []api.IngressRule{
				{
					ToPorts: []api.PortRule{{
						Ports: []api.PortProtocol{
							{Port: "80", Protocol: api.ProtoTCP},
						},
					}},
				},
				{
					ToPorts: []api.PortRule{{
						Ports: []api.PortProtocol{
							{Port: "80", Protocol: api.ProtoTCP},
						},
						Rules: &api.L7Rules{
							HTTP: []api.PortRuleHTTP{
								{Method: "GET", Path: "/"},
							},
						},
					}},
				},
				{
					FromEndpoints: fooSelector,
					ToPorts: []api.PortRule{{
						Ports: []api.PortProtocol{
							{Port: "80", Protocol: api.ProtoTCP},
						},
						Rules: &api.L7Rules{
							HTTP: []api.PortRuleHTTP{
								{Method: "GET", Path: "/"},
							},
						},
					}},
				},
			},
		},
	}

	l7rules := api.L7Rules{
		HTTP: []api.PortRuleHTTP{{Path: "/", Method: "GET"}},
	}
	l7map := L7DataMap{
		WildcardEndpointSelector: l7rules,
		fooSelector[0]:           l7rules,
	}

	expected := NewL4Policy()
	expected.Ingress["80/TCP"] = L4Filter{
		Port: 80, Protocol: api.ProtoTCP, U8Proto: 6, FromEndpoints: nil,
		L7Parser: "http", L7RulesPerEp: l7map, Ingress: true,
		DerivedFromRules: labels.LabelArrayList{nil, nil, nil},
	}

	state := traceState{}
	res, err := rule1.resolveL4Policy(toBar, &state, NewL4Policy())
	c.Assert(err, IsNil)
	c.Assert(res, Not(IsNil))
	c.Assert(*res, comparator.DeepEquals, *expected)
	c.Assert(state.selectedRules, Equals, 1)
	c.Assert(state.matchedRules, Equals, 0)

	state = traceState{}
	res, err = rule1.resolveL4Policy(toFoo, &state, NewL4Policy())
	c.Assert(res, IsNil)
	c.Assert(state.selectedRules, Equals, 0)
	c.Assert(state.matchedRules, Equals, 0)

	rule2 := &rule{
		Rule: api.Rule{
			EndpointSelector: api.NewESFromLabels(labels.ParseSelectLabel("bar")),
			Ingress: []api.IngressRule{
				{
					ToPorts: []api.PortRule{{
						Ports: []api.PortProtocol{
							{Port: "80", Protocol: api.ProtoTCP},
						},
					}},
				},
				{
					ToPorts: []api.PortRule{{
						Ports: []api.PortProtocol{
							{Port: "80", Protocol: api.ProtoTCP},
						},
						Rules: &api.L7Rules{
							Kafka: []api.PortRuleKafka{
								{Topic: "foo"},
							},
						},
					}},
				},
				{
					FromEndpoints: fooSelector,
					ToPorts: []api.PortRule{{
						Ports: []api.PortProtocol{
							{Port: "80", Protocol: api.ProtoTCP},
						},
						Rules: &api.L7Rules{
							Kafka: []api.PortRuleKafka{
								{Topic: "foo"},
							},
						},
					}},
				},
			},
		},
	}

	l7rules = api.L7Rules{
		Kafka: []api.PortRuleKafka{{Topic: "foo"}},
	}
	l7map = L7DataMap{
		WildcardEndpointSelector: l7rules,
		fooSelector[0]:           l7rules,
	}

	expected = NewL4Policy()
	expected.Ingress["80/TCP"] = L4Filter{
		Port: 80, Protocol: api.ProtoTCP, U8Proto: 6, FromEndpoints: nil,
		L7Parser: "kafka", L7RulesPerEp: l7map, Ingress: true,
		DerivedFromRules: labels.LabelArrayList{nil, nil, nil},
	}

	state = traceState{}
	res, err = rule2.resolveL4Policy(toBar, &state, NewL4Policy())
	c.Assert(err, IsNil)
	c.Assert(res, Not(IsNil))
	c.Assert(*res, comparator.DeepEquals, *expected)
	c.Assert(state.selectedRules, Equals, 1)
	c.Assert(state.matchedRules, Equals, 0)

	state = traceState{}
	res, err = rule2.resolveL4Policy(toFoo, &state, NewL4Policy())
	c.Assert(res, IsNil)
	c.Assert(state.selectedRules, Equals, 0)
	c.Assert(state.matchedRules, Equals, 0)

	// Resolve rule1's policy, then try to add rule2.
	res, err = rule1.resolveL4Policy(toBar, &state, NewL4Policy())
	c.Assert(err, IsNil)
	c.Assert(res, Not(IsNil))

	state = traceState{}
	res, err = rule2.resolveL4Policy(toBar, &state, res)
	c.Assert(err, Not(IsNil))
	c.Assert(err.Error(), Equals, "Cannot merge conflicting L7 parsers (kafka/http)")

	// Similar to 'rule2', but with different topics for the l3-dependent
	// rule and the l4-only rule.
	rule3 := &rule{
		Rule: api.Rule{
			EndpointSelector: api.NewESFromLabels(labels.ParseSelectLabel("bar")),
			Ingress: []api.IngressRule{
				{
					FromEndpoints: fooSelector,
					ToPorts: []api.PortRule{{
						Ports: []api.PortProtocol{
							{Port: "80", Protocol: api.ProtoTCP},
						},
						Rules: &api.L7Rules{
							Kafka: []api.PortRuleKafka{
								{Topic: "foo"},
							},
						},
					}},
				},
				{
					ToPorts: []api.PortRule{{
						Ports: []api.PortProtocol{
							{Port: "80", Protocol: api.ProtoTCP},
						},
						Rules: &api.L7Rules{
							Kafka: []api.PortRuleKafka{
								{Topic: "bar"},
							},
						},
					}},
				},
			},
		},
	}

	fooRules := api.L7Rules{
		Kafka: []api.PortRuleKafka{{Topic: "foo"}},
	}
	barRules := api.L7Rules{
		Kafka: []api.PortRuleKafka{{Topic: "bar"}},
	}

	// The l3-dependent l7 rules are not merged together.
	l7map = L7DataMap{
		fooSelector[0]:           fooRules,
		WildcardEndpointSelector: barRules,
	}
	expected = NewL4Policy()
	expected.Ingress["80/TCP"] = L4Filter{
		Port: 80, Protocol: api.ProtoTCP, U8Proto: 6, FromEndpoints: nil,
		L7Parser: "kafka", L7RulesPerEp: l7map, Ingress: true,
		DerivedFromRules: labels.LabelArrayList{nil, nil},
	}

	state = traceState{}
	res, err = rule3.resolveL4Policy(toBar, &state, NewL4Policy())
	c.Assert(err, IsNil)
	c.Assert(res, Not(IsNil))
	c.Assert(*res, comparator.DeepEquals, *expected)
	c.Assert(state.selectedRules, Equals, 1)
	c.Assert(state.matchedRules, Equals, 0)
}

func (ds *PolicyTestSuite) TestL3Policy(c *C) {
	apiRule1 := api.Rule{
		EndpointSelector: api.NewESFromLabels(labels.ParseSelectLabel("bar")),

		Ingress: []api.IngressRule{
			{
				FromCIDR: []api.CIDR{
					"10.0.1.0/24",
					"192.168.2.0",
					"10.0.3.1",
					"2001:db8::1/48",
					"2001:db9::",
				},
			},
		},
		Egress: []api.EgressRule{
			{
				ToCIDR: []api.CIDR{
					"10.1.0.0/16",
					"2001:dbf::/64",
				},
				ToCIDRSet: []api.CIDRRule{{Cidr: api.CIDR("10.0.0.0/8"), ExceptCIDRs: []api.CIDR{"10.96.0.0/12"}}},
			},
		},
	}

	err := apiRule1.Sanitize()
	c.Assert(err, IsNil)

	rule1 := &rule{Rule: apiRule1}
	err = rule1.sanitize()
	c.Assert(err, IsNil)

	expected := NewCIDRPolicy()
	expected.Ingress.Map["10.0.1.0/24"] = &CIDRPolicyMapRule{Prefix: net.IPNet{IP: []byte{10, 0, 1, 0}, Mask: []byte{255, 255, 255, 0}}, DerivedFromRules: labels.LabelArrayList{nil}}
	expected.Ingress.Map["192.168.2.0/24"] = &CIDRPolicyMapRule{Prefix: net.IPNet{IP: []byte{192, 168, 2, 0}, Mask: []byte{255, 255, 255, 0}}, DerivedFromRules: labels.LabelArrayList{nil}}
	expected.Ingress.Map["10.0.3.1/32"] = &CIDRPolicyMapRule{Prefix: net.IPNet{IP: []byte{10, 0, 3, 1}, Mask: []byte{255, 255, 255, 255}}, DerivedFromRules: labels.LabelArrayList{nil}}
	expected.Ingress.IPv4Count = 3
	expected.Ingress.Map["2001:db8::/48"] = &CIDRPolicyMapRule{Prefix: net.IPNet{IP: []byte{0x20, 1, 0xd, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}, Mask: []byte{255, 255, 255, 255, 255, 255, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}}, DerivedFromRules: labels.LabelArrayList{nil}}
	expected.Ingress.Map["2001:db9::/128"] = &CIDRPolicyMapRule{Prefix: net.IPNet{IP: []byte{0x20, 1, 0xd, 0xb9, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}, Mask: []byte{255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255}}, DerivedFromRules: labels.LabelArrayList{nil}}
	expected.Ingress.IPv6Count = 2
	expected.Egress.Map["10.1.0.0/16"] = &CIDRPolicyMapRule{Prefix: net.IPNet{IP: []byte{10, 1, 0, 0}, Mask: []byte{255, 255, 0, 0}}, DerivedFromRules: labels.LabelArrayList{nil}}
	expected.Egress.Map["10.128.0.0/9"] = &CIDRPolicyMapRule{Prefix: net.IPNet{IP: []byte{10, 128, 0, 0}, Mask: []byte{255, 128, 0, 0}}, DerivedFromRules: labels.LabelArrayList{nil}}
	expected.Egress.Map["10.0.0.0/10"] = &CIDRPolicyMapRule{Prefix: net.IPNet{IP: []byte{10, 0, 0, 0}, Mask: []byte{255, 192, 0, 0}}, DerivedFromRules: labels.LabelArrayList{nil}}
	expected.Egress.Map["10.64.0.0/11"] = &CIDRPolicyMapRule{Prefix: net.IPNet{IP: []byte{10, 64, 0, 0}, Mask: []byte{255, 224, 0, 0}}, DerivedFromRules: labels.LabelArrayList{nil}}
	expected.Egress.Map["10.112.0.0/12"] = &CIDRPolicyMapRule{Prefix: net.IPNet{IP: []byte{10, 112, 0, 0}, Mask: []byte{255, 240, 0, 0}}, DerivedFromRules: labels.LabelArrayList{nil}}
	expected.Egress.IPv4Count = 5
	expected.Egress.Map["2001:dbf::/64"] = &CIDRPolicyMapRule{Prefix: net.IPNet{IP: []byte{0x20, 1, 0xd, 0xbf, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}, Mask: []byte{255, 255, 255, 255, 255, 255, 255, 255, 0, 0, 0, 0, 0, 0, 0, 0}}, DerivedFromRules: labels.LabelArrayList{nil}}
	expected.Egress.IPv6Count = 1

	toBar := &SearchContext{To: labels.ParseSelectLabelArray("bar")}
	state := traceState{}
	res := rule1.resolveCIDRPolicy(toBar, &state, NewCIDRPolicy())
	c.Assert(res, Not(IsNil))
	c.Assert(*res, comparator.DeepEquals, *expected)
	c.Assert(state.selectedRules, Equals, 1)
	c.Assert(state.matchedRules, Equals, 0)

	// Must be parsable, make sure Validate fails when not.
	err = api.Rule{
		Ingress: []api.IngressRule{{
			FromCIDR: []api.CIDR{"10.0.1..0/24"},
		}},
	}.Sanitize()
	c.Assert(err, Not(IsNil))

	// Test CIDRRule with no provided CIDR or ExceptionCIDR.
	// Should fail as CIDR is required.
	err = api.Rule{
		Ingress: []api.IngressRule{{
			FromCIDRSet: []api.CIDRRule{{Cidr: "", ExceptCIDRs: nil}},
		}},
	}.Sanitize()
	c.Assert(err, Not(IsNil))

	// Test CIDRRule with only CIDR provided; should not fail, as ExceptionCIDR
	// is optional.
	err = api.Rule{
		Ingress: []api.IngressRule{{
			FromCIDRSet: []api.CIDRRule{{Cidr: "10.0.1.0/24", ExceptCIDRs: nil}},
		}},
	}.Sanitize()
	c.Assert(err, IsNil)

	// Cannot provide just an IP to a CIDRRule; Cidr must be of format
	// <IP>/<prefix>.
	err = api.Rule{
		Ingress: []api.IngressRule{{
			FromCIDRSet: []api.CIDRRule{{Cidr: "10.0.1.32", ExceptCIDRs: nil}},
		}},
	}.Sanitize()
	c.Assert(err, Not(IsNil))

	// Cannot exclude a range that is not part of the CIDR.
	err = api.Rule{
		Ingress: []api.IngressRule{{
			FromCIDRSet: []api.CIDRRule{{Cidr: "10.0.0.0/10", ExceptCIDRs: []api.CIDR{"10.64.0.0/11"}}},
		}},
	}.Sanitize()
	c.Assert(err, Not(IsNil))

	// Must have a mask, make sure Validate fails when not.
	err = api.Rule{
		Ingress: []api.IngressRule{{
			FromCIDR: []api.CIDR{"10.0.1.0/0"},
		}},
	}.Sanitize()
	c.Assert(err, Not(IsNil))

	// Prefix length must be in range for the address, make sure
	// Validate fails if given prefix length is out of range.
	err = api.Rule{
		Ingress: []api.IngressRule{{
			FromCIDR: []api.CIDR{"10.0.1.0/34"},
		}},
	}.Sanitize()
	c.Assert(err, Not(IsNil))
}

// Tests the restrictions of combining certain label-based L3 and L4 policies.
// This ensures that the user is informed of policy combinations that are not
// implemented in the datapath.
func (ds *PolicyTestSuite) TestEgressRuleRestrictions(c *C) {

	fooSelector := []api.EndpointSelector{
		api.NewESFromLabels(labels.ParseSelectLabel("foo")),
	}

	// Cannot combine ToEndpoints and ToCIDR
	apiRule1 := api.Rule{
		EndpointSelector: api.NewESFromLabels(labels.ParseSelectLabel("bar")),
		Egress: []api.EgressRule{
			{
				ToCIDR: []api.CIDR{
					"10.1.0.0/16",
					"2001:dbf::/64",
				},
				ToEndpoints: fooSelector,
			},
		},
	}

	err := apiRule1.Sanitize()
	c.Assert(err, Not(IsNil))

	// Cannot combine ToEndpoints and ToPorts
	apiRule1 = api.Rule{
		EndpointSelector: api.NewESFromLabels(labels.ParseSelectLabel("bar")),
		Egress: []api.EgressRule{
			{
				ToEndpoints: fooSelector,
				ToPorts: []api.PortRule{{
					Ports: []api.PortProtocol{
						{Port: "80", Protocol: api.ProtoTCP},
					},
					Rules: &api.L7Rules{
						Kafka: []api.PortRuleKafka{
							{Topic: "foo"},
						},
					},
				}},
			},
		},
	}

	err = apiRule1.Sanitize()
	c.Assert(err, Not(IsNil))

	// Cannot combine ToCIDR and ToPorts
	apiRule1 = api.Rule{
		EndpointSelector: api.NewESFromLabels(labels.ParseSelectLabel("bar")),
		Egress: []api.EgressRule{
			{
				ToCIDR: []api.CIDR{
					"10.1.0.0/16",
					"2001:dbf::/64",
				},
				ToPorts: []api.PortRule{{
					Ports: []api.PortProtocol{
						{Port: "80", Protocol: api.ProtoTCP},
					},
					Rules: &api.L7Rules{
						Kafka: []api.PortRuleKafka{
							{Topic: "foo"},
						},
					},
				}},
			},
		},
	}

	err = apiRule1.Sanitize()
	c.Assert(err, Not(IsNil))
}

func (ds *PolicyTestSuite) TestRuleCanReachFromEntity(c *C) {
	fromWorld := &SearchContext{
		From: labels.ParseSelectLabelArray("reserved:world"),
		To:   labels.ParseSelectLabelArray("bar"),
	}

	notFromWorld := &SearchContext{
		From: labels.ParseSelectLabelArray("foo"),
		To:   labels.ParseSelectLabelArray("bar"),
	}

	rule1 := rule{
		Rule: api.Rule{
			EndpointSelector: api.NewESFromLabels(labels.ParseSelectLabel("bar")),
			Ingress: []api.IngressRule{
				{
					FromEntities: []api.Entity{api.EntityWorld},
				},
			},
		},
	}

	c.Assert(rule1.sanitize(), IsNil)

	state := traceState{}
	c.Assert(rule1.canReachIngress(fromWorld, &state), Equals, api.Allowed)
	c.Assert(state.selectedRules, Equals, 1)
	c.Assert(state.matchedRules, Equals, 1)
	state = traceState{}
	c.Assert(rule1.canReachIngress(notFromWorld, &traceState{}), Equals, api.Undecided)
	c.Assert(state.selectedRules, Equals, 0)
	c.Assert(state.matchedRules, Equals, 0)
}

func (ds *PolicyTestSuite) TestRuleCanReachEntity(c *C) {
	toWorld := &SearchContext{
		From: labels.ParseSelectLabelArray("bar"),
		To:   labels.ParseSelectLabelArray("reserved:world"),
	}

	notToWorld := &SearchContext{
		From: labels.ParseSelectLabelArray("bar"),
		To:   labels.ParseSelectLabelArray("foo"),
	}

	rule1 := rule{
		Rule: api.Rule{
			EndpointSelector: api.NewESFromLabels(labels.ParseSelectLabel("bar")),
			Egress: []api.EgressRule{
				{
					ToEntities: []api.Entity{api.EntityWorld},
				},
			},
		},
	}

	c.Assert(rule1.sanitize(), IsNil)

	state := traceState{}
	c.Assert(rule1.canReachEgress(toWorld, &state), Equals, api.Allowed)
	c.Assert(state.selectedRules, Equals, 1)
	c.Assert(state.matchedRules, Equals, 1)
	state = traceState{}
	c.Assert(rule1.canReachEgress(notToWorld, &traceState{}), Equals, api.Undecided)
	c.Assert(state.selectedRules, Equals, 0)
	c.Assert(state.matchedRules, Equals, 0)
}

func (ds *PolicyTestSuite) TestPolicyEntityValidationEgress(c *C) {
	r := rule{
		Rule: api.Rule{
			EndpointSelector: api.NewESFromLabels(labels.ParseSelectLabel("bar")),
			Egress: []api.EgressRule{
				{
					ToEntities: []api.Entity{api.EntityWorld},
				},
			},
		},
	}
	c.Assert(r.sanitize(), IsNil)
	c.Assert(len(r.toEntities), Equals, 1)

	r.Egress[0].ToEntities = []api.Entity{api.EntityHost}
	c.Assert(r.sanitize(), IsNil)
	c.Assert(len(r.toEntities), Equals, 1)

	r.Egress[0].ToEntities = []api.Entity{"trololo"}
	c.Assert(r.sanitize(), NotNil)
}

func (ds *PolicyTestSuite) TestPolicyEntityValidationIngress(c *C) {
	r := rule{
		Rule: api.Rule{
			EndpointSelector: api.NewESFromLabels(labels.ParseSelectLabel("bar")),
			Ingress: []api.IngressRule{
				{
					FromEntities: []api.Entity{api.EntityWorld},
				},
			},
		},
	}
	c.Assert(r.sanitize(), IsNil)
	c.Assert(len(r.fromEntities), Equals, 1)

	r.Ingress[0].FromEntities = []api.Entity{api.EntityHost}
	c.Assert(r.sanitize(), IsNil)
	c.Assert(len(r.fromEntities), Equals, 1)

	r.Ingress[0].FromEntities = []api.Entity{"trololo"}
	c.Assert(r.sanitize(), NotNil)
}

func (ds *PolicyTestSuite) TestPolicyEntityValidationEntitySelectorsFill(c *C) {
	r := rule{
		Rule: api.Rule{
			EndpointSelector: api.NewESFromLabels(labels.ParseSelectLabel("bar")),
			Ingress: []api.IngressRule{
				{
					FromEntities: []api.Entity{api.EntityWorld, api.EntityHost},
				},
			},
			Egress: []api.EgressRule{
				{
					ToEntities: []api.Entity{api.EntityWorld, api.EntityHost},
				},
			},
		},
	}
	c.Assert(r.sanitize(), IsNil)
	c.Assert(len(r.fromEntities), Equals, 2)
	c.Assert(len(r.toEntities), Equals, 2)
}

func (ds *PolicyTestSuite) TestL3RuleLabels(c *C) {
	ruleLabels := map[string]labels.LabelArray{
		"rule0": labels.ParseLabelArray("name=apiRule0"),
		"rule1": labels.ParseLabelArray("name=apiRule1"),
		"rule2": labels.ParseLabelArray("name=apiRule2"),
	}

	rules := map[string]api.Rule{
		"rule0": {
			EndpointSelector: api.NewESFromLabels(labels.ParseSelectLabel("bar")),
			Labels:           ruleLabels["rule0"],
			Ingress:          []api.IngressRule{},
			Egress:           []api.EgressRule{},
		},
		"rule1": {
			EndpointSelector: api.NewESFromLabels(labels.ParseSelectLabel("bar")),
			Labels:           ruleLabels["rule1"],
			Ingress: []api.IngressRule{
				{
					FromCIDR: []api.CIDR{"10.0.1.0/32"},
				},
			},
			Egress: []api.EgressRule{
				{
					ToCIDR: []api.CIDR{"10.1.0.0/32"},
				},
			},
		},
		"rule2": {
			EndpointSelector: api.NewESFromLabels(labels.ParseSelectLabel("bar")),
			Labels:           ruleLabels["rule2"],
			Ingress: []api.IngressRule{
				{
					FromCIDR: []api.CIDR{"10.0.2.0/32"},
				},
			},
			Egress: []api.EgressRule{
				{
					ToCIDR: []api.CIDR{"10.2.0.0/32"},
				},
			},
		},
	}

	testCases := []struct {
		description           string                           // the description to print in asserts
		rulesToApply          []string                         // the rules from the rules map to resolve, in order
		expectedIngressLabels map[string]labels.LabelArrayList // the slice of LabelArray we should see, per CIDR prefix
		expectedEgressLabels  map[string]labels.LabelArrayList // the slice of LabelArray we should see, per CIDR prefix

	}{
		{
			description:           "Empty rule that matches. Should not apply labels",
			rulesToApply:          []string{"rule0"},
			expectedIngressLabels: nil,
			expectedEgressLabels:  nil,
		},
		{
			description:           "A rule that matches. Should apply labels",
			rulesToApply:          []string{"rule1"},
			expectedIngressLabels: map[string]labels.LabelArrayList{"10.0.1.0/32": {ruleLabels["rule1"]}},
			expectedEgressLabels:  map[string]labels.LabelArrayList{"10.1.0.0/32": {ruleLabels["rule1"]}},
		}, {
			description:  "Multiple matching rules. Should apply labels from all that have rule entries",
			rulesToApply: []string{"rule0", "rule1", "rule2"},
			expectedIngressLabels: map[string]labels.LabelArrayList{
				"10.0.1.0/32": {ruleLabels["rule1"]},
				"10.0.2.0/32": {ruleLabels["rule2"]}},
			expectedEgressLabels: map[string]labels.LabelArrayList{
				"10.1.0.0/32": {ruleLabels["rule1"]},
				"10.2.0.0/32": {ruleLabels["rule2"]}},
		}}

	// endpoint selector for all tests
	toBar := &SearchContext{To: labels.ParseSelectLabelArray("bar")}

	for _, test := range testCases {
		finalPolicy := NewCIDRPolicy()
		for _, r := range test.rulesToApply {
			apiRule := rules[r]
			err := apiRule.Sanitize()
			c.Assert(err, IsNil, Commentf("Cannot sanitize api.Rule: %+v", apiRule))

			rule := &rule{Rule: apiRule}
			err = rule.sanitize()
			c.Assert(err, IsNil, Commentf("Cannot sanitize Rule: %+v", rule))

			rule.resolveCIDRPolicy(toBar, &traceState{}, finalPolicy)
		}

		c.Assert(len(finalPolicy.Ingress.Map), Equals, len(test.expectedIngressLabels), Commentf(test.description))
		for cidrKey := range test.expectedIngressLabels {
			out := finalPolicy.Ingress.Map[cidrKey]
			c.Assert(out, Not(IsNil), Commentf(test.description))
			c.Assert(out.DerivedFromRules, comparator.DeepEquals, test.expectedIngressLabels[cidrKey], Commentf(test.description))
		}

		c.Assert(len(finalPolicy.Egress.Map), Equals, len(test.expectedEgressLabels), Commentf(test.description))
		for cidrKey := range test.expectedEgressLabels {
			out := finalPolicy.Egress.Map[cidrKey]
			c.Assert(out, Not(IsNil), Commentf(test.description))
			c.Assert(out.DerivedFromRules, comparator.DeepEquals, test.expectedEgressLabels[cidrKey], Commentf(test.description))
		}
	}
}

func (ds *PolicyTestSuite) TestL4RuleLabels(c *C) {
	ruleLabels := map[string]labels.LabelArray{
		"rule0": labels.ParseLabelArray("name=apiRule0"),
		"rule1": labels.ParseLabelArray("name=apiRule1"),
		"rule2": labels.ParseLabelArray("name=apiRule2"),
	}

	rules := map[string]api.Rule{
		"rule0": {
			EndpointSelector: api.NewESFromLabels(labels.ParseSelectLabel("bar")),
			Labels:           ruleLabels["rule0"],
			Ingress:          []api.IngressRule{},
			Egress:           []api.EgressRule{},
		},

		"rule1": {
			EndpointSelector: api.NewESFromLabels(labels.ParseSelectLabel("bar")),
			Labels:           ruleLabels["rule1"],
			Ingress: []api.IngressRule{
				{
					ToPorts: []api.PortRule{{
						Ports: []api.PortProtocol{{Port: "1010", Protocol: api.ProtoTCP}},
					}},
				},
			},
			Egress: []api.EgressRule{
				{
					ToPorts: []api.PortRule{{
						Ports: []api.PortProtocol{{Port: "1100", Protocol: api.ProtoTCP}},
					}},
				},
			},
		},
		"rule2": {
			EndpointSelector: api.NewESFromLabels(labels.ParseSelectLabel("bar")),
			Labels:           ruleLabels["rule2"],
			Ingress: []api.IngressRule{
				{
					ToPorts: []api.PortRule{{
						Ports: []api.PortProtocol{{Port: "1020", Protocol: api.ProtoTCP}},
					}},
				},
			},
			Egress: []api.EgressRule{
				{
					ToPorts: []api.PortRule{{
						Ports: []api.PortProtocol{{Port: "1200", Protocol: api.ProtoTCP}},
					}},
				},
			},
		},
	}

	testCases := []struct {
		description           string                           // the description to print in asserts
		rulesToApply          []string                         // the rules from the rules map to resolve, in order
		expectedIngressLabels map[string]labels.LabelArrayList // the slice of LabelArray we should see, in order
		expectedEgressLabels  map[string]labels.LabelArrayList // the slice of LabelArray we should see, in order

	}{
		{
			description:           "Empty rule that matches. Should not apply labels",
			rulesToApply:          []string{"rule0"},
			expectedIngressLabels: map[string]labels.LabelArrayList{},
			expectedEgressLabels:  map[string]labels.LabelArrayList{},
		},
		{
			description:           "A rule that matches. Should apply labels",
			rulesToApply:          []string{"rule1"},
			expectedIngressLabels: map[string]labels.LabelArrayList{"1010/TCP": {ruleLabels["rule1"]}},
			expectedEgressLabels:  map[string]labels.LabelArrayList{"1100/TCP": {ruleLabels["rule1"]}},
		}, {
			description:  "Multiple matching rules. Should apply labels from all that have rule entries",
			rulesToApply: []string{"rule0", "rule1", "rule2"},
			expectedIngressLabels: map[string]labels.LabelArrayList{
				"1010/TCP": {ruleLabels["rule1"]},
				"1020/TCP": {ruleLabels["rule2"]}},
			expectedEgressLabels: map[string]labels.LabelArrayList{
				"1100/TCP": {ruleLabels["rule1"]},
				"1200/TCP": {ruleLabels["rule2"]}},
		}}

	// endpoint selector for all tests
	toBar := &SearchContext{To: labels.ParseSelectLabelArray("bar")}

	for _, test := range testCases {
		finalPolicy := NewL4Policy()
		for _, r := range test.rulesToApply {
			apiRule := rules[r]
			err := apiRule.Sanitize()
			c.Assert(err, IsNil, Commentf("Cannot sanitize api.Rule: %+v", apiRule))

			rule := &rule{Rule: apiRule}
			err = rule.sanitize()
			c.Assert(err, IsNil, Commentf("Cannot sanitize Rule: %+v", rule))

			rule.resolveL4Policy(toBar, &traceState{}, finalPolicy)
		}

		c.Assert(len(finalPolicy.Ingress), Equals, len(test.expectedIngressLabels), Commentf(test.description))
		for portProto := range test.expectedIngressLabels {
			out, found := finalPolicy.Ingress[portProto]
			c.Assert(found, Equals, true, Commentf(test.description))
			c.Assert(out, NotNil, Commentf(test.description))
			c.Assert(out.DerivedFromRules, comparator.DeepEquals, test.expectedIngressLabels[portProto], Commentf(test.description))
		}

		c.Assert(len(finalPolicy.Egress), Equals, len(test.expectedEgressLabels), Commentf(test.description))
		for portProto := range test.expectedEgressLabels {
			out, found := finalPolicy.Egress[portProto]
			c.Assert(found, Equals, true, Commentf(test.description))
			c.Assert(out, Not(IsNil), Commentf(test.description))
			c.Assert(out.DerivedFromRules, comparator.DeepEquals, test.expectedEgressLabels[portProto], Commentf(test.description))
		}

	}
}

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
		api.Rule{
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
	c.Assert(rule1.canReach(fooFoo2ToBar, &state), Equals, api.Allowed)
	c.Assert(state.selectedRules, Equals, 1)
	state = traceState{}
	c.Assert(rule1.canReach(fooToBar, &traceState{}), Equals, api.Undecided)
	c.Assert(state.selectedRules, Equals, 0)

	// selector: bar
	// allow: foo
	// require: baz
	rule2 := rule{
		api.Rule{
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
	c.Assert(rule2.canReach(fooToBar, &state), Equals, api.Denied)
	c.Assert(state.selectedRules, Equals, 1)

	state = traceState{}
	c.Assert(rule2.canReach(bazToBar, &state), Equals, api.Undecided)
	c.Assert(state.selectedRules, Equals, 1)

	state = traceState{}
	c.Assert(rule2.canReach(fooBazToBar, &state), Equals, api.Allowed)
	c.Assert(state.selectedRules, Equals, 1)
}

func (ds *PolicyTestSuite) TestL4Policy(c *C) {
	toBar := &SearchContext{To: labels.ParseSelectLabelArray("bar")}
	toFoo := &SearchContext{To: labels.ParseSelectLabelArray("foo")}

	rule1 := &rule{
		api.Rule{
			EndpointSelector: api.NewESFromLabels(labels.ParseSelectLabel("bar")),
			Ingress: []api.IngressRule{
				{
					ToPorts: []api.PortRule{{
						Ports: []api.PortProtocol{
							{Port: "80", Protocol: "tcp"},
							{Port: "8080", Protocol: "tcp"},
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
							{Port: "3000"},
						},
					}},
				},
			},
		},
	}

	l7rules := []AuxRule{
		{Expr: "PathRegexp(\"/\") && MethodRegexp(\"GET\")"},
	}

	expected := NewL4Policy()
	expected.Ingress["80/tcp"] = L4Filter{Port: 80, Protocol: "tcp", L7Parser: "http", L7Rules: l7rules, Ingress: true}
	expected.Ingress["8080/tcp"] = L4Filter{Port: 8080, Protocol: "tcp", L7Parser: "http", L7Rules: l7rules, Ingress: true}
	expected.Egress["3000/tcp"] = L4Filter{Port: 3000, Protocol: "tcp", Ingress: false}
	expected.Egress["3000/udp"] = L4Filter{Port: 3000, Protocol: "udp", Ingress: false}

	state := traceState{}
	res := rule1.resolveL4Policy(toBar, &state, NewL4Policy())
	c.Assert(res, Not(IsNil))
	c.Assert(*res, DeepEquals, *expected)
	c.Assert(state.selectedRules, Equals, 1)

	state = traceState{}
	c.Assert(rule1.resolveL4Policy(toFoo, &state, NewL4Policy()), IsNil)
	c.Assert(state.selectedRules, Equals, 0)
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
			},
		},
	}

	err := apiRule1.Validate()
	c.Assert(err, IsNil)

	rule1 := &rule{apiRule1}
	err = rule1.validate()
	c.Assert(err, IsNil)

	expected := NewL3Policy()
	expected.Ingress.Map["10.0.1.0/24"] = net.IPNet{IP: []byte{10, 0, 1, 0}, Mask: []byte{255, 255, 255, 0}}
	expected.Ingress.Map["192.168.2.0/24"] = net.IPNet{IP: []byte{192, 168, 2, 0}, Mask: []byte{255, 255, 255, 0}}
	expected.Ingress.Map["10.0.3.1/32"] = net.IPNet{IP: []byte{10, 0, 3, 1}, Mask: []byte{255, 255, 255, 255}}
	expected.Ingress.IPv4Changed = true
	expected.Ingress.IPv4Count = 3
	expected.Ingress.Map["2001:db8::/48"] = net.IPNet{IP: []byte{0x20, 1, 0xd, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}, Mask: []byte{255, 255, 255, 255, 255, 255, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}}
	expected.Ingress.Map["2001:db9::/128"] = net.IPNet{IP: []byte{0x20, 1, 0xd, 0xb9, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}, Mask: []byte{255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255}}
	expected.Ingress.IPv6Changed = true
	expected.Ingress.IPv6Count = 2
	expected.Egress.Map["10.1.0.0/16"] = net.IPNet{IP: []byte{10, 1, 0, 0}, Mask: []byte{255, 255, 0, 0}}
	expected.Egress.IPv4Changed = true
	expected.Egress.IPv4Count = 1
	expected.Egress.Map["2001:dbf::/64"] = net.IPNet{IP: []byte{0x20, 1, 0xd, 0xbf, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}, Mask: []byte{255, 255, 255, 255, 255, 255, 255, 255, 0, 0, 0, 0, 0, 0, 0, 0}}
	expected.Egress.IPv6Changed = true
	expected.Egress.IPv6Count = 1

	toBar := &SearchContext{To: labels.ParseSelectLabelArray("bar")}
	state := traceState{}
	res := rule1.resolveL3Policy(toBar, &state, NewL3Policy())
	c.Assert(res, Not(IsNil))
	c.Assert(*res, DeepEquals, *expected)
	c.Assert(state.selectedRules, Equals, 1)

	// Must be parsable, make sure Validate fails when not.
	err = api.Rule{
		Ingress: []api.IngressRule{{
			FromCIDR: []api.CIDR{"10.0.1..0/24"},
		}},
	}.Validate()
	c.Assert(err, Not(IsNil))

	// Must have a mask, make sure Validate fails when not.
	err = api.Rule{
		Ingress: []api.IngressRule{{
			FromCIDR: []api.CIDR{"10.0.1.0/0"},
		}},
	}.Validate()
	c.Assert(err, Not(IsNil))

	// Prefix length must be in range for the address, make sure
	// Validate fails if given prefix length is out of range.
	err = api.Rule{
		Ingress: []api.IngressRule{{
			FromCIDR: []api.CIDR{"10.0.1.0/34"},
		}},
	}.Validate()
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
		api.Rule{
			EndpointSelector: api.NewESFromLabels(labels.ParseSelectLabel("bar")),
			Ingress: []api.IngressRule{
				{
					FromEntities: []api.Entity{api.World},
				},
			},
		},
	}

	state := traceState{}
	c.Assert(rule1.canReach(fromWorld, &state), Equals, api.Allowed)
	c.Assert(state.selectedRules, Equals, 1)
	state = traceState{}
	c.Assert(rule1.canReach(notFromWorld, &traceState{}), Equals, api.Undecided)
	c.Assert(state.selectedRules, Equals, 0)
}

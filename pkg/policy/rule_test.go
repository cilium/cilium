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
	"github.com/cilium/cilium/pkg/labels"
	"github.com/cilium/cilium/pkg/policy/api"

	. "gopkg.in/check.v1"
)

func (ds *PolicyTestSuite) TestRuleCanReach(c *C) {
	fooFoo2ToBar := &SearchContext{
		From: labels.ParseLabelArray("foo", "foo2"),
		To:   labels.ParseLabelArray("bar"),
	}
	fooToBar := &SearchContext{
		From: labels.ParseLabelArray("foo"),
		To:   labels.ParseLabelArray("bar"),
	}

	rule1 := rule{
		api.Rule{
			EndpointSelector: api.EndpointSelector{labels.ParseLabel("bar")},
			Ingress: []api.IngressRule{
				{
					FromEndpoints: []api.EndpointSelector{
						api.ParseEndpointSelector("foo", "foo2"),
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
			EndpointSelector: api.EndpointSelector{labels.ParseLabel("bar")},
			Ingress: []api.IngressRule{
				{
					FromEndpoints: []api.EndpointSelector{
						api.ParseEndpointSelector("foo"),
					},
					FromRequires: []api.EndpointSelector{
						api.ParseEndpointSelector("baz"),
					},
				},
			},
		},
	}

	fooBazToBar := &SearchContext{
		From: labels.ParseLabelArray("foo", "baz"),
		To:   labels.ParseLabelArray("bar"),
	}
	bazToBar := &SearchContext{
		From: labels.ParseLabelArray("baz"),
		To:   labels.ParseLabelArray("bar"),
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
	toBar := &SearchContext{To: labels.ParseLabelArray("bar")}
	toFoo := &SearchContext{To: labels.ParseLabelArray("foo")}

	rule1 := &rule{
		api.Rule{
			EndpointSelector: api.EndpointSelector{labels.ParseLabel("bar")},
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
	expected.Ingress["80/tcp"] = L4Filter{Port: 80, Protocol: "tcp", L7Parser: "http", L7Rules: l7rules}
	expected.Ingress["8080/tcp"] = L4Filter{Port: 8080, Protocol: "tcp", L7Parser: "http", L7Rules: l7rules}
	expected.Egress["3000/tcp"] = L4Filter{Port: 3000, Protocol: "tcp"}
	expected.Egress["3000/udp"] = L4Filter{Port: 3000, Protocol: "udp"}

	state := traceState{}
	res := rule1.resolveL4Policy(toBar, &state, NewL4Policy())
	c.Assert(res, Not(IsNil))
	c.Assert(*res, DeepEquals, *expected)
	c.Assert(state.selectedRules, Equals, 1)

	state = traceState{}
	c.Assert(rule1.resolveL4Policy(toFoo, &state, NewL4Policy()), IsNil)
	c.Assert(state.selectedRules, Equals, 0)
}

// Copyright 2017 Authors of Cilium
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
	"sort"

	"github.com/cilium/cilium/api/v1/models"
	"github.com/cilium/cilium/pkg/comparator"
	"github.com/cilium/cilium/pkg/labels"
	"github.com/cilium/cilium/pkg/policy/api"
	"github.com/kr/pretty"

	. "gopkg.in/check.v1"
)

func (s *PolicyTestSuite) testDPortCoverage(c *C, policy L4Policy,
	covers func([]*models.Port) api.Decision) {

	ports := []*models.Port{}
	c.Assert(covers(ports), Equals, api.Denied)

	// Policy should match all of the below ports.
	ports = []*models.Port{
		{
			Port:     8080,
			Protocol: models.PortProtocolTCP,
		},
	}
	c.Assert(covers(ports), Equals, api.Allowed)

	// Adding another port outside the policy will now be denied.
	ports = append(ports, &models.Port{Port: 8080, Protocol: models.PortProtocolUDP})
	c.Assert(covers(ports), Equals, api.Denied)

	// Ports with protocol any should match the TCP policy above.
	ports = []*models.Port{
		{
			Port:     8080,
			Protocol: models.PortProtocolANY,
		},
	}
	c.Assert(covers(ports), Equals, api.Allowed)
}

func (s *PolicyTestSuite) TestCreateL4Filter(c *C) {
	tuple := api.PortProtocol{Port: "80", Protocol: api.ProtoTCP}
	portrule := api.PortRule{
		Ports: []api.PortProtocol{tuple},
		Rules: &api.L7Rules{
			HTTP: []api.PortRuleHTTP{
				{Path: "/public", Method: "GET"},
			},
		},
	}
	selectors := []api.EndpointSelector{
		{},
		api.NewESFromLabels(labels.ParseSelectLabel("bar")),
	}

	for _, selector := range selectors {
		eps := []api.EndpointSelector{selector}
		// Regardless of ingress/egress, we should end up with
		// a single L7 rule whether the selector is wildcarded
		// or if it is based on specific labels.
		filter := CreateL4IngressFilter(eps, portrule, tuple, tuple.Protocol, nil)
		c.Assert(len(filter.L7RulesPerEp), Equals, 1)

		filter = CreateL4EgressFilter(eps, portrule, tuple, tuple.Protocol, nil)
		c.Assert(len(filter.L7RulesPerEp), Equals, 1)
	}
}

type SortablePolicyRules []*models.PolicyRule

func (a SortablePolicyRules) Len() int           { return len(a) }
func (a SortablePolicyRules) Swap(i, j int)      { a[i], a[j] = a[j], a[i] }
func (a SortablePolicyRules) Less(i, j int) bool { return a[i].Rule < a[j].Rule }

func (s *PolicyTestSuite) TestJSONMarshal(c *C) {
	fooSelector := api.NewESFromLabels(labels.ParseSelectLabel("foo"))
	wildcardSelector := api.NewESFromLabels()

	model := &models.L4Policy{}
	c.Assert(pretty.Sprintf("%+ v", model.Egress), comparator.DeepEquals, "[]")
	c.Assert(pretty.Sprintf("%+ v", model.Ingress), comparator.DeepEquals, "[]")

	policy := L4Policy{
		Egress: L4PolicyMap{
			"8080/TCP": {
				Port:     8080,
				Protocol: api.ProtoTCP,
				Ingress:  false,
			},
		},
		Ingress: L4PolicyMap{
			"80/TCP": {
				Port: 80, Protocol: api.ProtoTCP,
				Endpoints: []api.EndpointSelector{fooSelector},
				L7Parser:  "http",
				L7RulesPerEp: L7DataMap{
					fooSelector: api.L7Rules{
						HTTP: []api.PortRuleHTTP{{Path: "/", Method: "GET"}},
					},
				},
				Ingress: true,
			},
			"8080/TCP": {
				Port: 8080, Protocol: api.ProtoTCP,
				Endpoints: []api.EndpointSelector{fooSelector},
				L7Parser:  "http",
				L7RulesPerEp: L7DataMap{
					fooSelector: api.L7Rules{
						HTTP: []api.PortRuleHTTP{
							{Path: "/", Method: "GET"},
							{Path: "/bar", Method: "GET"},
						},
					},
					wildcardSelector: api.L7Rules{
						HTTP: []api.PortRuleHTTP{{Path: "/", Method: "GET"}},
					},
				},
				Ingress: true,
			},
		},
	}

	model = policy.GetModel()
	c.Assert(model, NotNil)

	expectedEgress := []string{`{
  "port": 8080,
  "protocol": "TCP"
}`}
	sort.StringSlice(expectedEgress).Sort()
	sort.Sort(SortablePolicyRules(model.Egress))
	c.Assert(len(expectedEgress), Equals, len(model.Egress))
	for i := range expectedEgress {
		c.Assert(model.Egress[i].Rule, Equals, expectedEgress[i])
	}

	expectedIngress := []string{`{
  "port": 80,
  "protocol": "TCP",
  "l7-rules": [
    {
      "any.foo=": {
        "http": [
          {
            "path": "/",
            "method": "GET"
          }
        ]
      }
    }
  ]
}`,
		`{
  "port": 8080,
  "protocol": "TCP",
  "l7-rules": [
    {
      "\u003cnone\u003e": {
        "http": [
          {
            "path": "/",
            "method": "GET"
          }
        ]
      }
    },
    {
      "any.foo=": {
        "http": [
          {
            "path": "/",
            "method": "GET"
          },
          {
            "path": "/bar",
            "method": "GET"
          }
        ]
      }
    }
  ]
}`}
	sort.StringSlice(expectedIngress).Sort()
	sort.Sort(SortablePolicyRules(model.Ingress))
	c.Assert(len(expectedIngress), Equals, len(model.Ingress))
	for i := range expectedIngress {
		c.Assert(model.Ingress[i].Rule, Equals, expectedIngress[i])
	}
}

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

package k8s

import (
	"encoding/json"
	"fmt"

	"github.com/cilium/cilium/pkg/comparator"
	"github.com/cilium/cilium/pkg/labels"
	"github.com/cilium/cilium/pkg/policy/api"

	. "gopkg.in/check.v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

var (
	apiRule = api.Rule{
		Ingress: []api.IngressRule{
			{
				FromEndpoints: []api.EndpointSelector{
					api.NewESFromLabels(
						labels.ParseSelectLabel("role=frontend"),
					),
					api.NewESFromLabels(
						labels.ParseSelectLabel("reserved:world"),
					),
				},
				ToPorts: []api.PortRule{
					{
						Ports: []api.PortProtocol{{Port: "80", Protocol: "TCP"}},
						Rules: &api.L7Rules{HTTP: []api.PortRuleHTTP{{Path: "/public", Method: "GET"}}},
					},
				},
			},
		},
		Egress: []api.EgressRule{
			{
				ToPorts: []api.PortRule{
					{
						Ports: []api.PortProtocol{{Port: "80", Protocol: "TCP"}},
						Rules: &api.L7Rules{HTTP: []api.PortRuleHTTP{{Path: "/public", Method: "GET"}}},
					},
				},
			}, {
				ToCIDR:    []api.CIDR{"10.0.0.1"},
				ToCIDRSet: []api.CIDRRule{{Cidr: api.CIDR("10.0.0.0/8"), ExceptCIDRs: []api.CIDR{"10.96.0.0/12"}}},
			},
		},
	}

	expectedSpecRule = api.Rule{
		Ingress: []api.IngressRule{
			{
				FromEndpoints: []api.EndpointSelector{
					api.NewESFromLabels(
						labels.ParseSelectLabel("role=frontend"),
						labels.ParseSelectLabel("k8s:"+PodNamespaceLabel+"=default"),
					),
					api.NewESFromLabels(
						labels.ParseSelectLabel("reserved:world"),
					),
				},
				ToPorts: []api.PortRule{
					{
						Ports: []api.PortProtocol{{Port: "80", Protocol: "TCP"}},
						Rules: &api.L7Rules{HTTP: []api.PortRuleHTTP{{Path: "/public", Method: "GET"}}},
					},
				},
			},
		},
		Egress: []api.EgressRule{
			{
				ToPorts: []api.PortRule{
					{
						Ports: []api.PortProtocol{{Port: "80", Protocol: "TCP"}},
						Rules: &api.L7Rules{HTTP: []api.PortRuleHTTP{{Path: "/public", Method: "GET"}}},
					},
				},
			},
			{
				ToCIDR:    []api.CIDR{"10.0.0.1"},
				ToCIDRSet: []api.CIDRRule{{Cidr: api.CIDR("10.0.0.0/8"), ExceptCIDRs: []api.CIDR{"10.96.0.0/12"}}},
			},
		},
		Labels: labels.ParseLabelArray(fmt.Sprintf("%s=%s", PolicyLabelName, "rule1")),
	}

	rawRule = []byte(`{
        "endpointSelector": {
            "matchLabels": {
                "role": "backend"
            },
            "matchExpressions": [
                {
                    "key": "role",
                    "operator": "NotIn",
                    "values": [
                        "production"
                    ]
                }
            ]
        },
        "ingress": [
            {
                "fromEndpoints": [
                    {
                        "matchLabels": {
                            "role": "frontend"
                        }
                    },
                    {
                        "matchLabels": {
                            "reserved:world": ""
                        }
                    }
                ],
                "toPorts": [
                    {
                        "ports": [
                            {
                                "port": "80",
                                "protocol": "TCP"
                            }
                        ],
                        "rules": {
                            "http": [
                                {
                                    "path": "/public",
                                    "method": "GET"
                                }
                            ]
                        }
                    }
                ]
            }
        ],
        "egress": [
            {
                "toPorts": [
                    {
                        "ports": [
                            {
                                "port": "80",
                                "protocol": "TCP"
                            }
                        ],
                        "rules": {
                            "http": [
                                {
                                    "path": "/public",
                                    "method": "GET"
                                }
                            ]
                        }
                    }
                ]
            },{
                "toCIDR": [
                    "10.0.0.1"
                ],
				"toCIDRSet": [
					{
						"cidr": "10.0.0.0/8",
						"except": [
							"10.96.0.0/12"
						]
					}
				]
            }
        ]
    }`)

	ciliumRule = append(append([]byte(`{
    "metadata": {
        "name": "rule1"
    },
    "spec": `), rawRule...), []byte(`
}`)...)
	ciliumRuleList = append(append(append(append([]byte(`{
    "metadata": {
        "name": "rule1"
    },
    "specs": [`), rawRule...), []byte(`, `)...), rawRule...), []byte(`]
}`)...)
)

func (s *K8sSuite) TestParseSpec(c *C) {

	es := api.NewESFromLabels(labels.ParseSelectLabel("role=backend"))
	es.MatchExpressions = []metav1.LabelSelectorRequirement{
		{Key: "any.role", Operator: "NotIn", Values: []string{"production"}},
	}

	apiRule.EndpointSelector = es

	expectedPolicyRule := &CiliumNetworkPolicy{
		Metadata: metav1.ObjectMeta{
			Name: "rule1",
		},
		Spec: &apiRule,
	}

	expectedES := api.NewESFromLabels(labels.ParseSelectLabel("role=backend"), labels.ParseSelectLabel("k8s:"+PodNamespaceLabel+"=default"))
	expectedES.MatchExpressions = []metav1.LabelSelectorRequirement{{Key: "any.role", Operator: "NotIn", Values: []string{"production"}}}

	expectedSpecRule.EndpointSelector = expectedES

	rules, err := expectedPolicyRule.Parse()
	c.Assert(err, IsNil)
	c.Assert(len(rules), Equals, 1)
	c.Assert(*rules[0], comparator.DeepEquals, expectedSpecRule)

	b, err := json.Marshal(expectedPolicyRule)
	c.Assert(err, IsNil)
	var expectedPolicyRuleUnmarshalled CiliumNetworkPolicy
	err = json.Unmarshal(b, &expectedPolicyRuleUnmarshalled)
	c.Assert(err, IsNil)
	c.Assert(expectedPolicyRuleUnmarshalled, comparator.DeepEquals, *expectedPolicyRule)

	cnpl := CiliumNetworkPolicy{}
	err = json.Unmarshal(ciliumRule, &cnpl)
	c.Assert(err, IsNil)
	c.Assert(cnpl, comparator.DeepEquals, *expectedPolicyRule)
}

func (s *K8sSuite) TestParseRules(c *C) {
	es := api.NewESFromLabels(labels.ParseSelectLabel("role=backend"))
	es.MatchExpressions = []metav1.LabelSelectorRequirement{{Key: "any.role", Operator: "NotIn", Values: []string{"production"}}}

	apiRule.EndpointSelector = es

	expectedPolicyRuleList := &CiliumNetworkPolicy{
		Metadata: metav1.ObjectMeta{
			Name: "rule1",
		},
		Specs: api.Rules{&apiRule, &apiRule},
	}

	expectedES := api.NewESFromLabels(labels.ParseSelectLabel("role=backend"), labels.ParseSelectLabel("k8s:"+PodNamespaceLabel+"=default"))
	expectedES.MatchExpressions = []metav1.LabelSelectorRequirement{{Key: "any.role", Operator: "NotIn", Values: []string{"production"}}}

	expectedSpecRule.EndpointSelector = expectedES

	expectedSpecRules := api.Rules{&expectedSpecRule, &expectedSpecRule}

	rules, err := expectedPolicyRuleList.Parse()
	c.Assert(err, IsNil)
	c.Assert(len(rules), Equals, 2)
	for i, rule := range rules {
		c.Assert(rule, comparator.DeepEquals, expectedSpecRules[i])
	}

	b, err := json.Marshal(expectedPolicyRuleList)
	c.Assert(err, IsNil)
	var expectedPolicyRuleUnmarshalled CiliumNetworkPolicy
	err = json.Unmarshal(b, &expectedPolicyRuleUnmarshalled)
	c.Assert(err, IsNil)
	c.Assert(expectedPolicyRuleUnmarshalled, comparator.DeepEquals, *expectedPolicyRuleList)

	cnpl := CiliumNetworkPolicy{}
	err = json.Unmarshal(ciliumRuleList, &cnpl)
	c.Assert(err, IsNil)
	c.Assert(cnpl, comparator.DeepEquals, *expectedPolicyRuleList)
}

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

package v2

import (
	"encoding/json"
	"testing"

	"github.com/cilium/cilium/pkg/comparator"
	k8sConst "github.com/cilium/cilium/pkg/k8s/apis"
	k8sUtils "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/utils"
	"github.com/cilium/cilium/pkg/labels"
	"github.com/cilium/cilium/pkg/policy/api/v2"

	. "gopkg.in/check.v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// Hook up gocheck into the "go test" runner.
func Test(t *testing.T) {
	TestingT(t)
}

type CiliumV2Suite struct{}

var _ = Suite(&CiliumV2Suite{})

var (
	apiRule = v2.Rule{
		Ingress: []v2.IngressRule{
			{
				FromEndpoints: []v2.EndpointSelector{
					v2.NewESFromLabels(
						labels.ParseSelectLabel("role=frontend"),
					),
					v2.NewESFromLabels(
						labels.ParseSelectLabel("reserved:world"),
					),
				},
				ToPorts: []v2.PortRule{
					{
						Ports: []v2.PortProtocol{{Port: "80", Protocol: "TCP"}},
						Rules: &v2.L7Rules{HTTP: []v2.PortRuleHTTP{{Path: "/public", Method: "GET"}}},
					},
				},
			},
		},
		Egress: []v2.EgressRule{
			{
				ToPorts: []v2.PortRule{
					{
						Ports: []v2.PortProtocol{{Port: "80", Protocol: "TCP"}},
						Rules: &v2.L7Rules{HTTP: []v2.PortRuleHTTP{{Path: "/public", Method: "GET"}}},
					},
				},
			}, {
				ToCIDR: []v2.CIDR{"10.0.0.1"},
			}, {
				ToCIDRSet: []v2.CIDRRule{{Cidr: v2.CIDR("10.0.0.0/8"), ExceptCIDRs: []v2.CIDR{"10.96.0.0/12"}}},
			},
		},
	}

	expectedSpecRule = v2.Rule{
		Ingress: []v2.IngressRule{
			{
				FromEndpoints: []v2.EndpointSelector{
					v2.NewESFromLabels(
						labels.ParseSelectLabel("role=frontend"),
						labels.ParseSelectLabel("k8s:"+k8sConst.PodNamespaceLabel+"=default"),
					),
					v2.NewESFromLabels(
						labels.ParseSelectLabel("reserved:world"),
					),
				},
				ToPorts: []v2.PortRule{
					{
						Ports: []v2.PortProtocol{{Port: "80", Protocol: "TCP"}},
						Rules: &v2.L7Rules{HTTP: []v2.PortRuleHTTP{{Path: "/public", Method: "GET"}}},
					},
				},
			},
		},
		Egress: []v2.EgressRule{
			{
				ToPorts: []v2.PortRule{
					{
						Ports: []v2.PortProtocol{{Port: "80", Protocol: "TCP"}},
						Rules: &v2.L7Rules{HTTP: []v2.PortRuleHTTP{{Path: "/public", Method: "GET"}}},
					},
				},
			},
			{
				ToCIDR: []v2.CIDR{"10.0.0.1"},
			}, {
				ToCIDRSet: []v2.CIDRRule{{Cidr: v2.CIDR("10.0.0.0/8"), ExceptCIDRs: []v2.CIDR{"10.96.0.0/12"}}},
			},
		},
		Labels: k8sUtils.GetPolicyLabels("default", "rule1"),
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
                ]
            },{
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

func (s *CiliumV2Suite) TestParseSpec(c *C) {

	es := v2.NewESFromLabels(labels.ParseSelectLabel("role=backend"))
	es.MatchExpressions = []metav1.LabelSelectorRequirement{
		{Key: "any.role", Operator: "NotIn", Values: []string{"production"}},
	}

	apiRule.EndpointSelector = es

	expectedPolicyRule := &CiliumNetworkPolicy{
		ObjectMeta: metav1.ObjectMeta{
			Name: "rule1",
		},
		Spec: &apiRule,
	}

	expectedES := v2.NewESFromLabels(labels.ParseSelectLabel("role=backend"), labels.ParseSelectLabel("k8s:"+k8sConst.PodNamespaceLabel+"=default"))
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

func (s *CiliumV2Suite) TestParseRules(c *C) {
	es := v2.NewESFromLabels(labels.ParseSelectLabel("role=backend"))
	es.MatchExpressions = []metav1.LabelSelectorRequirement{{Key: "any.role", Operator: "NotIn", Values: []string{"production"}}}

	apiRule.EndpointSelector = es

	expectedPolicyRuleList := &CiliumNetworkPolicy{
		ObjectMeta: metav1.ObjectMeta{
			Name: "rule1",
		},
		Specs: v2.Rules{&apiRule, &apiRule},
	}

	expectedES := v2.NewESFromLabels(labels.ParseSelectLabel("role=backend"), labels.ParseSelectLabel("k8s:"+k8sConst.PodNamespaceLabel+"=default"))
	expectedES.MatchExpressions = []metav1.LabelSelectorRequirement{{Key: "any.role", Operator: "NotIn", Values: []string{"production"}}}

	expectedSpecRule.EndpointSelector = expectedES

	expectedSpecRules := v2.Rules{&expectedSpecRule, &expectedSpecRule}

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

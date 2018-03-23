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

package v3

import (
	"encoding/json"
	"testing"

	"github.com/cilium/cilium/pkg/comparator"
	k8sConst "github.com/cilium/cilium/pkg/k8s/apis"
	k8sUtils "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/utils"
	"github.com/cilium/cilium/pkg/labels"
	"github.com/cilium/cilium/pkg/policy/api/v3"

	. "gopkg.in/check.v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// Hook up gocheck into the "go test" runner.
func Test(t *testing.T) {
	TestingT(t)
}

type CiliumV3Suite struct{}

var _ = Suite(&CiliumV3Suite{})

var (
	apiRule = v3.Rule{
		Ingress: []v3.IngressRule{
			{
				FromIdentities: &v3.IdentityRule{
					IdentitySelector: v3.NewESFromLabels(
						labels.ParseSelectLabel("role=frontend"),
					),
					ToPorts: &v3.PortRule{
						Ports: []v3.PortProtocol{{Port: "80", Protocol: "TCP"}},
						Rules: &v3.L7Rules{HTTP: []v3.PortRuleHTTP{{Path: "/public", Method: "GET"}}},
					},
				},
			},
			{
				FromIdentities: &v3.IdentityRule{
					IdentitySelector: v3.NewESFromLabels(
						labels.ParseSelectLabel("reserved:world"),
					),
					ToPorts: &v3.PortRule{
						Ports: []v3.PortProtocol{{Port: "80", Protocol: "TCP"}},
						Rules: &v3.L7Rules{HTTP: []v3.PortRuleHTTP{{Path: "/public", Method: "GET"}}},
					},
				},
			},
		},
		Egress: []v3.EgressRule{
			{
				ToCIDRs: &v3.CIDRRule{
					CIDR: []v3.CIDR{"10.0.0.1"},
					ToPorts: &v3.PortRule{
						Ports: []v3.PortProtocol{{Port: "80", Protocol: "TCP"}},
						Rules: &v3.L7Rules{HTTP: []v3.PortRuleHTTP{{Path: "/public", Method: "GET"}}},
					},
				},
			},
			{
				ToCIDRs: &v3.CIDRRule{
					CIDR:        []v3.CIDR{"10.0.0.0/8"},
					ExceptCIDRs: []v3.CIDR{"10.96.0.0/12"},
					ToPorts: &v3.PortRule{
						Ports: []v3.PortProtocol{{Port: "80", Protocol: "TCP"}},
						Rules: &v3.L7Rules{HTTP: []v3.PortRuleHTTP{{Path: "/public", Method: "GET"}}},
					},
				},
			},
		},
	}

	expectedSpecRule = v3.Rule{
		Ingress: []v3.IngressRule{
			{
				FromIdentities: &v3.IdentityRule{
					IdentitySelector: v3.NewESFromLabels(
						labels.ParseSelectLabel("role=frontend"),
						labels.ParseSelectLabel("k8s:"+k8sConst.PodNamespaceLabel+"=default"),
					),
					ToPorts: &v3.PortRule{
						Ports: []v3.PortProtocol{{Port: "80", Protocol: "TCP"}},
						Rules: &v3.L7Rules{HTTP: []v3.PortRuleHTTP{{Path: "/public", Method: "GET"}}},
					},
				},
			},
			{
				FromIdentities: &v3.IdentityRule{
					IdentitySelector: v3.NewESFromLabels(
						labels.ParseSelectLabel("reserved:world"),
					),
					ToPorts: &v3.PortRule{
						Ports: []v3.PortProtocol{{Port: "80", Protocol: "TCP"}},
						Rules: &v3.L7Rules{HTTP: []v3.PortRuleHTTP{{Path: "/public", Method: "GET"}}},
					},
				},
			},
		},
		Egress: []v3.EgressRule{
			{
				ToCIDRs: &v3.CIDRRule{
					CIDR: []v3.CIDR{"10.0.0.1"},
					ToPorts: &v3.PortRule{
						Ports: []v3.PortProtocol{{Port: "80", Protocol: "TCP"}},
						Rules: &v3.L7Rules{HTTP: []v3.PortRuleHTTP{{Path: "/public", Method: "GET"}}},
					},
				},
			},
			{
				ToCIDRs: &v3.CIDRRule{
					CIDR:        []v3.CIDR{"10.0.0.0/8"},
					ExceptCIDRs: []v3.CIDR{"10.96.0.0/12"},
					ToPorts: &v3.PortRule{
						Ports: []v3.PortProtocol{{Port: "80", Protocol: "TCP"}},
						Rules: &v3.L7Rules{HTTP: []v3.PortRuleHTTP{{Path: "/public", Method: "GET"}}},
					},
				},
			},
		},
		Labels: k8sUtils.GetPolicyLabels("default", "rule1"),
	}

	rawRule = []byte(`{
        "identitySelector": {
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
                "fromIdentities": {
                    "identitySelector": {
                        "matchLabels": {
                            "role": "frontend"
                        }
                    },
                    "toPorts": {
                        "anyOf": [
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
                }
            },
            {
                "fromIdentities": {
                    "identitySelector": {
                        "matchLabels": {
                            "reserved:world": ""
                        }
                    },
                    "toPorts": {
                        "anyOf": [
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
                }
            }
        ],
        "egress": [
            {
                "toCIDR": {
                    "anyOf": [
                        "10.0.0.1"
                    ],
                    "toPorts": {
                        "anyOf": [
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
                }
            },
            {
                "toCIDR": {
                    "anyOf": [
                        "10.0.0.0/8"
                    ],
                    "except": [
                        "10.96.0.0/12"
                    ],
                    "toPorts": {
                        "anyOf": [
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
                }
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

func (s *CiliumV3Suite) TestParseSpec(c *C) {

	es := v3.NewESFromLabels(labels.ParseSelectLabel("role=backend"))
	es.MatchExpressions = []metav1.LabelSelectorRequirement{
		{Key: "any.role", Operator: "NotIn", Values: []string{"production"}},
	}

	apiRule.IdentitySelector = es

	expectedPolicyRule := &CiliumNetworkPolicy{
		ObjectMeta: metav1.ObjectMeta{
			Name: "rule1",
		},
		Spec: &apiRule,
	}

	expectedES := v3.NewESFromLabels(labels.ParseSelectLabel("role=backend"), labels.ParseSelectLabel("k8s:"+k8sConst.PodNamespaceLabel+"=default"))
	expectedES.MatchExpressions = []metav1.LabelSelectorRequirement{{Key: "any.role", Operator: "NotIn", Values: []string{"production"}}}

	expectedSpecRule.IdentitySelector = expectedES

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

func (s *CiliumV3Suite) TestParseRules(c *C) {
	es := v3.NewESFromLabels(labels.ParseSelectLabel("role=backend"))
	es.MatchExpressions = []metav1.LabelSelectorRequirement{{Key: "any.role", Operator: "NotIn", Values: []string{"production"}}}

	apiRule.IdentitySelector = es

	expectedPolicyRuleList := &CiliumNetworkPolicy{
		ObjectMeta: metav1.ObjectMeta{
			Name: "rule1",
		},
		Specs: v3.Rules{&apiRule, &apiRule},
	}

	expectedES := v3.NewESFromLabels(labels.ParseSelectLabel("role=backend"), labels.ParseSelectLabel("k8s:"+k8sConst.PodNamespaceLabel+"=default"))
	expectedES.MatchExpressions = []metav1.LabelSelectorRequirement{{Key: "any.role", Operator: "NotIn", Values: []string{"production"}}}

	expectedSpecRule.IdentitySelector = expectedES

	expectedSpecRules := v3.Rules{&expectedSpecRule, &expectedSpecRule}

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

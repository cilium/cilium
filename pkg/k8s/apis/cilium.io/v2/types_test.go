// Copyright 2016-2019 Authors of Cilium
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

package v2

import (
	"encoding/json"
	"fmt"
	"testing"

	"github.com/cilium/cilium/pkg/checker"
	k8sConst "github.com/cilium/cilium/pkg/k8s/apis/cilium.io"
	k8sUtils "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/utils"
	"github.com/cilium/cilium/pkg/labels"
	"github.com/cilium/cilium/pkg/policy/api"

	. "gopkg.in/check.v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
)

// Hook up gocheck into the "go test" runner.
func Test(t *testing.T) {
	TestingT(t)
}

type CiliumV2Suite struct{}

var _ = Suite(&CiliumV2Suite{})

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
				ToCIDR: []api.CIDR{"10.0.0.1"},
			}, {
				ToCIDRSet: []api.CIDRRule{{Cidr: api.CIDR("10.0.0.0/8"), ExceptCIDRs: []api.CIDR{"10.96.0.0/12"}}},
			},
		},
	}

	apiRuleWithLabels = api.Rule{
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
				ToCIDR: []api.CIDR{"10.0.0.1"},
			}, {
				ToCIDRSet: []api.CIDRRule{{Cidr: api.CIDR("10.0.0.0/8"), ExceptCIDRs: []api.CIDR{"10.96.0.0/12"}}},
			},
		},
		Labels: labels.LabelArray{{Key: "uuid", Value: "98678-9868976-78687678887678", Source: ""}},
	}
	uuidRule         = types.UID("98678-9868976-78687678887678")
	expectedSpecRule = api.NewRule().
				WithIngressRules([]api.IngressRule{
			{
				FromEndpoints: []api.EndpointSelector{
					api.NewESFromLabels(
						labels.ParseSelectLabel("role=frontend"),
						labels.ParseSelectLabel("k8s:"+k8sConst.PodNamespaceLabel+"=default"),
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
		}).
		WithEgressRules([]api.EgressRule{
			{
				ToPorts: []api.PortRule{
					{
						Ports: []api.PortProtocol{{Port: "80", Protocol: "TCP"}},
						Rules: &api.L7Rules{HTTP: []api.PortRuleHTTP{{Path: "/public", Method: "GET"}}},
					},
				},
			},
			{
				ToCIDR: []api.CIDR{"10.0.0.1"},
			}, {
				ToCIDRSet: []api.CIDRRule{{Cidr: api.CIDR("10.0.0.0/8"), ExceptCIDRs: []api.CIDR{"10.96.0.0/12"}}},
			},
		}).
		WithLabels(k8sUtils.GetPolicyLabels("default", "rule1", uuidRule, "CiliumNetworkPolicy"))

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
        ],
        "labels": [
            {
                "key": "uuid",
                "value": "98678-9868976-78687678887678"
            }
        ]
    }`)

	ciliumRule = append(append([]byte(`{
    "metadata": {
        "name": "rule1",
		"uid": "`+uuidRule+`"
    },
    "spec": `), rawRule...), []byte(`
}`)...)
	ciliumRuleList = append(append(append(append([]byte(`{
    "metadata": {
        "name": "rule1",
		"uid": "`+uuidRule+`"
    },
    "specs": [`), rawRule...), []byte(`, `)...), rawRule...), []byte(`]
}`)...)
)

func (s *CiliumV2Suite) TestParseSpec(c *C) {
	es := api.NewESFromMatchRequirements(
		map[string]string{
			fmt.Sprintf("%s.role", labels.LabelSourceAny): "backend",
		},
		[]metav1.LabelSelectorRequirement{{
			Key:      fmt.Sprintf("%s.role", labels.LabelSourceAny),
			Operator: "NotIn",
			Values:   []string{"production"},
		}},
	)

	apiRule.EndpointSelector = es

	expectedPolicyRule := &CiliumNetworkPolicy{
		ObjectMeta: metav1.ObjectMeta{
			Name: "rule1",
			UID:  uuidRule,
		},
		Spec: &apiRule,
	}

	apiRuleWithLabels.EndpointSelector = es

	expectedPolicyRuleWithLabel := &CiliumNetworkPolicy{
		ObjectMeta: metav1.ObjectMeta{
			Name: "rule1",
			UID:  uuidRule,
		},
		Spec: &apiRuleWithLabels,
	}

	expectedES := api.NewESFromMatchRequirements(
		map[string]string{
			fmt.Sprintf("%s.role", labels.LabelSourceAny):                           "backend",
			fmt.Sprintf("%s.%s", labels.LabelSourceK8s, k8sConst.PodNamespaceLabel): "default",
		},
		[]metav1.LabelSelectorRequirement{{
			Key:      fmt.Sprintf("%s.role", labels.LabelSourceAny),
			Operator: "NotIn",
			Values:   []string{"production"},
		}},
	)
	expectedSpecRule.EndpointSelector = expectedES

	// Sanitize rule to populate aggregated selectors.
	expectedSpecRule.Sanitize()

	rules, err := expectedPolicyRule.Parse()
	c.Assert(err, IsNil)
	c.Assert(len(rules), Equals, 1)
	c.Assert(*rules[0], checker.DeepEquals, *expectedSpecRule)

	b, err := json.Marshal(expectedPolicyRule)
	c.Assert(err, IsNil)
	var expectedPolicyRuleUnmarshalled CiliumNetworkPolicy
	err = json.Unmarshal(b, &expectedPolicyRuleUnmarshalled)
	c.Assert(err, IsNil)
	expectedPolicyRuleUnmarshalled.Parse()
	c.Assert(expectedPolicyRuleUnmarshalled, checker.DeepEquals, *expectedPolicyRule)

	cnpl := CiliumNetworkPolicy{}
	err = json.Unmarshal(ciliumRule, &cnpl)
	c.Assert(err, IsNil)
	c.Assert(cnpl, checker.DeepEquals, *expectedPolicyRuleWithLabel)
}

func (s *CiliumV2Suite) TestParseRules(c *C) {
	es := api.NewESFromMatchRequirements(
		map[string]string{
			fmt.Sprintf("%s.role", labels.LabelSourceAny): "backend",
		},
		[]metav1.LabelSelectorRequirement{{
			Key:      fmt.Sprintf("%s.role", labels.LabelSourceAny),
			Operator: "NotIn",
			Values:   []string{"production"},
		}},
	)

	apiRule.EndpointSelector = es

	expectedPolicyRuleList := &CiliumNetworkPolicy{
		ObjectMeta: metav1.ObjectMeta{
			Name: "rule1",
			UID:  uuidRule,
		},
		Specs: api.Rules{&apiRule, &apiRule},
	}

	apiRuleWithLabels.EndpointSelector = es

	expectedPolicyRuleListWithLabel := &CiliumNetworkPolicy{
		ObjectMeta: metav1.ObjectMeta{
			Name: "rule1",
			UID:  uuidRule,
		},
		Specs: api.Rules{&apiRuleWithLabels, &apiRuleWithLabels},
	}

	expectedES := api.NewESFromMatchRequirements(
		map[string]string{
			fmt.Sprintf("%s.role", labels.LabelSourceAny):                           "backend",
			fmt.Sprintf("%s.%s", labels.LabelSourceK8s, k8sConst.PodNamespaceLabel): "default",
		},
		[]metav1.LabelSelectorRequirement{{
			Key:      fmt.Sprintf("%s.role", labels.LabelSourceAny),
			Operator: "NotIn",
			Values:   []string{"production"},
		}},
	)
	expectedSpecRule.EndpointSelector = expectedES
	expectedSpecRules := api.Rules{expectedSpecRule, expectedSpecRule}
	expectedSpecRule.Sanitize()
	for i := range expectedSpecRules {
		expectedSpecRules[i].Sanitize()
	}

	rules, err := expectedPolicyRuleList.Parse()
	c.Assert(err, IsNil)
	c.Assert(len(rules), Equals, 2)
	for i, rule := range rules {
		c.Assert(rule, checker.DeepEquals, expectedSpecRules[i])
	}

	b, err := json.Marshal(expectedPolicyRuleList)
	c.Assert(err, IsNil)
	var expectedPolicyRuleUnmarshalled CiliumNetworkPolicy
	err = json.Unmarshal(b, &expectedPolicyRuleUnmarshalled)
	c.Assert(err, IsNil)
	expectedPolicyRuleUnmarshalled.Parse()
	c.Assert(expectedPolicyRuleUnmarshalled, checker.DeepEquals, *expectedPolicyRuleList)

	cnpl := CiliumNetworkPolicy{}
	err = json.Unmarshal(ciliumRuleList, &cnpl)
	c.Assert(err, IsNil)
	c.Assert(cnpl, checker.DeepEquals, *expectedPolicyRuleListWithLabel)
}

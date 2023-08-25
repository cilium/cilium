// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package v2

import (
	"encoding/json"
	"fmt"
	"reflect"
	"testing"

	. "github.com/cilium/checkmate"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"

	eniTypes "github.com/cilium/cilium/pkg/aws/eni/types"
	"github.com/cilium/cilium/pkg/checker"
	k8sConst "github.com/cilium/cilium/pkg/k8s/apis/cilium.io"
	k8sUtils "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/utils"
	slim_metav1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/apis/meta/v1"
	"github.com/cilium/cilium/pkg/labels"
	"github.com/cilium/cilium/pkg/policy/api"
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
				IngressCommonRule: api.IngressCommonRule{
					FromEndpoints: []api.EndpointSelector{
						api.NewESFromLabels(
							labels.ParseSelectLabel("role=frontend"),
						),
						api.NewESFromLabels(
							labels.ParseSelectLabel("reserved:world"),
						),
					},
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
				EgressCommonRule: api.EgressCommonRule{
					ToCIDR: []api.CIDR{"10.0.0.1"},
				},
			}, {
				EgressCommonRule: api.EgressCommonRule{
					ToCIDRSet: []api.CIDRRule{{Cidr: api.CIDR("10.0.0.0/8"), ExceptCIDRs: []api.CIDR{"10.96.0.0/12"}}},
				},
			},
		},
	}

	apiRuleWithLabels = api.Rule{
		Ingress: []api.IngressRule{
			{
				IngressCommonRule: api.IngressCommonRule{
					FromEndpoints: []api.EndpointSelector{
						api.NewESFromLabels(
							labels.ParseSelectLabel("role=frontend"),
						),
						api.NewESFromLabels(
							labels.ParseSelectLabel("reserved:world"),
						),
					},
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
				EgressCommonRule: api.EgressCommonRule{
					ToCIDR: []api.CIDR{"10.0.0.1"},
				},
			}, {
				EgressCommonRule: api.EgressCommonRule{
					ToCIDRSet: []api.CIDRRule{{Cidr: api.CIDR("10.0.0.0/8"), ExceptCIDRs: []api.CIDR{"10.96.0.0/12"}}},
				},
			},
		},
		Labels: labels.LabelArray{{Key: "uuid", Value: "98678-9868976-78687678887678", Source: ""}},
	}
	uuidRule         = types.UID("98678-9868976-78687678887678")
	expectedSpecRule = api.NewRule().
				WithIngressRules([]api.IngressRule{
			{
				IngressCommonRule: api.IngressCommonRule{
					FromEndpoints: []api.EndpointSelector{
						api.NewESFromLabels(
							labels.ParseSelectLabel("role=frontend"),
							labels.ParseSelectLabel("k8s:"+k8sConst.PodNamespaceLabel+"=default"),
						),
						api.NewESFromLabels(
							labels.ParseSelectLabel("reserved:world"),
						),
					},
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
				EgressCommonRule: api.EgressCommonRule{
					ToCIDR: []api.CIDR{"10.0.0.1"},
				},
			}, {
				EgressCommonRule: api.EgressCommonRule{
					ToCIDRSet: []api.CIDRRule{{Cidr: api.CIDR("10.0.0.0/8"), ExceptCIDRs: []api.CIDR{"10.96.0.0/12"}}},
				},
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
		"namespace": "default",
        "name": "rule1",
		"uid": "`+uuidRule+`"
    },
    "spec": `), rawRule...), []byte(`
}`)...)
	ciliumRuleList = append(append(append(append([]byte(`{
    "metadata": {
		"namespace": "default",
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
		[]slim_metav1.LabelSelectorRequirement{{
			Key:      fmt.Sprintf("%s.role", labels.LabelSourceAny),
			Operator: "NotIn",
			Values:   []string{"production"},
		}},
	)

	apiRule.EndpointSelector = es

	expectedPolicyRule := &CiliumNetworkPolicy{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: "default",
			Name:      "rule1",
			UID:       uuidRule,
		},
		Spec: &apiRule,
	}

	apiRuleWithLabels.EndpointSelector = es

	expectedPolicyRuleWithLabel := &CiliumNetworkPolicy{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: "default",
			Name:      "rule1",
			UID:       uuidRule,
		},
		Spec: &apiRuleWithLabels,
	}

	expectedES := api.NewESFromMatchRequirements(
		map[string]string{
			fmt.Sprintf("%s.role", labels.LabelSourceAny):                           "backend",
			fmt.Sprintf("%s.%s", labels.LabelSourceK8s, k8sConst.PodNamespaceLabel): "default",
		},
		[]slim_metav1.LabelSelectorRequirement{{
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

	empty := &CiliumNetworkPolicy{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: "default",
			Name:      "rule1",
			UID:       uuidRule,
		},
	}
	_, err = empty.Parse()
	c.Assert(err, checker.DeepEquals, ErrEmptyCNP)

	emptyCCNP := &CiliumClusterwideNetworkPolicy{
		ObjectMeta: metav1.ObjectMeta{
			Name: "rule1",
			UID:  uuidRule,
		},
	}
	_, err = emptyCCNP.Parse()
	c.Assert(err, checker.DeepEquals, ErrEmptyCCNP)
}

func (s *CiliumV2Suite) TestParseRules(c *C) {
	es := api.NewESFromMatchRequirements(
		map[string]string{
			fmt.Sprintf("%s.role", labels.LabelSourceAny): "backend",
		},
		[]slim_metav1.LabelSelectorRequirement{{
			Key:      fmt.Sprintf("%s.role", labels.LabelSourceAny),
			Operator: "NotIn",
			Values:   []string{"production"},
		}},
	)

	apiRule.EndpointSelector = es

	expectedPolicyRuleList := &CiliumNetworkPolicy{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: "default",
			Name:      "rule1",
			UID:       uuidRule,
		},
		Specs: api.Rules{&apiRule, &apiRule},
	}

	apiRuleWithLabels.EndpointSelector = es

	expectedPolicyRuleListWithLabel := &CiliumNetworkPolicy{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: "default",
			Name:      "rule1",
			UID:       uuidRule,
		},
		Specs: api.Rules{&apiRuleWithLabels, &apiRuleWithLabels},
	}

	expectedES := api.NewESFromMatchRequirements(
		map[string]string{
			fmt.Sprintf("%s.role", labels.LabelSourceAny):                           "backend",
			fmt.Sprintf("%s.%s", labels.LabelSourceK8s, k8sConst.PodNamespaceLabel): "default",
		},
		[]slim_metav1.LabelSelectorRequirement{{
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

func (s *CiliumV2Suite) TestParseWithNodeSelector(c *C) {
	// A rule without any L7 rules so that we can validate both CNP and CCNP.
	// CCNP doesn't support L7 rules just yet.
	rule := api.Rule{
		EndpointSelector: api.NewESFromLabels(),
		Ingress: []api.IngressRule{
			{
				IngressCommonRule: api.IngressCommonRule{
					FromEndpoints: []api.EndpointSelector{
						api.NewESFromLabels(
							labels.ParseSelectLabel("role=frontend"),
						),
						api.NewESFromLabels(
							labels.ParseSelectLabel("reserved:world"),
						),
					},
				},
				ToPorts: []api.PortRule{
					{
						Ports: []api.PortProtocol{{Port: "80", Protocol: "TCP"}},
					},
				},
			},
		},
		Egress: []api.EgressRule{
			{
				ToPorts: []api.PortRule{
					{
						Ports: []api.PortProtocol{{Port: "80", Protocol: "TCP"}},
					},
				},
			}, {
				EgressCommonRule: api.EgressCommonRule{
					ToCIDR: []api.CIDR{"10.0.0.1"},
				},
			}, {
				EgressCommonRule: api.EgressCommonRule{
					ToCIDRSet: []api.CIDRRule{{Cidr: api.CIDR("10.0.0.0/8"), ExceptCIDRs: []api.CIDR{"10.96.0.0/12"}}},
				},
			},
		},
	}

	emptySelector := api.EndpointSelector{LabelSelector: nil}
	prevEPSelector := rule.EndpointSelector

	// A NodeSelector is an EndpointSelector. We can reuse the previous value
	// that was set as an EndpointSelector.
	rule.EndpointSelector = emptySelector
	rule.NodeSelector = prevEPSelector

	// Expect CNP parse error because it's not allowed to have a NodeSelector.
	cnpl := CiliumNetworkPolicy{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: "default",
			Name:      "rule",
			UID:       uuidRule,
		},
		Spec: &rule,
	}
	_, err := cnpl.Parse()
	c.Assert(err, ErrorMatches,
		"Invalid CiliumNetworkPolicy spec: rule cannot have NodeSelector")

	// CCNP parse is allowed to have a NodeSelector.
	ccnpl := CiliumClusterwideNetworkPolicy{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: "",
			Name:      "rule",
			UID:       uuidRule,
		},
		Spec: cnpl.Spec,
	}
	_, err = ccnpl.Parse()
	c.Assert(err, IsNil)

	// CCNPs are received as CNP and initially parsed as CNP. Create a CNP with
	// an empty namespace to test this case. See #12834 for details.
	ccnplAsCNP := CiliumNetworkPolicy{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: "",
			Name:      "rule",
			UID:       uuidRule,
		},
		Spec: &rule,
	}
	_, err = ccnplAsCNP.Parse()
	c.Assert(err, IsNil)

	// Now test a CNP and CCNP with an EndpointSelector only.
	rule.EndpointSelector = prevEPSelector
	rule.NodeSelector = emptySelector

	// CNP and CCNP parse is allowed to have an EndpointSelector.
	_, err = cnpl.Parse()
	c.Assert(err, IsNil)
	_, err = ccnpl.Parse()
	c.Assert(err, IsNil)
	_, err = ccnplAsCNP.Parse()
	c.Assert(err, IsNil)
}

func (s *CiliumV2Suite) TestCiliumNodeInstanceID(c *C) {
	c.Assert((*CiliumNode)(nil).InstanceID(), Equals, "")
	c.Assert((&CiliumNode{}).InstanceID(), Equals, "")
	c.Assert((&CiliumNode{Spec: NodeSpec{InstanceID: "foo"}}).InstanceID(), Equals, "foo")
	c.Assert((&CiliumNode{Spec: NodeSpec{InstanceID: "foo", ENI: eniTypes.ENISpec{InstanceID: "bar"}}}).InstanceID(), Equals, "foo")
	c.Assert((&CiliumNode{Spec: NodeSpec{ENI: eniTypes.ENISpec{InstanceID: "bar"}}}).InstanceID(), Equals, "bar")
}

func BenchmarkSpecEquals(b *testing.B) {
	r := &CiliumNetworkPolicy{
		Spec: &api.Rule{
			EndpointSelector: api.EndpointSelector{
				LabelSelector: &slim_metav1.LabelSelector{
					MatchLabels: map[string]string{
						"foo3": "bar3",
						"foo4": "bar4",
					},
					MatchExpressions: []slim_metav1.LabelSelectorRequirement{
						{
							Key:      "any.foo",
							Operator: "NotIn",
							Values:   []string{"default"},
						},
					},
				},
			},
			Ingress: []api.IngressRule{
				{
					IngressCommonRule: api.IngressCommonRule{
						FromEndpoints: []api.EndpointSelector{
							{
								LabelSelector: &slim_metav1.LabelSelector{
									MatchLabels: map[string]string{
										"foo3": "bar3",
										"foo4": "bar4",
									},
									MatchExpressions: []slim_metav1.LabelSelectorRequirement{
										{
											Key:      "any.foo",
											Operator: "NotIn",
											Values:   []string{"default"},
										},
									},
								},
							},
						},
						FromCIDR:     nil,
						FromCIDRSet:  nil,
						FromEntities: nil,
					},
					ToPorts: []api.PortRule{{
						Ports: []api.PortProtocol{
							{
								Port:     "8080",
								Protocol: "TCP",
							},
						},
						TerminatingTLS: &api.TLSContext{
							Secret: &api.Secret{
								Namespace: "",
								Name:      "",
							},
							TrustedCA:   "",
							Certificate: "",
							PrivateKey:  "",
						},
						OriginatingTLS: &api.TLSContext{
							Secret: &api.Secret{
								Namespace: "",
								Name:      "",
							},
							TrustedCA:   "",
							Certificate: "",
							PrivateKey:  "",
						},
						Rules: &api.L7Rules{
							HTTP: []api.PortRuleHTTP{
								{
									Path:   "path",
									Method: "method",
									Host:   "host",
								},
							},
						},
					}},
				},
			},
		},
	}
	o := r.DeepCopy()
	if !r.DeepEqual(o) {
		b.Error("Both structures should be equal!")
	}
	b.Run("Reflected SpecEquals", func(b *testing.B) {
		b.ReportAllocs()
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			reflect.DeepEqual(r.Spec, o.Spec)
			reflect.DeepEqual(r.Specs, o.Specs)
		}
	})
	b.Run("Generated SpecEquals", func(b *testing.B) {
		b.ReportAllocs()
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			r.DeepEqual(o)
		}
	})
}

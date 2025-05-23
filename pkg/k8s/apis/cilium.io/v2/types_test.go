// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package v2

import (
	"encoding/json"
	"fmt"
	"net"
	"reflect"
	"testing"

	"github.com/cilium/hive/hivetest"
	"github.com/stretchr/testify/require"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"

	eniTypes "github.com/cilium/cilium/pkg/aws/eni/types"
	cmtypes "github.com/cilium/cilium/pkg/clustermesh/types"
	k8sConst "github.com/cilium/cilium/pkg/k8s/apis/cilium.io"
	k8sUtils "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/utils"
	slim_metav1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/apis/meta/v1"
	"github.com/cilium/cilium/pkg/labels"
	"github.com/cilium/cilium/pkg/node/addressing"
	"github.com/cilium/cilium/pkg/policy/api"
)

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

func TestParseSpec(t *testing.T) {
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

	logger := hivetest.Logger(t)

	rules, err := expectedPolicyRule.Parse(logger, cmtypes.PolicyAnyCluster)
	require.NoError(t, err)
	require.Len(t, rules, 1)
	require.Equal(t, *expectedSpecRule, *rules[0])

	b, err := json.Marshal(expectedPolicyRule)
	require.NoError(t, err)
	var expectedPolicyRuleUnmarshalled CiliumNetworkPolicy
	err = json.Unmarshal(b, &expectedPolicyRuleUnmarshalled)
	require.NoError(t, err)
	expectedPolicyRuleUnmarshalled.Parse(logger, cmtypes.PolicyAnyCluster)
	require.Equal(t, *expectedPolicyRule, expectedPolicyRuleUnmarshalled)

	cnpl := CiliumNetworkPolicy{}
	err = json.Unmarshal(ciliumRule, &cnpl)
	require.NoError(t, err)
	require.Equal(t, *expectedPolicyRuleWithLabel, cnpl)

	empty := &CiliumNetworkPolicy{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: "default",
			Name:      "rule1",
			UID:       uuidRule,
		},
	}
	_, err = empty.Parse(logger, cmtypes.PolicyAnyCluster)
	require.EqualValues(t, ErrEmptyCNP, err)

	emptyCCNP := &CiliumClusterwideNetworkPolicy{
		ObjectMeta: metav1.ObjectMeta{
			Name: "rule1",
			UID:  uuidRule,
		},
	}
	_, err = emptyCCNP.Parse(logger, cmtypes.PolicyAnyCluster)
	require.EqualValues(t, ErrEmptyCCNP, err)
}

func TestParseRules(t *testing.T) {
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

	logger := hivetest.Logger(t)

	rules, err := expectedPolicyRuleList.Parse(logger, cmtypes.PolicyAnyCluster)
	require.NoError(t, err)
	require.Len(t, rules, 2)
	for i, rule := range rules {
		require.Equal(t, expectedSpecRules[i], rule)
	}

	b, err := json.Marshal(expectedPolicyRuleList)
	require.NoError(t, err)
	var expectedPolicyRuleUnmarshalled CiliumNetworkPolicy
	err = json.Unmarshal(b, &expectedPolicyRuleUnmarshalled)
	require.NoError(t, err)
	expectedPolicyRuleUnmarshalled.Parse(logger, cmtypes.PolicyAnyCluster)
	require.Equal(t, *expectedPolicyRuleList, expectedPolicyRuleUnmarshalled)

	cnpl := CiliumNetworkPolicy{}
	err = json.Unmarshal(ciliumRuleList, &cnpl)
	require.NoError(t, err)
	require.Equal(t, *expectedPolicyRuleListWithLabel, cnpl)
}

func TestParseWithNodeSelector(t *testing.T) {
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

	logger := hivetest.Logger(t)

	// Expect CNP parse error because it's not allowed to have a NodeSelector.
	cnpl := CiliumNetworkPolicy{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: "default",
			Name:      "rule",
			UID:       uuidRule,
		},
		Spec: &rule,
	}
	_, err := cnpl.Parse(logger, cmtypes.PolicyAnyCluster)
	require.ErrorContains(t, err, "Invalid CiliumNetworkPolicy spec: rule cannot have NodeSelector")

	// CCNP parse is allowed to have a NodeSelector.
	ccnpl := CiliumClusterwideNetworkPolicy{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: "",
			Name:      "rule",
			UID:       uuidRule,
		},
		Spec: cnpl.Spec,
	}
	_, err = ccnpl.Parse(logger, cmtypes.PolicyAnyCluster)
	require.NoError(t, err)

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
	_, err = ccnplAsCNP.Parse(logger, cmtypes.PolicyAnyCluster)
	require.NoError(t, err)

	// Now test a CNP and CCNP with an EndpointSelector only.
	rule.EndpointSelector = prevEPSelector
	rule.NodeSelector = emptySelector

	// CNP and CCNP parse is allowed to have an EndpointSelector.
	_, err = cnpl.Parse(logger, cmtypes.PolicyAnyCluster)
	require.NoError(t, err)
	_, err = ccnpl.Parse(logger, cmtypes.PolicyAnyCluster)
	require.NoError(t, err)
	_, err = ccnplAsCNP.Parse(logger, cmtypes.PolicyAnyCluster)
	require.NoError(t, err)
}

func TestCiliumNodeInstanceID(t *testing.T) {
	require.Empty(t, (*CiliumNode)(nil).InstanceID())
	require.Empty(t, (&CiliumNode{}).InstanceID())
	require.Equal(t, "foo", (&CiliumNode{Spec: NodeSpec{InstanceID: "foo"}}).InstanceID())
	require.Equal(t, "foo", (&CiliumNode{Spec: NodeSpec{InstanceID: "foo", ENI: eniTypes.ENISpec{InstanceID: "bar"}}}).InstanceID())
	require.Equal(t, "bar", (&CiliumNode{Spec: NodeSpec{ENI: eniTypes.ENISpec{InstanceID: "bar"}}}).InstanceID())
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
		for b.Loop() {
			reflect.DeepEqual(r.Spec, o.Spec)
			reflect.DeepEqual(r.Specs, o.Specs)
		}
	})
	b.Run("Generated SpecEquals", func(b *testing.B) {
		b.ReportAllocs()
		b.ResetTimer()
		for b.Loop() {
			r.DeepEqual(o)
		}
	})
}

func TestGetIP(t *testing.T) {
	n := CiliumNode{
		Spec: NodeSpec{
			Addresses: []NodeAddress{
				{
					Type: addressing.NodeExternalIP,
					IP:   "192.0.2.3",
				},
			},
		},
	}
	ip := n.GetIP(false)
	// Return the only IP present
	require.NotNil(t, ip)
	require.True(t, ip.Equal(net.ParseIP("192.0.2.3")))

	n.Spec.Addresses = append(n.Spec.Addresses, NodeAddress{IP: "w.x.y.z", Type: addressing.NodeExternalIP})
	ip = n.GetIP(false)
	// Invalid external IPv4 address should return the existing external IPv4 address
	require.NotNil(t, ip)
	require.True(t, ip.Equal(net.ParseIP("192.0.2.3")))

	n.Spec.Addresses = append(n.Spec.Addresses, NodeAddress{IP: "198.51.100.2", Type: addressing.NodeInternalIP})
	ip = n.GetIP(false)
	// The next priority should be NodeInternalIP
	require.NotNil(t, ip)
	require.True(t, ip.Equal(net.ParseIP("198.51.100.2")))

	n.Spec.Addresses = append(n.Spec.Addresses, NodeAddress{IP: "2001:DB8::1", Type: addressing.NodeExternalIP})
	ip = n.GetIP(true)
	// The next priority should be NodeExternalIP and IPv6
	require.NotNil(t, ip)
	require.True(t, ip.Equal(net.ParseIP("2001:DB8::1")))

	n.Spec.Addresses = append(n.Spec.Addresses, NodeAddress{IP: "w.x.y.z", Type: addressing.NodeExternalIP})
	ip = n.GetIP(true)
	// Invalid external IPv6 address should return the existing external IPv6 address
	require.NotNil(t, ip)
	require.True(t, ip.Equal(net.ParseIP("2001:DB8::1")))

	n.Spec.Addresses = append(n.Spec.Addresses, NodeAddress{IP: "2001:DB8::2", Type: addressing.NodeInternalIP})
	ip = n.GetIP(true)
	// The next priority should be NodeInternalIP and IPv6
	require.NotNil(t, ip)
	require.True(t, ip.Equal(net.ParseIP("2001:DB8::2")))

	n.Spec.Addresses = append(n.Spec.Addresses, NodeAddress{IP: "198.51.100.2", Type: addressing.NodeInternalIP})
	ip = n.GetIP(false)
	// Should still return NodeInternalIP and IPv4
	require.NotNil(t, ip)
	require.True(t, ip.Equal(net.ParseIP("198.51.100.2")))

	n.Spec.Addresses = []NodeAddress{{IP: "w.x.y.z", Type: addressing.NodeExternalIP}}
	ip = n.GetIP(false)
	// Return a nil IP when no valid IPv4 addresses exist
	require.Nil(t, ip)
	ip = n.GetIP(true)
	// Return a nil IP when no valid IPv6 addresses exist
	require.Nil(t, ip)
}

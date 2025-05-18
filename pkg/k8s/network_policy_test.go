// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package k8s

import (
	"encoding/json"
	"fmt"
	"testing"

	"github.com/cilium/hive/hivetest"
	"github.com/stretchr/testify/require"
	"k8s.io/apimachinery/pkg/types"

	"github.com/cilium/cilium/pkg/annotation"
	cmtypes "github.com/cilium/cilium/pkg/clustermesh/types"
	"github.com/cilium/cilium/pkg/identity"
	k8sConst "github.com/cilium/cilium/pkg/k8s/apis/cilium.io"
	slim_corev1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/api/core/v1"
	slim_networkingv1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/api/networking/v1"
	slim_metav1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/apis/meta/v1"
	"github.com/cilium/cilium/pkg/k8s/slim/k8s/apis/util/intstr"
	"github.com/cilium/cilium/pkg/labels"
	"github.com/cilium/cilium/pkg/policy"
	"github.com/cilium/cilium/pkg/policy/api"
	testidentity "github.com/cilium/cilium/pkg/testutils/identity"
	"github.com/cilium/cilium/pkg/u8proto"
)

var (
	labelsA = labels.LabelArray{
		labels.NewLabel(k8sConst.PodNamespaceLabel, slim_metav1.NamespaceDefault, labels.LabelSourceK8s),
		labels.NewLabel("id", "a", labels.LabelSourceK8s),
	}.Sort()
	nidA = identity.NumericIdentity(1001)
	idA  = identity.NewIdentityFromLabelArray(nidA, labelsA)

	labelSelectorA = slim_metav1.LabelSelector{
		MatchLabels: map[string]string{
			"id": "a",
		},
	}

	labelsB = labels.LabelArray{
		labels.NewLabel(k8sConst.PodNamespaceLabel, slim_metav1.NamespaceDefault, labels.LabelSourceK8s),
		labels.NewLabel("id1", "b", labels.LabelSourceK8s),
		labels.NewLabel("id2", "c", labels.LabelSourceK8s),
	}.Sort()
	nidB           = identity.NumericIdentity(1002)
	idB            = identity.NewIdentityFromLabelArray(nidB, labelsB)
	labelSelectorB = slim_metav1.LabelSelector{
		MatchLabels: map[string]string{
			"id1": "b",
		},
	}

	labelsC = labels.LabelArray{
		labels.NewLabel(k8sConst.PodNamespaceLabel, slim_metav1.NamespaceDefault, labels.LabelSourceK8s),
		labels.NewLabel("id", "c", labels.LabelSourceK8s),
	}.Sort()
	nidC = identity.NumericIdentity(1003)
	idC  = identity.NewIdentityFromLabelArray(nidC, labelsC)

	labelSelectorC = slim_metav1.LabelSelector{
		MatchLabels: map[string]string{
			"id": "c",
		},
	}

	labelsOther = labels.LabelArray{
		labels.NewLabel("io.cilium.k8s.namespace.labels.kubernetes.io/metadata.name", "other", labels.LabelSourceK8s),
		labels.NewLabel(k8sConst.PodNamespaceLabel, "other", labels.LabelSourceK8s),
		labels.NewLabel("id", "other", labels.LabelSourceK8s),
	}.Sort()
	nidOther = identity.NumericIdentity(1004)
	idOther  = identity.NewIdentityFromLabelArray(nidOther, labelsOther)

	allIDs = []*identity.Identity{idA, idB, idC, idOther}

	flowAToB = policy.Flow{
		From:  idA,
		To:    idB,
		Proto: u8proto.TCP,
		Dport: 80,
	}
	flowBToA = policy.Flow{
		From:  idB,
		To:    idA,
		Proto: u8proto.TCP,
		Dport: 80,
	}
	flowAToOther = policy.Flow{
		From:  idA,
		To:    idOther,
		Proto: u8proto.TCP,
		Dport: 80,
	}
	flowOtherToA = policy.Flow{
		From:  idOther,
		To:    idA,
		Proto: u8proto.TCP,
		Dport: 80,
	}
	flowAToC = policy.Flow{
		From:  idA,
		To:    idC,
		Proto: u8proto.TCP,
		Dport: 80,
	}
	flowCToA = policy.Flow{
		From:  idC,
		To:    idA,
		Proto: u8proto.TCP,
		Dport: 80,
	}
	port80 = slim_networkingv1.NetworkPolicyPort{
		Port: &intstr.IntOrString{
			Type:   intstr.Int,
			IntVal: 80,
		},
	}

	int8090        = int32(8090)
	port8080to8090 = slim_networkingv1.NetworkPolicyPort{
		Port: &intstr.IntOrString{
			Type:   intstr.Int,
			IntVal: 8080,
		},
		EndPort: &int8090,
	}
)

func testNewPolicyRepository(t *testing.T, initialIDs []*identity.Identity) *policy.Repository {
	idmap := identity.IdentityMap{}
	for _, id := range initialIDs {
		idmap[id.ID] = id.LabelArray
	}
	logger := hivetest.Logger(t)
	repo := policy.NewPolicyRepository(logger, idmap, nil, nil, nil, api.NewPolicyMetricsNoop())
	repo.GetSelectorCache().SetLocalIdentityNotifier(testidentity.NewDummyIdentityNotifier())
	return repo
}

// validateNetworkPolicy takes a repository and validates
// that the set of flows are allowed and denied as expected.
func validateNetworkPolicy(t *testing.T, repo *policy.Repository, allowFlows, denyFlows []policy.Flow) {
	t.Helper()
	logger := hivetest.Logger(t)

	for i, allow := range allowFlows {
		verdict, err := policy.LookupFlow(logger, repo, allow, nil, nil)
		require.NoError(t, err, "Looking up allow flow %i failed", i)
		require.Equal(t, api.Allowed, verdict, "Verdict for allow flow %d must match", i)
	}

	for i, allow := range denyFlows {
		verdict, err := policy.LookupFlow(logger, repo, allow, nil, nil)
		require.NoError(t, err, "Looking up deny flow %i failed", i)
		require.Equal(t, api.Denied, verdict, "Verdict for deny flow %d must match", i)
	}
}

func TestParseNetworkPolicy(t *testing.T) {

	// The network policies are normalized and compared for rule sanity:
	// - always the same endpoint selector
	// - always the same name and namespace

	for i, tc := range []struct {
		name string
		in   slim_networkingv1.NetworkPolicySpec
		out  api.Rule
	}{
		{
			name: "ingress pod + port",
			in: slim_networkingv1.NetworkPolicySpec{
				Ingress: []slim_networkingv1.NetworkPolicyIngressRule{
					{
						From: []slim_networkingv1.NetworkPolicyPeer{
							{
								PodSelector: &slim_metav1.LabelSelector{
									MatchLabels: map[string]string{
										"foo3": "bar3",
										"foo4": "bar4",
									},
								},
							},
						},
						Ports: []slim_networkingv1.NetworkPolicyPort{
							{
								Port: &intstr.IntOrString{
									Type:   intstr.Int,
									IntVal: 80,
								},
							},
						},
					},
				},
			},
			out: api.Rule{
				Ingress: []api.IngressRule{{
					IngressCommonRule: api.IngressCommonRule{
						FromEndpoints: []api.EndpointSelector{
							api.NewESFromLabels(
								labels.NewLabel(k8sConst.PodNamespaceLabel, slim_metav1.NamespaceDefault, labels.LabelSourceK8s),
								labels.NewLabel("foo3", "bar3", labels.LabelSourceK8s),
								labels.NewLabel("foo4", "bar4", labels.LabelSourceK8s),
							),
						},
					},
					ToPorts: api.PortRules{{
						Ports: []api.PortProtocol{{
							Port:     "80",
							Protocol: "TCP",
						}},
					}},
				}},
			},
		},
		{
			name: "ingress only port",
			in: slim_networkingv1.NetworkPolicySpec{
				Ingress: []slim_networkingv1.NetworkPolicyIngressRule{
					{
						Ports: []slim_networkingv1.NetworkPolicyPort{
							{
								Port: &intstr.IntOrString{
									Type:   intstr.Int,
									IntVal: 80,
								},
							},
						},
					},
				},
			},
			out: api.Rule{
				Ingress: []api.IngressRule{{
					IngressCommonRule: api.IngressCommonRule{
						FromEndpoints: []api.EndpointSelector{api.NewESFromLabels()},
					},
					ToPorts: api.PortRules{{
						Ports: []api.PortProtocol{{
							Port:     "80",
							Protocol: "TCP",
						}},
					}},
				}},
			},
		},
		{
			name: "ingress pod + namespace + port",
			in: slim_networkingv1.NetworkPolicySpec{
				Ingress: []slim_networkingv1.NetworkPolicyIngressRule{
					{
						From: []slim_networkingv1.NetworkPolicyPeer{
							{
								PodSelector: &slim_metav1.LabelSelector{
									MatchLabels: map[string]string{
										"foo3": "bar3",
										"foo4": "bar4",
									},
								},
								NamespaceSelector: &slim_metav1.LabelSelector{
									MatchLabels: map[string]string{
										"nsfoo": "nsbar",
									},
								},
							},
						},
						Ports: []slim_networkingv1.NetworkPolicyPort{
							{
								Port: &intstr.IntOrString{
									Type:   intstr.Int,
									IntVal: 80,
								},
							},
						},
					},
				},
			},
			out: api.Rule{
				Ingress: []api.IngressRule{{
					IngressCommonRule: api.IngressCommonRule{
						FromEndpoints: []api.EndpointSelector{
							api.NewESFromLabels(
								labels.NewLabel("foo3", "bar3", labels.LabelSourceK8s),
								labels.NewLabel("foo4", "bar4", labels.LabelSourceK8s),
								labels.NewLabel("io.cilium.k8s.namespace.labels.nsfoo", "nsbar", labels.LabelSourceK8s),
							),
						},
					},
					ToPorts: api.PortRules{{
						Ports: []api.PortProtocol{{
							Port:     "80",
							Protocol: "TCP",
						}},
					}},
				}},
			},
		},
		{
			name: "ingress default deny",
			in: slim_networkingv1.NetworkPolicySpec{
				PolicyTypes: []slim_networkingv1.PolicyType{"Ingress"},
			},
			out: api.Rule{
				Ingress: []api.IngressRule{{
					IngressCommonRule: api.IngressCommonRule{},
				}},
			},
		},
		{
			name: "ingress allow all",
			in: slim_networkingv1.NetworkPolicySpec{
				Ingress: []slim_networkingv1.NetworkPolicyIngressRule{{}},
			},
			out: api.Rule{
				Ingress: []api.IngressRule{{
					IngressCommonRule: api.IngressCommonRule{
						FromEndpoints: []api.EndpointSelector{api.NewESFromLabels()},
					},
				}},
			},
		},
	} {
		t.Run(fmt.Sprintf("%d-%s", i, tc.name), func(t *testing.T) {
			np := &slim_networkingv1.NetworkPolicy{
				ObjectMeta: slim_metav1.ObjectMeta{
					Namespace: "default",
					Name:      "testing",
					UID:       "test-uid",
					Labels: map[string]string{
						"label1": "value1",
					},
				},
				Spec: tc.in,
			}

			np.Spec.PodSelector = slim_metav1.LabelSelector{
				MatchLabels: map[string]string{
					"foo1": "bar1",
					"foo2": "bar2",
				}}

			tc.out.EndpointSelector = api.NewESFromLabels(
				labels.NewLabel(k8sConst.PodNamespaceLabel, slim_metav1.NamespaceDefault, labels.LabelSourceK8s),
				labels.NewLabel("foo1", "bar1", labels.LabelSourceK8s),
				labels.NewLabel("foo2", "bar2", labels.LabelSourceK8s),
			)

			tc.out.Labels = labels.ParseLabelArray(
				"k8s:io.cilium.k8s.policy.derived-from=NetworkPolicy",
				"k8s:io.cilium.k8s.policy.name=testing",
				"k8s:io.cilium.k8s.policy.namespace=default",
				"k8s:io.cilium.k8s.policy.uid=test-uid",
			)

			if tc.out.Egress == nil {
				tc.out.Egress = []api.EgressRule{}
			}

			err := tc.out.Sanitize()
			require.NoError(t, err)

			rules, err := ParseNetworkPolicy(hivetest.Logger(t), cmtypes.PolicyAnyCluster, np)
			require.NoError(t, err)
			require.Len(t, rules, 1)
			require.Equal(t, &tc.out, rules[0])
		})
	}
}

func TestParseNetworkPolicyMultipleSelectors(t *testing.T) {

	// Rule with multiple selectors in egress and ingress
	ex1 := []byte(`{
"kind":"NetworkPolicy",
"apiVersion":"networking.k8s.io/v1",
"metadata":{
  "name":"ingress-multiple-selectors"
},
"spec":{
  "podSelector":{
    "matchLabels":{
      "id":"a"
    }
  },
  "egress":[
    {
      "ports":[
        {
          "protocol":"TCP",
          "port":80
        }
      ],
      "to":[
        {
          "podSelector":{
            "matchLabels":{
              "id1":"b"
            }
          }
        },
        {
          "podSelector":{
            "matchLabels":{
              "id":"c"
            }
          }
        }
      ]
    }
  ],
  "ingress":[
    {
      "from":[
        {
          "podSelector":{
            "matchLabels":{
              "id":"other"
            }
          },
          "namespaceSelector":{
            "matchLabels":{
			  "kubernetes.io/metadata.name":"other"
            }
          }
        },
        {
          "podSelector":{
            "matchLabels":{
              "id":"c"
            }
          }
        }
      ]
    }
  ]
}
}`)

	// In this policy, A can talk to B and C,
	// but only C and Other can talk to A
	np := slim_networkingv1.NetworkPolicy{}
	err := json.Unmarshal(ex1, &np)
	require.NoError(t, err)
	repo := parseAndAddRules(t, &np)

	allowedFlows := []policy.Flow{
		flowAToB,
		flowAToC,
		flowCToA,
		flowOtherToA,
	}

	deniedFlows := []policy.Flow{
		flowBToA,
		flowAToOther,
	}

	validateNetworkPolicy(t, repo, allowedFlows, deniedFlows)
}

func TestParseNetworkPolicyNoSelectors(t *testing.T) {

	// Ingress with neither pod nor namespace selector set.
	ex1 := []byte(`{
"kind": "NetworkPolicy",
"apiVersion": "networking.k8s.io/v1",
"metadata": {
  "name": "ingress-cidr-test",
  "namespace": "myns",
  "uid": "11bba160-ddca-11e8-b697-0800273b04ff"
},
"spec": {
  "podSelector": {
    "matchLabels": {
      "role": "backend"
    }
  },
  "ingress": [
    {
      "from": [
        {
          "ipBlock": {
            "cidr": "10.0.0.0/8",
	          "except": [
	            "10.96.0.0/12"
	          ]
          }
        }
      ]
    }
  ]
}
}`)

	fromEndpoints := labels.LabelArray{
		labels.NewLabel(k8sConst.PodNamespaceLabel, "myns", labels.LabelSourceK8s),
		labels.NewLabel("role", "backend", labels.LabelSourceK8s),
	}

	epSelector := api.NewESFromLabels(fromEndpoints...)
	np := slim_networkingv1.NetworkPolicy{}
	err := json.Unmarshal(ex1, &np)
	require.NoError(t, err)

	expectedRule := api.NewRule().
		WithEndpointSelector(epSelector).
		WithIngressRules([]api.IngressRule{
			{
				IngressCommonRule: api.IngressCommonRule{
					FromCIDRSet: []api.CIDRRule{
						{
							Cidr: api.CIDR("10.0.0.0/8"),
							ExceptCIDRs: []api.CIDR{
								"10.96.0.0/12",
							},
						},
					},
				},
			},
		}).
		WithEgressRules([]api.EgressRule{}).
		WithLabels(labels.ParseLabelArray(
			"k8s:"+k8sConst.PolicyLabelName+"=ingress-cidr-test",
			"k8s:"+k8sConst.PolicyLabelUID+"=11bba160-ddca-11e8-b697-0800273b04ff",
			"k8s:"+k8sConst.PolicyLabelNamespace+"=myns",
			"k8s:"+k8sConst.PolicyLabelDerivedFrom+"="+resourceTypeNetworkPolicy,
		))

	expectedRule.Sanitize()

	expectedRules := api.Rules{
		expectedRule,
	}

	rules, err := ParseNetworkPolicy(hivetest.Logger(t), cmtypes.PolicyAnyCluster, &np)
	require.NoError(t, err)
	require.NotNil(t, rules)
	require.Equal(t, expectedRules, rules)
}

func TestParseNetworkPolicyEgress(t *testing.T) {
	netPolicy := &slim_networkingv1.NetworkPolicy{
		Spec: slim_networkingv1.NetworkPolicySpec{
			PodSelector: slim_metav1.LabelSelector{
				MatchLabels: map[string]string{
					"id": "a",
				},
			},
			Egress: []slim_networkingv1.NetworkPolicyEgressRule{
				{
					To: []slim_networkingv1.NetworkPolicyPeer{
						{
							PodSelector: &slim_metav1.LabelSelector{
								MatchLabels: map[string]string{
									"id1": "b",
								},
							},
						},
					},
					Ports: []slim_networkingv1.NetworkPolicyPort{
						{
							Port: &intstr.IntOrString{
								Type:   intstr.Int,
								IntVal: 80,
							},
						},
					},
				},
			},
		},
	}

	flowAToB81 := flowAToB
	flowAToB81.Dport = 81

	repo := parseAndAddRules(t, netPolicy)
	validateNetworkPolicy(t, repo,
		[]policy.Flow{
			flowAToB,
		}, []policy.Flow{
			flowAToB81,
			flowAToC,
			flowAToOther,
		})
}

func parseAndAddRules(t *testing.T, ps ...*slim_networkingv1.NetworkPolicy) *policy.Repository {
	t.Helper()
	repo := testNewPolicyRepository(t, allIDs)

	for i, p := range ps {
		if p.Name == "" {
			p.Name = fmt.Sprintf("policy-%d", i)
		}
		if p.Namespace == "" {
			p.Namespace = "default"
		}
		rules, err := ParseNetworkPolicy(hivetest.Logger(t), cmtypes.PolicyAnyCluster, p)
		require.NoError(t, err)
		rev := repo.GetRevision()
		_, id := repo.MustAddList(rules)
		require.Equal(t, rev+1, id)
	}
	return repo
}

func TestParseNetworkPolicyEgressAllowAll(t *testing.T) {
	repo := parseAndAddRules(t,
		// pod A: allow all egress
		&slim_networkingv1.NetworkPolicy{Spec: slim_networkingv1.NetworkPolicySpec{
			PodSelector: labelSelectorA,
			Egress: []slim_networkingv1.NetworkPolicyEgressRule{
				{
					To: []slim_networkingv1.NetworkPolicyPeer{},
				},
			},
		}},
		// pod B: deny all egress
		&slim_networkingv1.NetworkPolicy{Spec: slim_networkingv1.NetworkPolicySpec{
			PodSelector: labelSelectorB,
			PolicyTypes: []slim_networkingv1.PolicyType{"Egress"},
		}},
	)

	validateNetworkPolicy(t, repo,
		[]policy.Flow{
			flowAToB,
			flowAToC,
		}, []policy.Flow{
			flowBToA,
			flowOtherToA,
		})
}

func TestParseNetworkPolicyEgressL4AllowAll(t *testing.T) {
	repo := parseAndAddRules(t, &slim_networkingv1.NetworkPolicy{
		Spec: slim_networkingv1.NetworkPolicySpec{
			PodSelector: labelSelectorA,
			Egress: []slim_networkingv1.NetworkPolicyEgressRule{
				{
					Ports: []slim_networkingv1.NetworkPolicyPort{port80},
					To:    []slim_networkingv1.NetworkPolicyPeer{},
				},
			},
		},
	})
	flowAToC90 := flowAToC
	flowAToC90.Dport = 90

	validateNetworkPolicy(t, repo,
		[]policy.Flow{flowAToC},
		[]policy.Flow{flowAToC90})

}

func TestParseNetworkPolicyEgressL4PortRangeAllowAll(t *testing.T) {
	repo := parseAndAddRules(t, &slim_networkingv1.NetworkPolicy{
		Spec: slim_networkingv1.NetworkPolicySpec{
			PodSelector: labelSelectorA,
			Egress: []slim_networkingv1.NetworkPolicyEgressRule{
				{
					Ports: []slim_networkingv1.NetworkPolicyPort{port8080to8090},
					To:    []slim_networkingv1.NetworkPolicyPeer{},
				},
			},
		},
	})

	for port, expected := range map[uint16]api.Decision{
		8080: api.Allowed,
		8085: api.Allowed,
		8090: api.Allowed,
		8091: api.Denied,
	} {
		flow := flowAToC
		flow.Dport = port

		verdict, err := policy.LookupFlow(hivetest.Logger(t), repo, flow, nil, nil)
		require.NoError(t, err)
		require.Equal(t, expected, verdict, "Port %d", port)
	}
}

func TestParseNetworkPolicyIngressAllowAll(t *testing.T) {
	repo := parseAndAddRules(t,
		// pod a: deny all ingress
		&slim_networkingv1.NetworkPolicy{Spec: slim_networkingv1.NetworkPolicySpec{
			PodSelector: labelSelectorA,
			PolicyTypes: []slim_networkingv1.PolicyType{"Ingress"},
		}},
		// pod b: allow all: empty rule
		&slim_networkingv1.NetworkPolicy{Spec: slim_networkingv1.NetworkPolicySpec{
			PodSelector: labelSelectorB,
			Ingress: []slim_networkingv1.NetworkPolicyIngressRule{
				{},
			},
		}},
		// pod c: allow all
		&slim_networkingv1.NetworkPolicy{Spec: slim_networkingv1.NetworkPolicySpec{
			PodSelector: labelSelectorC,
			Ingress: []slim_networkingv1.NetworkPolicyIngressRule{
				{
					From: []slim_networkingv1.NetworkPolicyPeer{},
				},
			},
		}})

	validateNetworkPolicy(t, repo, []policy.Flow{
		flowAToB,
		flowAToC,
	}, []policy.Flow{
		flowBToA,
	})
}

func TestParseNetworkPolicyIngressL4AllowAll(t *testing.T) {
	repo := parseAndAddRules(t, &slim_networkingv1.NetworkPolicy{
		Spec: slim_networkingv1.NetworkPolicySpec{
			PodSelector: labelSelectorC,
			Ingress: []slim_networkingv1.NetworkPolicyIngressRule{
				{
					Ports: []slim_networkingv1.NetworkPolicyPort{port80},
					From:  []slim_networkingv1.NetworkPolicyPeer{},
				},
			},
		},
	})
	flowAToC90 := flowAToC
	flowAToC90.Dport = 90

	validateNetworkPolicy(t, repo,
		[]policy.Flow{
			flowAToC,
		}, []policy.Flow{
			flowAToC90,
		})
}

func TestParseNetworkPolicyNamedPort(t *testing.T) {
	netPolicy := &slim_networkingv1.NetworkPolicy{
		Spec: slim_networkingv1.NetworkPolicySpec{
			Ingress: []slim_networkingv1.NetworkPolicyIngressRule{
				{
					Ports: []slim_networkingv1.NetworkPolicyPort{
						{
							Port: &intstr.IntOrString{
								Type:   intstr.String,
								StrVal: "port-80",
							},
						},
					},
				},
			},
		},
	}

	rules, err := ParseNetworkPolicy(hivetest.Logger(t), cmtypes.PolicyAnyCluster, netPolicy)
	require.NoError(t, err)
	require.Len(t, rules, 1)
}

func TestParseNetworkPolicyEmptyPort(t *testing.T) {
	netPolicy := &slim_networkingv1.NetworkPolicy{
		Spec: slim_networkingv1.NetworkPolicySpec{
			Ingress: []slim_networkingv1.NetworkPolicyIngressRule{
				{
					Ports: []slim_networkingv1.NetworkPolicyPort{
						{},
					},
				},
			},
		},
	}

	rules, err := ParseNetworkPolicy(hivetest.Logger(t), cmtypes.PolicyAnyCluster, netPolicy)
	require.NoError(t, err)
	require.Len(t, rules, 1)
	require.Len(t, rules[0].Ingress, 1)
	require.Len(t, rules[0].Ingress[0].ToPorts, 1)
	ports := rules[0].Ingress[0].ToPorts[0].Ports
	require.Len(t, ports, 1)
	require.Equal(t, "0", ports[0].Port)
	require.Equal(t, api.ProtoTCP, ports[0].Protocol)
}

func TestParsePorts(t *testing.T) {
	rules := parsePorts([]slim_networkingv1.NetworkPolicyPort{
		{},
	})
	require.Len(t, rules, 1)
	require.Len(t, rules[0].Ports, 1)
	require.Equal(t, "0", rules[0].Ports[0].Port)
	require.Equal(t, api.ProtoTCP, rules[0].Ports[0].Protocol)
}

func TestParseNetworkPolicyUnknownProto(t *testing.T) {
	unknownProtocol := slim_corev1.Protocol("unknown")
	netPolicy := &slim_networkingv1.NetworkPolicy{
		Spec: slim_networkingv1.NetworkPolicySpec{
			Ingress: []slim_networkingv1.NetworkPolicyIngressRule{
				{
					Ports: []slim_networkingv1.NetworkPolicyPort{
						{
							Port: &intstr.IntOrString{
								Type:   intstr.String,
								StrVal: "port-80",
							},
							Protocol: &unknownProtocol,
						},
					},
				},
			},
		},
	}

	rules, err := ParseNetworkPolicy(hivetest.Logger(t), cmtypes.PolicyAnyCluster, netPolicy)
	require.Error(t, err)
	require.Empty(t, rules)
}

func TestParseNetworkPolicyEmptyFrom(t *testing.T) {
	// From missing, all sources should be allowed
	netPolicy1 := &slim_networkingv1.NetworkPolicy{
		Spec: slim_networkingv1.NetworkPolicySpec{
			PodSelector: slim_metav1.LabelSelector{
				MatchLabels: map[string]string{
					"id": "a",
				},
			},
			Ingress: []slim_networkingv1.NetworkPolicyIngressRule{
				{},
			},
		},
	}

	repo := parseAndAddRules(t, netPolicy1)
	validateNetworkPolicy(t, repo, []policy.Flow{
		flowBToA,
		flowCToA,
		flowOtherToA,
	}, nil)
}

func TestParseNetworkPolicyDenyAll(t *testing.T) {
	// For backwards-compatibility, a policy with no statements whatsoever
	// is assumed to be an ingress-only deny-all
	netPolicy1 := &slim_networkingv1.NetworkPolicy{
		Spec: slim_networkingv1.NetworkPolicySpec{
			PodSelector: slim_metav1.LabelSelector{
				MatchLabels: map[string]string{},
			},
		},
	}

	repo := parseAndAddRules(t, netPolicy1)
	validateNetworkPolicy(t, repo,
		[]policy.Flow{
			flowAToOther,
		},
		[]policy.Flow{
			flowAToB,
			flowBToA,
			flowAToC,
			flowCToA,
			flowOtherToA,
		})

}

func TestParseNetworkPolicyNoIngress(t *testing.T) {
	netPolicy := &slim_networkingv1.NetworkPolicy{
		Spec: slim_networkingv1.NetworkPolicySpec{
			PodSelector: slim_metav1.LabelSelector{
				MatchLabels: map[string]string{
					"foo1": "bar1",
					"foo2": "bar2",
				},
			},
		},
	}

	rules, err := ParseNetworkPolicy(hivetest.Logger(t), cmtypes.PolicyAnyCluster, netPolicy)
	require.NoError(t, err)
	require.Len(t, rules, 1)
}

func TestNetworkPolicyExamples(t *testing.T) {

	allIDs := []*identity.Identity{}

	nextID := identity.NumericIdentity(1000)
	makePod := func(namespace string, podLabels, nsLabels map[string]string) *identity.Identity {
		lbls := labels.LabelArray{
			labels.NewLabel(k8sConst.PodNamespaceLabel, namespace, labels.LabelSourceK8s),
		}
		for k, v := range podLabels {
			lbls = append(lbls, labels.NewLabel(k, v, labels.LabelSourceK8s))
		}

		for k, v := range nsLabels {
			lbls = append(lbls, labels.NewLabel("io.cilium.k8s.namespace.labels."+k, v, labels.LabelSourceK8s))
		}
		lbls.Sort()
		nextID++
		id := identity.NewIdentity(nextID, lbls.Labels())
		allIDs = append(allIDs, id)
		return id
	}

	tcpFlow := func(src, dst *identity.Identity, port uint16) policy.Flow {
		return policy.Flow{
			From:  src,
			To:    dst,
			Proto: u8proto.TCP,
			Dport: port,
		}
	}
	udpFlow := func(src, dst *identity.Identity, port uint16) policy.Flow {
		return policy.Flow{
			From:  src,
			To:    dst,
			Proto: u8proto.UDP,
			Dport: port,
		}
	}

	frontend := makePod("myns", map[string]string{"role": "frontend"}, nil)
	backend := makePod("myns", map[string]string{"role": "backend"}, nil)
	db := makePod("myns", map[string]string{"role": "db"}, nil)
	nsBob := makePod("nsBob", map[string]string{"role": "frontend"}, map[string]string{"user": "bob"})
	nsSally := makePod("nsSally", map[string]string{"role": "frontend"}, map[string]string{"user": "sally"})

	makeRepo := func(pol ...[]byte) *policy.Repository {
		t.Helper()
		repo := testNewPolicyRepository(t, allIDs)

		for i, p := range pol {
			np := slim_networkingv1.NetworkPolicy{}
			err := json.Unmarshal(p, &np)
			require.NoError(t, err, "Failed to unmarshal policy %d", i)

			rules, err := ParseNetworkPolicy(hivetest.Logger(t), cmtypes.PolicyAnyCluster, &np)
			require.NoError(t, err, "Failed to parse policy %d", i)
			require.Len(t, rules, 1)

			repo.MustAddList(rules)
		}
		return repo
	}

	// Example 1a: Only allow traffic from frontend pods on TCP port 6379 to
	// backend pods in the same namespace `myns`
	ex1 := []byte(`{
  "kind": "NetworkPolicy",
  "apiVersion": "networking.k8s.io/v1",
  "metadata": {
    "name": "allow-frontend",
    "namespace": "myns"
  },
  "spec": {
    "podSelector": {
      "matchLabels": {
        "role": "backend"
      }
    },
    "ingress": [
      {
        "from": [
          {
            "podSelector": {
              "matchLabels": {
                "role": "frontend"
              }
            }
          }
        ],
        "ports": [
          {
            "protocol": "TCP",
            "port": 6379
          }
        ]
      }
    ]
  }
}`)

	repo := makeRepo(ex1)
	validateNetworkPolicy(t, repo,
		[]policy.Flow{
			tcpFlow(frontend, backend, 6379),
		}, []policy.Flow{
			// different proto and port
			udpFlow(frontend, backend, 6379),
			tcpFlow(frontend, backend, 6378),

			// correct port + proto, different namespace
			tcpFlow(nsBob, backend, 6379),
			tcpFlow(nsSally, backend, 6379),

			// correct port + proto + ns, different labels
			tcpFlow(db, backend, 6379),
		})

	// Example 1b: Only allow traffic from frontend pods to backend pods
	// in the same namespace `myns`
	ex1b := []byte(`{
		  "kind": "NetworkPolicy",
		  "apiVersion": "networking.k8s.io/v1",
		  "metadata": {
		    "name": "allow-frontend",
		    "namespace": "myns"
		  },
		  "spec": {
		    "podSelector": {
		      "matchLabels": {
		        "role": "backend"
		      }
		    },
		    "ingress": [
		      {
		        "from": [
		          {
		            "podSelector": {
		              "matchLabels": {
		                "role": "frontend"
		              }
		            }
		          }
		        ]
		      },{
		        "ports": [
		          {
		            "protocol": "TCP",
		            "port": 6379
		          }
		        ]
		      }
		    ]
		  }
		}`)

	repo = makeRepo(ex1b)
	validateNetworkPolicy(t, repo,
		[]policy.Flow{
			// allows all from frontend
			tcpFlow(frontend, backend, 6379),
			tcpFlow(frontend, backend, 1),
			udpFlow(frontend, backend, 1),

			// allows all for TCP 6379
			tcpFlow(nsBob, backend, 6379),
			tcpFlow(nsSally, backend, 6379),
			tcpFlow(db, backend, 6379),
		}, []policy.Flow{
			// denies in-namespace except tcp 6379
			udpFlow(db, backend, 6379),
			tcpFlow(db, backend, 1),

			// denies out-of-namespace (except 6379)
			tcpFlow(nsBob, backend, 1),
			tcpFlow(nsSally, backend, 1),
		})

	// Example 2a: Allow TCP 443 from any source in Bob's namespaces.
	ex2 := []byte(`{
		  "kind": "NetworkPolicy",
		  "apiVersion": "networking.k8s.io/v1",
		  "metadata": {
		  	"namespace": "myns",
		    "name": "allow-tcp-443"
		  },
		  "spec": {
		    "podSelector": {
		      "matchLabels": {
		        "role": "frontend"
		      }
		    },
		    "ingress": [
		      {
		        "ports": [
		          {
		            "protocol": "TCP",
		            "port": 443
		          }
		        ],
		        "from": [
		          {
		            "namespaceSelector": {
		              "matchLabels": {
		                "user": "bob"
		              }
		            }
		          }
		        ]
		      }
		    ]
		  }
		}`)

	repo = makeRepo(ex2)
	validateNetworkPolicy(t, repo,
		[]policy.Flow{
			// allows nsbob 443, rejects everything else
			tcpFlow(nsBob, frontend, 443),
		}, []policy.Flow{
			tcpFlow(nsBob, frontend, 80),
			udpFlow(nsBob, frontend, 443),
			tcpFlow(nsSally, frontend, 443),
			tcpFlow(backend, frontend, 443),
			tcpFlow(db, frontend, 443),
		})

	// Example 3: Allow all traffic to all pods in this namespace.
	ex3 := []byte(`{
		  "kind": "NetworkPolicy",
		  "apiVersion": "networking.k8s.io/v1",
		  "metadata": {
		    "name": "allow-all",
			"namespace": "myns"
		  },
		  "spec": {
		    "podSelector": null,
		    "ingress": [
		      {
		      }
		    ]
		  }
		}`)
	repo = makeRepo(ex3)
	validateNetworkPolicy(t, repo,
		[]policy.Flow{
			// allows all
			tcpFlow(nsBob, frontend, 443),
			tcpFlow(nsBob, backend, 443),
			tcpFlow(nsBob, db, 443),
			tcpFlow(frontend, backend, 443),
			tcpFlow(db, backend, 443),
		}, []policy.Flow{})

	// Example 4a: Example 4 is similar to example 2 but we will add both network
	// policies to see if the rules are additive for the same podSelector.
	ex4a := []byte(`{
		  "kind": "NetworkPolicy",
		  "apiVersion": "networking.k8s.io/v1",
		  "metadata": {
		    "name": "allow-tcp-8080",
			"namespace": "myns"
		  },
		  "spec": {
		    "podSelector": {
		      "matchLabels": {
		        "role": "frontend"
		      }
		    },
		    "ingress": [
		      {
		        "ports": [
		          {
		            "protocol": "UDP",
		            "port": 8080
		          }
		        ],
		        "from": [
		          {
		            "namespaceSelector": {
		              "matchLabels": {
		                "user": "bob"
		              }
		            }
		          }
		        ]
		      }
		    ]
		  }
		}`)

	// Example 4b: Example 4 is similar to example 2 but we will add both network
	// policies to see if the rules are additive for the same podSelector.
	ex4b := []byte(`{
		  "kind": "NetworkPolicy",
		  "apiVersion": "networking.k8s.io/v1",
		  "metadata": {
		    "name": "allow-tcp-8080",
			"namespace": "myns"
		  },
		  "spec": {
		    "podSelector": {
		      "matchLabels": {
		        "role": "frontend"
		      }
		    },
		    "ingress": [
		      {
		        "ports": [
		          {
		            "protocol": "UDP",
		            "port": 8080
		          }
		        ]
		      },{
		        "from": [
		          {
		            "namespaceSelector": {
		              "matchLabels": {
		                "user": "bob"
		              }
		            }
		          }
		        ]
		      }
		    ]
		  }
		}`)

	repo = makeRepo(ex4a, ex4b)

	validateNetworkPolicy(t, repo,
		[]policy.Flow{
			// allows all from bob
			udpFlow(nsBob, frontend, 8080),
			udpFlow(nsBob, frontend, 8081),

			// allows udp 8080 from all
			udpFlow(nsSally, frontend, 8080),
			udpFlow(backend, frontend, 8080),
			udpFlow(db, frontend, 8080),
		}, []policy.Flow{

			// denies udp 8081 from all except bob
			udpFlow(nsSally, frontend, 8081),
			udpFlow(backend, frontend, 8081),
			udpFlow(db, frontend, 8081),
		})

	// Example 5: Some policies with match expressions.
	ex5 := []byte(`{
		  "kind": "NetworkPolicy",
		  "apiVersion": "networking.k8s.io/v1",
		  "metadata": {
		    "name": "allow-tcp-8080",
		    "namespace": "expressions"
		  },
		  "spec": {
		    "podSelector": {
		      "matchLabels": {
		        "component": "redis"
		      },
		      "matchExpressions": [
		        {
		          "key": "tier",
		          "operator": "In",
		          "values": [
		            "cache"
		          ]
		        },
		        {
		          "key": "environment",
		          "operator": "NotIn",
		          "values": [
		            "dev"
		          ]
		        }
		      ]
		    },
		    "ingress": [
		      {
		        "ports": [
		          {
		            "protocol": "UDP",
		            "port": 8080
		          }
		        ],
		        "from": [
		          {
		            "namespaceSelector": {
		              "matchLabels": {
		                "component": "redis"
		              },
		              "matchExpressions": [
		                {
		                  "key": "tier",
		                  "operator": "In",
		                  "values": [
		                    "cache"
		                  ]
		                },
		                {
		                  "key": "environment",
		                  "operator": "NotIn",
		                  "values": [
		                    "dev"
		                  ]
		                }
		              ]
		            }
		          }
		        ]
		      }
		    ]
		  }
		}`)

	defaultDeny := []byte(`
	{
		  "kind": "NetworkPolicy",
		  "apiVersion": "networking.k8s.io/v1",
		  "metadata": {
		    "name": "ingress-default-deny",
		    "namespace": "expressions"
		  },
		  "spec": {
		    "podSelector": {},
			"policyTypes": ["Ingress"]
		  }
	}`)

	// reset IDs
	allIDs = []*identity.Identity{}

	redisCacheDev := makePod("expressions", map[string]string{
		"component":   "redis",
		"tier":        "cache",
		"environment": "dev",
	}, nil)

	redisCacheProd := makePod("expressions", map[string]string{
		"component":   "redis",
		"tier":        "cache",
		"environment": "prod",
	}, nil)

	redisCacheDevOther := makePod("other", map[string]string{
		"component": "monitoring",
	}, map[string]string{
		"component":   "redis",
		"tier":        "cache",
		"environment": "dev",
	})
	redisCacheProdOther := makePod("other", map[string]string{
		"component": "monitoring",
	}, map[string]string{
		"component":   "redis",
		"tier":        "cache",
		"environment": "prod",
	})

	repo = makeRepo(defaultDeny, ex5)

	// Policy allows FROM all namespaces with the desired labels
	// TO pods with the desired labels
	validateNetworkPolicy(t, repo, []policy.Flow{
		udpFlow(redisCacheProdOther, redisCacheProd, 8080),
	}, []policy.Flow{
		udpFlow(redisCacheDevOther, redisCacheProd, 8080),
		udpFlow(redisCacheDev, redisCacheProd, 8080),

		// policy does not apply to redisCacheDev, only redisCacheProd,
		// so default-deny should take effect
		udpFlow(redisCacheProdOther, redisCacheDev, 8080),
		udpFlow(redisCacheDevOther, redisCacheDev, 8080),
		udpFlow(redisCacheProd, redisCacheDev, 8080),
	})
}

func TestCIDRPolicyExamples(t *testing.T) {
	ex1 := []byte(`{
  "kind": "NetworkPolicy",
  "apiVersion": "networking.k8s.io/v1",
  "metadata": {
    "name": "ingress-cidr-test",
    "namespace": "myns"
  },
  "spec": {
    "podSelector": {
      "matchLabels": {
        "role": "backend"
      }
    },
    "ingress": [
      {
        "from": [
          {
            "namespaceSelector": {
              "matchLabels": {
                "user": "bob"
              }
            }
          }
        ]
      }, {
        "from": [
          {
            "ipBlock": {
              "cidr": "10.0.0.0/8",
	          "except": [
	            "10.96.0.0/12"
	          ]
            }
          }
        ]
      }
    ]
  }
}`)
	np := slim_networkingv1.NetworkPolicy{}
	err := json.Unmarshal(ex1, &np)
	require.NoError(t, err)

	rules, err := ParseNetworkPolicy(hivetest.Logger(t), cmtypes.PolicyAnyCluster, &np)
	require.NoError(t, err)
	require.NotNil(t, rules)
	require.Len(t, rules, 1)
	require.Len(t, rules[0].Ingress, 2)

	ex2 := []byte(`{
  "kind": "NetworkPolicy",
  "apiVersion": "networking.k8s.io/v1",
  "metadata": {
    "name": "ingress-cidr-test",
    "namespace": "myns"
  },
  "spec": {
    "podSelector": {
      "matchLabels": {
        "role": "backend"
      }
    },
    "egress": [
      {
        "to": [
          {
            "ipBlock": {
              "cidr": "10.0.0.0/8",
	          "except": [
	            "10.96.0.0/12", "10.255.255.254/32"
	          ]
            }
          },
	      {
            "ipBlock": {
              "cidr": "11.0.0.0/8",
	          "except": [
	            "11.96.0.0/12", "11.255.255.254/32"
	          ]
            }
          }
        ]
      }
    ]
  }
}`)

	np = slim_networkingv1.NetworkPolicy{}
	err = json.Unmarshal(ex2, &np)
	require.NoError(t, err)

	rules, err = ParseNetworkPolicy(hivetest.Logger(t), cmtypes.PolicyAnyCluster, &np)
	require.NoError(t, err)
	require.NotNil(t, rules)
	require.Len(t, rules, 1)
	require.Equal(t, api.CIDR("10.0.0.0/8"), rules[0].Egress[0].ToCIDRSet[0].Cidr)

	expectedCIDRs := []api.CIDR{"10.96.0.0/12", "10.255.255.254/32"}
	for k, v := range rules[0].Egress[0].ToCIDRSet[0].ExceptCIDRs {
		require.Equal(t, expectedCIDRs[k], v)
	}

	expectedCIDRs = []api.CIDR{"11.96.0.0/12", "11.255.255.254/32"}
	for k, v := range rules[0].Egress[1].ToCIDRSet[0].ExceptCIDRs {
		require.Equal(t, expectedCIDRs[k], v)
	}

	require.Len(t, rules[0].Egress, 2)

}

func getSelectorPointer(sel api.EndpointSelector) *api.EndpointSelector {
	return &sel
}

func TestParseNetworkPolicyClusterLabel(t *testing.T) {
	np := &slim_networkingv1.NetworkPolicy{
		Spec: slim_networkingv1.NetworkPolicySpec{
			PodSelector: slim_metav1.LabelSelector{
				MatchLabels: map[string]string{
					"foo": "bar",
				},
			},
			Ingress: []slim_networkingv1.NetworkPolicyIngressRule{{
				From: []slim_networkingv1.NetworkPolicyPeer{{
					PodSelector: &slim_metav1.LabelSelector{
						MatchLabels: map[string]string{},
					},
				}},
			}},
			Egress: []slim_networkingv1.NetworkPolicyEgressRule{{
				To: []slim_networkingv1.NetworkPolicyPeer{{
					PodSelector: &slim_metav1.LabelSelector{
						MatchLabels: map[string]string{"io.cilium.k8s.policy.cluster": "cluster2"},
					},
				}},
			}},
		},
	}
	fromEndpoints := labels.LabelArray{
		labels.NewLabel(k8sConst.PodNamespaceLabel, "default", labels.LabelSourceK8s),
		labels.NewLabel("foo", "bar", labels.LabelSourceK8s),
	}
	epSelector := api.NewESFromLabels(fromEndpoints...)

	expectedRule := api.NewRule().
		WithEndpointSelector(epSelector).
		WithIngressRules([]api.IngressRule{{
			IngressCommonRule: api.IngressCommonRule{
				FromEndpoints: []api.EndpointSelector{api.NewESFromK8sLabelSelector(
					labels.LabelSourceK8sKeyPrefix,
					&slim_metav1.LabelSelector{
						MatchLabels: map[string]string{
							"io.cilium.k8s.policy.cluster": "cluster1",
							"io.kubernetes.pod.namespace":  "default",
						},
					},
				)},
			},
		}}).
		WithEgressRules([]api.EgressRule{{
			EgressCommonRule: api.EgressCommonRule{
				ToEndpoints: []api.EndpointSelector{api.NewESFromK8sLabelSelector(
					labels.LabelSourceK8sKeyPrefix,
					&slim_metav1.LabelSelector{
						MatchLabels: map[string]string{
							"io.cilium.k8s.policy.cluster": "cluster2",
							"io.kubernetes.pod.namespace":  "default",
						},
					},
				)},
			},
		}}).
		WithLabels(labels.ParseLabelArray(
			"k8s:"+k8sConst.PolicyLabelName+"=",
			"k8s:"+k8sConst.PolicyLabelUID+"=",
			"k8s:"+k8sConst.PolicyLabelNamespace+"=default",
			"k8s:"+k8sConst.PolicyLabelDerivedFrom+"="+resourceTypeNetworkPolicy,
		))

	expectedRule.Sanitize()

	expectedRules := api.Rules{
		expectedRule,
	}

	rules, err := ParseNetworkPolicy(hivetest.Logger(t), "cluster1", np)
	require.NoError(t, err)
	require.NotNil(t, rules)
	require.Equal(t, expectedRules, rules)
}

func Test_parseNetworkPolicyPeer(t *testing.T) {
	type args struct {
		namespace   string
		clusterName string
		peer        *slim_networkingv1.NetworkPolicyPeer
	}
	tests := []struct {
		name string
		args args
		want *api.EndpointSelector
	}{
		{
			name: "peer-with-pod-selector",
			args: args{
				namespace:   "foo-namespace",
				clusterName: "cluster1",
				peer: &slim_networkingv1.NetworkPolicyPeer{
					PodSelector: &slim_metav1.LabelSelector{
						MatchLabels: map[string]string{
							"foo": "bar",
						},
						MatchExpressions: []slim_metav1.LabelSelectorRequirement{
							{
								Key:      "foo",
								Operator: slim_metav1.LabelSelectorOpIn,
								Values:   []string{"bar", "baz"},
							},
						},
					},
				},
			},
			want: getSelectorPointer(
				api.NewESFromMatchRequirements(
					map[string]string{
						"k8s.foo":                          "bar",
						"k8s.io.kubernetes.pod.namespace":  "foo-namespace",
						"k8s.io.cilium.k8s.policy.cluster": "cluster1",
					},
					[]slim_metav1.LabelSelectorRequirement{
						{
							Key:      "k8s.foo",
							Operator: slim_metav1.LabelSelectorOpIn,
							Values:   []string{"bar", "baz"},
						},
					},
				),
			),
		},
		{
			name: "peer-nil",
			args: args{
				namespace: "foo-namespace",
			},
			want: nil,
		},
		{
			name: "peer-with-pod-selector-and-ns-selector",
			args: args{
				namespace: "foo-namespace",
				peer: &slim_networkingv1.NetworkPolicyPeer{
					PodSelector: &slim_metav1.LabelSelector{
						MatchLabels: map[string]string{
							"foo": "bar",
						},
						MatchExpressions: []slim_metav1.LabelSelectorRequirement{
							{
								Key:      "foo",
								Operator: slim_metav1.LabelSelectorOpIn,
								Values:   []string{"bar", "baz"},
							},
						},
					},
					NamespaceSelector: &slim_metav1.LabelSelector{
						MatchLabels: map[string]string{
							"ns-foo": "ns-bar",
						},
						MatchExpressions: []slim_metav1.LabelSelectorRequirement{
							{
								Key:      "ns-foo-expression",
								Operator: slim_metav1.LabelSelectorOpExists,
							},
						},
					},
				},
			},
			want: getSelectorPointer(
				api.NewESFromMatchRequirements(
					map[string]string{
						"k8s.foo": "bar",
						"k8s.io.cilium.k8s.namespace.labels.ns-foo": "ns-bar",
					},
					[]slim_metav1.LabelSelectorRequirement{
						{
							Key:      "k8s.io.cilium.k8s.namespace.labels.ns-foo-expression",
							Operator: slim_metav1.LabelSelectorOpExists,
						},
						{
							Key:      "k8s.foo",
							Operator: slim_metav1.LabelSelectorOpIn,
							Values:   []string{"bar", "baz"},
						},
					},
				),
			),
		},
		{
			name: "peer-with-ns-selector",
			args: args{
				namespace: "foo-namespace",
				peer: &slim_networkingv1.NetworkPolicyPeer{
					NamespaceSelector: &slim_metav1.LabelSelector{
						MatchLabels: map[string]string{
							"ns-foo": "ns-bar",
						},
						MatchExpressions: []slim_metav1.LabelSelectorRequirement{
							{
								Key:      "ns-foo-expression",
								Operator: slim_metav1.LabelSelectorOpExists,
							},
						},
					},
				},
			},
			want: getSelectorPointer(
				api.NewESFromMatchRequirements(
					map[string]string{
						"k8s.io.cilium.k8s.namespace.labels.ns-foo": "ns-bar",
					},
					[]slim_metav1.LabelSelectorRequirement{
						{
							Key:      "k8s.io.cilium.k8s.namespace.labels.ns-foo-expression",
							Operator: slim_metav1.LabelSelectorOpExists,
						},
					},
				),
			),
		},
		{
			name: "peer-with-allow-all-ns-selector",
			args: args{
				namespace: "foo-namespace",
				peer: &slim_networkingv1.NetworkPolicyPeer{
					NamespaceSelector: &slim_metav1.LabelSelector{},
				},
			},
			want: getSelectorPointer(
				api.NewESFromMatchRequirements(
					map[string]string{},
					[]slim_metav1.LabelSelectorRequirement{
						{
							Key:      fmt.Sprintf("%s.%s", labels.LabelSourceK8s, k8sConst.PodNamespaceLabel),
							Operator: slim_metav1.LabelSelectorOpExists,
						},
					},
				),
			),
		},
		{
			name: "peer-with-defaut-cluster",
			args: args{
				namespace:   "foo-namespace",
				clusterName: "cluster1",
				peer: &slim_networkingv1.NetworkPolicyPeer{
					PodSelector: &slim_metav1.LabelSelector{
						MatchLabels: map[string]string{
							"foo": "bar",
						},
						MatchExpressions: []slim_metav1.LabelSelectorRequirement{
							{
								Key:      "foo",
								Operator: slim_metav1.LabelSelectorOpIn,
								Values:   []string{"bar", "baz"},
							},
						},
					},
				},
			},
			want: getSelectorPointer(
				api.NewESFromMatchRequirements(
					map[string]string{
						"k8s.foo":                          "bar",
						"k8s.io.cilium.k8s.policy.cluster": "cluster1",
						"k8s.io.kubernetes.pod.namespace":  "foo-namespace",
					},
					[]slim_metav1.LabelSelectorRequirement{
						{
							Key:      "k8s.foo",
							Operator: slim_metav1.LabelSelectorOpIn,
							Values:   []string{"bar", "baz"},
						},
					},
				),
			),
		},
		{
			name: "peer-with-cluster-selector",
			args: args{
				namespace:   "foo-namespace",
				clusterName: "cluster1",
				peer: &slim_networkingv1.NetworkPolicyPeer{
					PodSelector: &slim_metav1.LabelSelector{
						MatchLabels: map[string]string{
							"foo":                          "bar",
							"io.cilium.k8s.policy.cluster": "cluster2",
						},
					},
				},
			},
			want: getSelectorPointer(
				api.NewESFromMatchRequirements(
					map[string]string{
						"k8s.foo":                          "bar",
						"k8s.io.kubernetes.pod.namespace":  "foo-namespace",
						"k8s.io.cilium.k8s.policy.cluster": "cluster2",
					},
					nil,
				),
			),
		},
		{
			name: "peer-with-cluster-selector-expr",
			args: args{
				namespace:   "foo-namespace",
				clusterName: "cluster1",
				peer: &slim_networkingv1.NetworkPolicyPeer{
					PodSelector: &slim_metav1.LabelSelector{
						MatchExpressions: []slim_metav1.LabelSelectorRequirement{
							{
								Key:      "io.cilium.k8s.policy.cluster",
								Operator: slim_metav1.LabelSelectorOpIn,
								Values:   []string{"bar", "baz"},
							},
						},
					},
				},
			},
			want: getSelectorPointer(
				api.NewESFromMatchRequirements(
					map[string]string{
						"k8s.io.kubernetes.pod.namespace": "foo-namespace",
					},
					[]slim_metav1.LabelSelectorRequirement{
						{
							Key:      "k8s.io.cilium.k8s.policy.cluster",
							Operator: slim_metav1.LabelSelectorOpIn,
							Values:   []string{"bar", "baz"},
						},
					},
				),
			),
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := parseNetworkPolicyPeer(tt.args.clusterName, tt.args.namespace, tt.args.peer)
			require.Equal(t, tt.want, got)
		})
	}
}

func TestGetPolicyLabelsv1(t *testing.T) {
	uuid := "1bba160-ddca-11e8-b697-0800273b04ff"
	tests := []struct {
		np          *slim_networkingv1.NetworkPolicy // input network policy
		name        string                           // expected extracted name
		namespace   string                           // expected extracted namespace
		uuid        string                           // expected extracted uuid
		derivedFrom string                           // expected extracted derived
	}{
		{
			np:          &slim_networkingv1.NetworkPolicy{},
			name:        "",
			namespace:   slim_metav1.NamespaceDefault,
			uuid:        "",
			derivedFrom: resourceTypeNetworkPolicy,
		},
		{
			np: &slim_networkingv1.NetworkPolicy{
				ObjectMeta: slim_metav1.ObjectMeta{
					Annotations: map[string]string{
						annotation.PolicyName: "foo",
					},
				},
			},
			name:        "foo",
			uuid:        "",
			namespace:   slim_metav1.NamespaceDefault,
			derivedFrom: resourceTypeNetworkPolicy,
		},
		{
			np: &slim_networkingv1.NetworkPolicy{
				ObjectMeta: slim_metav1.ObjectMeta{
					Name:      "foo",
					Namespace: "bar",
					UID:       types.UID(uuid),
				},
			},
			name:        "foo",
			namespace:   "bar",
			uuid:        uuid,
			derivedFrom: resourceTypeNetworkPolicy,
		},
	}

	assertLabel := func(lbl labels.Label, key, value string) {
		require.Equal(t, key, lbl.Key)
		require.Equal(t, value, lbl.Value)
		require.Equal(t, labels.LabelSourceK8s, lbl.Source)
	}

	for _, tt := range tests {
		lbls := GetPolicyLabelsv1(hivetest.Logger(t), tt.np)
		require.NotNil(t, lbls)
		require.Len(t, lbls, 4, "Incorrect number of labels: Expected DerivedFrom, Name, Namespace and UID labels.")
		assertLabel(lbls[0], "io.cilium.k8s.policy.derived-from", tt.derivedFrom)
		assertLabel(lbls[1], "io.cilium.k8s.policy.name", tt.name)
		assertLabel(lbls[2], "io.cilium.k8s.policy.namespace", tt.namespace)
		assertLabel(lbls[3], "io.cilium.k8s.policy.uid", tt.uuid)
	}
}

func TestIPBlockToCIDRRule(t *testing.T) {
	blocks := []*slim_networkingv1.IPBlock{
		{},
		{CIDR: "192.168.1.1/24"},
		{CIDR: "192.168.1.1/24", Except: []string{}},
		{CIDR: "192.168.1.1/24", Except: []string{"192.168.1.1/28"}},
		{
			CIDR: "192.168.1.1/24",
			Except: []string{
				"192.168.1.1/30",
				"192.168.1.1/26",
				"192.168.1.1/28",
			},
		},
	}

	for _, block := range blocks {
		cidrRule := ipBlockToCIDRRule(block)

		exceptCIDRs := make([]api.CIDR, len(block.Except))
		for i, v := range block.Except {
			exceptCIDRs[i] = api.CIDR(v)
		}

		require.False(t, cidrRule.Generated)
		require.Equal(t, api.CIDR(block.CIDR), cidrRule.Cidr)

		if len(block.Except) == 0 {
			require.Nil(t, cidrRule.ExceptCIDRs)
		} else {
			require.Equal(t, exceptCIDRs, cidrRule.ExceptCIDRs)
		}
	}
}

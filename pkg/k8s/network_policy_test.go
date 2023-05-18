// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package k8s

import (
	"encoding/json"
	"fmt"
	"testing"

	. "github.com/cilium/checkmate"
	"k8s.io/apimachinery/pkg/types"

	"github.com/cilium/cilium/api/v1/models"
	"github.com/cilium/cilium/pkg/annotation"
	"github.com/cilium/cilium/pkg/checker"
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
)

// Hook up gocheck into the "go test" runner.
func Test(t *testing.T) {
	TestingT(t)
}

type K8sSuite struct{}

var _ = Suite(&K8sSuite{})

var (
	labelsA = labels.LabelArray{
		labels.NewLabel(k8sConst.PodNamespaceLabel, slim_metav1.NamespaceDefault, labels.LabelSourceK8s),
		labels.NewLabel("id", "a", labels.LabelSourceK8s),
	}

	labelSelectorA = slim_metav1.LabelSelector{
		MatchLabels: map[string]string{
			"id": "a",
		},
	}

	labelsB = labels.LabelArray{
		labels.NewLabel(k8sConst.PodNamespaceLabel, slim_metav1.NamespaceDefault, labels.LabelSourceK8s),
		labels.NewLabel("id1", "b", labels.LabelSourceK8s),
		labels.NewLabel("id2", "c", labels.LabelSourceK8s),
	}

	labelsC = labels.LabelArray{
		labels.NewLabel(k8sConst.PodNamespaceLabel, slim_metav1.NamespaceDefault, labels.LabelSourceK8s),
		labels.NewLabel("id", "c", labels.LabelSourceK8s),
	}

	labelSelectorC = slim_metav1.LabelSelector{
		MatchLabels: map[string]string{
			"id": "c",
		},
	}

	ctxAToB = policy.SearchContext{
		From:  labelsA,
		To:    labelsB,
		Trace: policy.TRACE_VERBOSE,
	}

	ctxAToC = policy.SearchContext{
		From:  labelsA,
		To:    labelsC,
		Trace: policy.TRACE_VERBOSE,
	}

	port80 = slim_networkingv1.NetworkPolicyPort{
		Port: &intstr.IntOrString{
			Type:   intstr.Int,
			IntVal: 80,
		},
	}

	dummySelectorCacheUser = &DummySelectorCacheUser{}
)

type DummySelectorCacheUser struct{}

func testNewPolicyRepository() *policy.Repository {
	idAllocator := testidentity.NewMockIdentityAllocator(nil)
	repo := policy.NewPolicyRepository(idAllocator, nil, nil, nil)
	repo.GetSelectorCache().SetLocalIdentityNotifier(testidentity.NewDummyIdentityNotifier())
	return repo
}

func (d *DummySelectorCacheUser) IdentitySelectionUpdated(selector policy.CachedSelector, added, deleted []identity.NumericIdentity) {
}

func (s *K8sSuite) TestParseNetworkPolicyIngress(c *C) {
	netPolicy := &slim_networkingv1.NetworkPolicy{
		Spec: slim_networkingv1.NetworkPolicySpec{
			PodSelector: slim_metav1.LabelSelector{
				MatchLabels: map[string]string{
					"foo1": "bar1",
					"foo2": "bar2",
				},
			},
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
	}

	_, err := ParseNetworkPolicy(netPolicy)
	c.Assert(err, IsNil)

	fromEndpoints := labels.LabelArray{
		labels.NewLabel(k8sConst.PodNamespaceLabel, slim_metav1.NamespaceDefault, labels.LabelSourceK8s),
		labels.NewLabel("foo3", "bar3", labels.LabelSourceK8s),
		labels.NewLabel("foo4", "bar4", labels.LabelSourceK8s),
	}

	ctx := policy.SearchContext{
		From: fromEndpoints,
		To: labels.LabelArray{
			labels.NewLabel(k8sConst.PodNamespaceLabel, slim_metav1.NamespaceDefault, labels.LabelSourceK8s),
			labels.NewLabel("foo1", "bar1", labels.LabelSourceK8s),
			labels.NewLabel("foo2", "bar2", labels.LabelSourceK8s),
		},
		Trace: policy.TRACE_VERBOSE,
	}

	rules, err := ParseNetworkPolicy(netPolicy)
	c.Assert(err, IsNil)
	c.Assert(len(rules), Equals, 1)

	repo := testNewPolicyRepository()

	repo.AddList(rules)
	c.Assert(repo.AllowsIngressRLocked(&ctx), Equals, api.Denied)

	epSelector := api.NewESFromLabels(fromEndpoints...)
	cachedEPSelector, _ := repo.GetSelectorCache().AddIdentitySelector(dummySelectorCacheUser, epSelector)
	defer func() { repo.GetSelectorCache().RemoveSelector(cachedEPSelector, dummySelectorCacheUser) }()

	ingressL4Policy, err := repo.ResolveL4IngressPolicy(&ctx)
	c.Assert(ingressL4Policy, Not(IsNil))
	c.Assert(err, IsNil)
	c.Assert(ingressL4Policy, checker.Equals, policy.L4PolicyMap{
		"80/TCP": {
			Port: 80, Protocol: api.ProtoTCP, U8Proto: 6,
			L7Parser:            policy.ParserTypeNone,
			PerSelectorPolicies: policy.L7DataMap{cachedEPSelector: nil},
			Ingress:             true,
			RuleOrigin: map[policy.CachedSelector]labels.LabelArrayList{
				cachedEPSelector: {labels.ParseLabelArray(
					"k8s:"+k8sConst.PolicyLabelName,
					"k8s:"+k8sConst.PolicyLabelUID,
					"k8s:"+k8sConst.PolicyLabelNamespace+"=default",
					"k8s:"+k8sConst.PolicyLabelDerivedFrom+"="+resourceTypeNetworkPolicy,
				)},
			},
		},
	})
	ingressL4Policy.Detach(repo.GetSelectorCache())

	ctx.To = labels.LabelArray{
		labels.NewLabel("foo2", "bar2", labels.LabelSourceK8s),
	}

	// ctx.To needs to have all labels from the policy in order to be accepted
	c.Assert(repo.AllowsIngressRLocked(&ctx), Not(Equals), api.Allowed)

	ctx = policy.SearchContext{
		From: labels.LabelArray{
			labels.NewLabel("foo3", "bar3", labels.LabelSourceK8s),
		},
		To: labels.LabelArray{
			labels.NewLabel("foo1", "bar1", labels.LabelSourceK8s),
			labels.NewLabel("foo2", "bar2", labels.LabelSourceK8s),
		},
		Trace: policy.TRACE_VERBOSE,
	}
	// ctx.From also needs to have all labels from the policy in order to be accepted
	c.Assert(repo.AllowsIngressRLocked(&ctx), Not(Equals), api.Allowed)
}

func (s *K8sSuite) TestParseNetworkPolicyMultipleSelectors(c *C) {

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
      "role":"backend"
    }
  },
  "egress":[
    {
      "ports":[
        {
          "protocol":"TCP",
          "port":5432
        }
      ],
      "to":[
        {
          "podSelector":{
            "matchLabels":{
              "app":"db1"
            }
          }
        },
        {
          "podSelector":{
            "matchLabels":{
              "app":"db2"
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
              "role":"frontend"
            }
          },
          "namespaceSelector":{
            "matchLabels":{
              "project":"myproject"
            }
          }
        },
        {
          "podSelector":{
            "matchLabels":{
              "app":"inventory"
            }
          }
        }
      ]
    }
  ]
}
}`)

	np := slim_networkingv1.NetworkPolicy{}
	err := json.Unmarshal(ex1, &np)
	c.Assert(err, IsNil)

	rules, err := ParseNetworkPolicy(&np)
	c.Assert(err, IsNil)
	c.Assert(len(rules), Equals, 1)

	repo := testNewPolicyRepository()
	repo.AddList(rules)

	endpointLabels := labels.LabelArray{
		labels.NewLabel(k8sConst.PodNamespaceLabel, slim_metav1.NamespaceDefault, labels.LabelSourceK8s),
		labels.NewLabel("role", "backend", labels.LabelSourceK8s),
	}

	// Ingress context
	ctx := policy.SearchContext{
		From: labels.LabelArray{
			labels.NewLabel("role", "frontend", labels.LabelSourceK8s),
		},
		To:    endpointLabels,
		Trace: policy.TRACE_VERBOSE,
	}

	// should be DENIED because ctx.From is missing the namespace selector
	c.Assert(repo.AllowsIngressRLocked(&ctx), Equals, api.Denied)

	ctx.From = labels.LabelArray{
		labels.NewLabel("role", "frontend", labels.LabelSourceK8s),
		labels.NewLabel(policy.JoinPath(k8sConst.PodNamespaceMetaLabels, "project"), "myproject", labels.LabelSourceK8s),
	}

	// should be ALLOWED with the namespace label properly set
	c.Assert(repo.AllowsIngressRLocked(&ctx), Equals, api.Allowed)

	ctx.From = labels.LabelArray{
		labels.NewLabel(k8sConst.PodNamespaceLabel, slim_metav1.NamespaceDefault, labels.LabelSourceK8s),
		labels.NewLabel("app", "inventory", labels.LabelSourceK8s),
	}

	// should be ALLOWED since all rules in From must match
	c.Assert(repo.AllowsIngressRLocked(&ctx), Equals, api.Allowed)

	// Egress context
	ctx = policy.SearchContext{
		From: endpointLabels,
		To: labels.LabelArray{
			labels.NewLabel(k8sConst.PodNamespaceLabel, slim_metav1.NamespaceDefault, labels.LabelSourceK8s),
			labels.NewLabel("app", "db1", labels.LabelSourceK8s),
		},
		Trace: policy.TRACE_VERBOSE,
	}

	// should be DENIED because DPorts are missing in context
	c.Assert(repo.AllowsEgressRLocked(&ctx), Equals, api.Denied)

	ctx.DPorts = []*models.Port{{Port: 5432, Protocol: models.PortProtocolTCP}}

	// should be ALLOWED with DPorts set correctly
	c.Assert(repo.AllowsEgressRLocked(&ctx), Equals, api.Allowed)

	ctx.To = labels.LabelArray{
		labels.NewLabel(k8sConst.PodNamespaceLabel, slim_metav1.NamespaceDefault, labels.LabelSourceK8s),
		labels.NewLabel("app", "db2", labels.LabelSourceK8s),
	}

	// should be ALLOWED for db2 as well
	c.Assert(repo.AllowsEgressRLocked(&ctx), Equals, api.Allowed)
}

func (s *K8sSuite) TestParseNetworkPolicyNoSelectors(c *C) {

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
	c.Assert(err, IsNil)

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

	rules, err := ParseNetworkPolicy(&np)
	c.Assert(err, IsNil)
	c.Assert(rules, NotNil)
	c.Assert(rules, checker.DeepEquals, expectedRules)
}

func (s *K8sSuite) TestParseNetworkPolicyEgress(c *C) {

	netPolicy := &slim_networkingv1.NetworkPolicy{
		Spec: slim_networkingv1.NetworkPolicySpec{
			PodSelector: slim_metav1.LabelSelector{
				MatchLabels: map[string]string{
					"foo1": "bar1",
					"foo2": "bar2",
				},
			},
			Egress: []slim_networkingv1.NetworkPolicyEgressRule{
				{
					To: []slim_networkingv1.NetworkPolicyPeer{
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
	}

	rules, err := ParseNetworkPolicy(netPolicy)
	c.Assert(err, IsNil)
	c.Assert(len(rules), Equals, 1)

	fromEndpoints := labels.LabelArray{
		labels.NewLabel(k8sConst.PodNamespaceLabel, slim_metav1.NamespaceDefault, labels.LabelSourceK8s),
		labels.NewLabel("foo1", "bar1", labels.LabelSourceK8s),
		labels.NewLabel("foo2", "bar2", labels.LabelSourceK8s),
	}

	toEndpoints := labels.LabelArray{
		labels.NewLabel(k8sConst.PodNamespaceLabel, slim_metav1.NamespaceDefault, labels.LabelSourceK8s),
		labels.NewLabel("foo3", "bar3", labels.LabelSourceK8s),
		labels.NewLabel("foo4", "bar4", labels.LabelSourceK8s),
	}

	ctx := policy.SearchContext{
		From:  fromEndpoints,
		To:    toEndpoints,
		Trace: policy.TRACE_VERBOSE,
	}

	repo := testNewPolicyRepository()
	repo.AddList(rules)
	// Because search context did not contain port-specific policy, deny is
	// expected.
	c.Assert(repo.AllowsEgressRLocked(&ctx), Equals, api.Denied)

	epSelector := api.NewESFromLabels(toEndpoints...)
	cachedEPSelector, _ := repo.GetSelectorCache().AddIdentitySelector(dummySelectorCacheUser, epSelector)
	defer func() { repo.GetSelectorCache().RemoveSelector(cachedEPSelector, dummySelectorCacheUser) }()

	egressL4Policy, err := repo.ResolveL4EgressPolicy(&ctx)
	c.Assert(egressL4Policy, Not(IsNil))
	c.Assert(err, IsNil)
	c.Assert(egressL4Policy, checker.DeepEquals, policy.L4PolicyMap{
		"80/TCP": {
			Port: 80, Protocol: api.ProtoTCP, U8Proto: 6,
			L7Parser:            policy.ParserTypeNone,
			PerSelectorPolicies: policy.L7DataMap{cachedEPSelector: nil},
			Ingress:             false,
			RuleOrigin: map[policy.CachedSelector]labels.LabelArrayList{
				cachedEPSelector: {rules[0].Labels},
			},
		},
	})
	egressL4Policy.Detach(repo.GetSelectorCache())

	ctx.From = labels.LabelArray{
		labels.NewLabel("foo2", "bar2", labels.LabelSourceK8s),
	}

	// ctx.From needs to have all labels from the policy in order to be accepted
	c.Assert(repo.AllowsEgressRLocked(&ctx), Not(Equals), api.Allowed)

	ctx = policy.SearchContext{
		To: labels.LabelArray{
			labels.NewLabel("foo3", "bar3", labels.LabelSourceK8s),
		},
		From: labels.LabelArray{
			labels.NewLabel("foo1", "bar1", labels.LabelSourceK8s),
			labels.NewLabel("foo2", "bar2", labels.LabelSourceK8s),
		},
		Trace: policy.TRACE_VERBOSE,
	}

	// ctx.To also needs to have all labels from the policy in order to be accepted.
	c.Assert(repo.AllowsEgressRLocked(&ctx), Not(Equals), api.Allowed)
}

func parseAndAddRules(c *C, p *slim_networkingv1.NetworkPolicy) *policy.Repository {
	repo := testNewPolicyRepository()
	rules, err := ParseNetworkPolicy(p)
	c.Assert(err, IsNil)
	rev := repo.GetRevision()
	_, id := repo.AddList(rules)
	c.Assert(id, Equals, rev+1)

	return repo
}

func (s *K8sSuite) TestParseNetworkPolicyEgressAllowAll(c *C) {
	repo := parseAndAddRules(c, &slim_networkingv1.NetworkPolicy{
		Spec: slim_networkingv1.NetworkPolicySpec{
			PodSelector: labelSelectorA,
			Egress: []slim_networkingv1.NetworkPolicyEgressRule{
				{
					To: []slim_networkingv1.NetworkPolicyPeer{},
				},
			},
		},
	})

	c.Assert(repo.AllowsEgressRLocked(&ctxAToB), Equals, api.Allowed)
	c.Assert(repo.AllowsEgressRLocked(&ctxAToC), Equals, api.Allowed)

	ctxAToC80 := ctxAToC
	ctxAToC80.DPorts = []*models.Port{{Port: 80, Protocol: models.PortProtocolTCP}}
	c.Assert(repo.AllowsEgressRLocked(&ctxAToC80), Equals, api.Allowed)

	ctxAToC90 := ctxAToC
	ctxAToC90.DPorts = []*models.Port{{Port: 90, Protocol: models.PortProtocolTCP}}
	c.Assert(repo.AllowsEgressRLocked(&ctxAToC90), Equals, api.Allowed)
}

func (s *K8sSuite) TestParseNetworkPolicyEgressL4AllowAll(c *C) {
	repo := parseAndAddRules(c, &slim_networkingv1.NetworkPolicy{
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

	ctxAToC80 := ctxAToC
	ctxAToC80.DPorts = []*models.Port{{Port: 80, Protocol: models.PortProtocolTCP}}
	c.Assert(repo.AllowsEgressRLocked(&ctxAToC80), Equals, api.Allowed)

	ctxAToC90 := ctxAToC
	ctxAToC90.DPorts = []*models.Port{{Port: 90, Protocol: models.PortProtocolTCP}}
	c.Assert(repo.AllowsEgressRLocked(&ctxAToC90), Equals, api.Denied)
}

func (s *K8sSuite) TestParseNetworkPolicyIngressAllowAll(c *C) {
	repo := parseAndAddRules(c, &slim_networkingv1.NetworkPolicy{
		Spec: slim_networkingv1.NetworkPolicySpec{
			PodSelector: labelSelectorC,
			Ingress: []slim_networkingv1.NetworkPolicyIngressRule{
				{
					From: []slim_networkingv1.NetworkPolicyPeer{},
				},
			},
		},
	})

	c.Assert(repo.AllowsIngressRLocked(&ctxAToB), Equals, api.Denied)
	c.Assert(repo.AllowsIngressRLocked(&ctxAToC), Equals, api.Allowed)

	ctxAToC80 := ctxAToC
	ctxAToC80.DPorts = []*models.Port{{Port: 80, Protocol: models.PortProtocolTCP}}
	c.Assert(repo.AllowsIngressRLocked(&ctxAToC80), Equals, api.Allowed)

	ctxAToC90 := ctxAToC
	ctxAToC90.DPorts = []*models.Port{{Port: 90, Protocol: models.PortProtocolTCP}}
	c.Assert(repo.AllowsIngressRLocked(&ctxAToC90), Equals, api.Allowed)
}

func (s *K8sSuite) TestParseNetworkPolicyIngressL4AllowAll(c *C) {
	repo := parseAndAddRules(c, &slim_networkingv1.NetworkPolicy{
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

	c.Assert(repo.AllowsIngressRLocked(&ctxAToB), Equals, api.Denied)

	ctxAToC80 := ctxAToC
	ctxAToC80.DPorts = []*models.Port{{Port: 80, Protocol: models.PortProtocolTCP}}
	c.Assert(repo.AllowsIngressRLocked(&ctxAToC80), Equals, api.Allowed)

	ctxAToC90 := ctxAToC
	ctxAToC90.DPorts = []*models.Port{{Port: 90, Protocol: models.PortProtocolTCP}}
	c.Assert(repo.AllowsIngressRLocked(&ctxAToC90), Equals, api.Denied)
}

func (s *K8sSuite) TestParseNetworkPolicyNamedPort(c *C) {
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

	rules, err := ParseNetworkPolicy(netPolicy)
	c.Assert(err, IsNil)
	c.Assert(len(rules), Equals, 1)
}

func (s *K8sSuite) TestParseNetworkPolicyEmptyPort(c *C) {
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

	rules, err := ParseNetworkPolicy(netPolicy)
	c.Assert(err, IsNil)
	c.Assert(len(rules), Equals, 1)
	c.Assert(len(rules[0].Ingress), Equals, 1)
	c.Assert(len(rules[0].Ingress[0].ToPorts), Equals, 1)
	ports := rules[0].Ingress[0].ToPorts[0].Ports
	c.Assert(len(ports), Equals, 1)
	c.Assert(ports[0].Port, Equals, "0")
	c.Assert(ports[0].Protocol, Equals, api.ProtoTCP)
}

func (s *K8sSuite) TestParsePorts(c *C) {
	rules := parsePorts([]slim_networkingv1.NetworkPolicyPort{
		{},
	})
	c.Assert(len(rules), Equals, 1)
	c.Assert(len(rules[0].Ports), Equals, 1)
	c.Assert(rules[0].Ports[0].Port, Equals, "0")
	c.Assert(rules[0].Ports[0].Protocol, Equals, api.ProtoTCP)
}

func (s *K8sSuite) TestParseNetworkPolicyUnknownProto(c *C) {
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

	rules, err := ParseNetworkPolicy(netPolicy)
	c.Assert(err, Not(IsNil))
	c.Assert(len(rules), Equals, 0)
}

func (s *K8sSuite) TestParseNetworkPolicyEmptyFrom(c *C) {
	// From missing, all sources should be allowed
	netPolicy1 := &slim_networkingv1.NetworkPolicy{
		Spec: slim_networkingv1.NetworkPolicySpec{
			PodSelector: slim_metav1.LabelSelector{
				MatchLabels: map[string]string{
					"foo1": "bar1",
				},
			},
			Ingress: []slim_networkingv1.NetworkPolicyIngressRule{
				{},
			},
		},
	}

	rules, err := ParseNetworkPolicy(netPolicy1)
	c.Assert(err, IsNil)
	c.Assert(len(rules), Equals, 1)

	ctx := policy.SearchContext{
		From: labels.LabelArray{
			labels.NewLabel(k8sConst.PodNamespaceLabel, slim_metav1.NamespaceDefault, labels.LabelSourceK8s),
			labels.NewLabel("foo0", "bar0", labels.LabelSourceK8s),
		},
		To: labels.LabelArray{
			labels.NewLabel(k8sConst.PodNamespaceLabel, slim_metav1.NamespaceDefault, labels.LabelSourceK8s),
			labels.NewLabel("foo1", "bar1", labels.LabelSourceK8s),
		},
		Trace: policy.TRACE_VERBOSE,
	}

	repo := testNewPolicyRepository()
	repo.AddList(rules)
	c.Assert(repo.AllowsIngressRLocked(&ctx), Equals, api.Allowed)

	// Empty From rules, all sources should be allowed
	netPolicy2 := &slim_networkingv1.NetworkPolicy{
		Spec: slim_networkingv1.NetworkPolicySpec{
			PodSelector: slim_metav1.LabelSelector{
				MatchLabels: map[string]string{
					"foo1": "bar1",
				},
			},
			Ingress: []slim_networkingv1.NetworkPolicyIngressRule{
				{
					From:  []slim_networkingv1.NetworkPolicyPeer{},
					Ports: []slim_networkingv1.NetworkPolicyPort{},
				},
			},
		},
	}

	rules, err = ParseNetworkPolicy(netPolicy2)
	c.Assert(err, IsNil)
	c.Assert(len(rules), Equals, 1)
	repo = testNewPolicyRepository()
	repo.AddList(rules)
	c.Assert(repo.AllowsIngressRLocked(&ctx), Equals, api.Allowed)
}

func (s *K8sSuite) TestParseNetworkPolicyDenyAll(c *C) {
	// From missing, all sources should be allowed
	netPolicy1 := &slim_networkingv1.NetworkPolicy{
		Spec: slim_networkingv1.NetworkPolicySpec{
			PodSelector: slim_metav1.LabelSelector{
				MatchLabels: map[string]string{},
			},
		},
	}

	rules, err := ParseNetworkPolicy(netPolicy1)
	c.Assert(err, IsNil)
	c.Assert(len(rules), Equals, 1)

	ctx := policy.SearchContext{
		From: labels.LabelArray{
			labels.NewLabel(k8sConst.PodNamespaceLabel, slim_metav1.NamespaceDefault, labels.LabelSourceK8s),
			labels.NewLabel("foo0", "bar0", labels.LabelSourceK8s),
		},
		To: labels.LabelArray{
			labels.NewLabel(k8sConst.PodNamespaceLabel, slim_metav1.NamespaceDefault, labels.LabelSourceK8s),
			labels.NewLabel("foo1", "bar1", labels.LabelSourceK8s),
		},
		Trace: policy.TRACE_VERBOSE,
	}

	repo := testNewPolicyRepository()
	repo.AddList(rules)
	c.Assert(repo.AllowsIngressRLocked(&ctx), Equals, api.Denied)
}

func (s *K8sSuite) TestParseNetworkPolicyNoIngress(c *C) {
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

	rules, err := ParseNetworkPolicy(netPolicy)
	c.Assert(err, IsNil)
	c.Assert(len(rules), Equals, 1)
}

func (s *K8sSuite) TestNetworkPolicyExamples(c *C) {
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
	np := slim_networkingv1.NetworkPolicy{}
	err := json.Unmarshal(ex1, &np)
	c.Assert(err, IsNil)

	_, err = ParseNetworkPolicy(&np)
	c.Assert(err, IsNil)

	// Example 1b: Only allow traffic from frontend pods to backend pods
	// in the same namespace `myns`
	ex1 = []byte(`{
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
	np = slim_networkingv1.NetworkPolicy{}
	err = json.Unmarshal(ex1, &np)
	c.Assert(err, IsNil)

	rules, err := ParseNetworkPolicy(&np)
	c.Assert(err, IsNil)
	c.Assert(len(rules), Equals, 1)

	repo := testNewPolicyRepository()
	repo.AddList(rules)
	ctx := policy.SearchContext{
		From: labels.LabelArray{
			labels.NewLabel(k8sConst.PodNamespaceLabel, "myns", labels.LabelSourceK8s),
			labels.NewLabel("role", "frontend", labels.LabelSourceK8s),
		},
		To: labels.LabelArray{
			labels.NewLabel("role", "backend", labels.LabelSourceK8s),
		},
		Trace: policy.TRACE_VERBOSE,
	}
	// Doesn't share the same namespace
	c.Assert(repo.AllowsIngressRLocked(&ctx), Equals, api.Denied)

	ctx = policy.SearchContext{
		From: labels.LabelArray{
			labels.NewLabel(k8sConst.PodNamespaceLabel, slim_metav1.NamespaceDefault, labels.LabelSourceK8s),
			labels.NewLabel("role", "frontend", labels.LabelSourceK8s),
		},
		To: labels.LabelArray{
			labels.NewLabel("role", "backend", labels.LabelSourceK8s),
		},
		Trace: policy.TRACE_VERBOSE,
	}
	// Doesn't share the same namespace
	c.Assert(repo.AllowsIngressRLocked(&ctx), Equals, api.Denied)

	ctx = policy.SearchContext{
		From: labels.LabelArray{
			labels.NewLabel(k8sConst.PodNamespaceLabel, "myns", labels.LabelSourceK8s),
			labels.NewLabel("role", "frontend", labels.LabelSourceK8s),
		},
		To: labels.LabelArray{
			labels.NewLabel(k8sConst.PodNamespaceLabel, "myns", labels.LabelSourceK8s),
			labels.NewLabel("role", "backend", labels.LabelSourceK8s),
		},
		DPorts: []*models.Port{
			{
				Port:     6379,
				Protocol: models.PortProtocolTCP,
			},
		},
		Trace: policy.TRACE_VERBOSE,
	}
	// Should be ACCEPT sense the traffic needs to come from `frontend` AND
	// port 6379 and belong to the same namespace `myns`.
	c.Assert(repo.AllowsIngressRLocked(&ctx), Equals, api.Allowed)

	// Example 2a: Allow TCP 443 from any source in Bob's namespaces.
	ex2 := []byte(`{
  "kind": "NetworkPolicy",
  "apiVersion": "networking.k8s.io/v1",
  "metadata": {
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

	np = slim_networkingv1.NetworkPolicy{}
	err = json.Unmarshal(ex2, &np)
	c.Assert(err, IsNil)

	_, err = ParseNetworkPolicy(&np)
	c.Assert(err, IsNil)

	// Example 2b: Allow from any source in Bob's namespaces.
	ex2 = []byte(`{
  "kind": "NetworkPolicy",
  "apiVersion": "networking.k8s.io/v1",
  "metadata": {
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

	np = slim_networkingv1.NetworkPolicy{}
	err = json.Unmarshal(ex2, &np)
	c.Assert(err, IsNil)

	rules, err = ParseNetworkPolicy(&np)
	c.Assert(err, IsNil)
	c.Assert(len(rules), Equals, 1)

	repo = testNewPolicyRepository()
	repo.AddList(rules)
	ctx = policy.SearchContext{
		From: labels.LabelArray{
			labels.NewLabel(k8sConst.PodNamespaceLabel, slim_metav1.NamespaceDefault, labels.LabelSourceK8s),
			labels.NewLabel(policy.JoinPath(k8sConst.PodNamespaceMetaLabels, "user"), "bob", labels.LabelSourceK8s),
		},
		To: labels.LabelArray{
			labels.NewLabel(k8sConst.PodNamespaceLabel, slim_metav1.NamespaceDefault, labels.LabelSourceK8s),
			labels.NewLabel("role", "frontend", labels.LabelSourceK8s),
		},
		Trace: policy.TRACE_VERBOSE,
	}

	// Should be DENY sense the traffic needs to come from
	// namespace `user=bob` AND port 443.
	c.Assert(repo.AllowsIngressRLocked(&ctx), Equals, api.Denied)

	l4Policy, err := repo.ResolveL4IngressPolicy(&ctx)
	c.Assert(l4Policy, Not(IsNil))
	c.Assert(err, IsNil)
	l4Policy.Detach(repo.GetSelectorCache())

	ctx = policy.SearchContext{
		From: labels.LabelArray{
			labels.NewLabel(k8sConst.PodNamespaceLabel, "myns", labels.LabelSourceK8s),
			labels.NewLabel(policy.JoinPath(k8sConst.PodNamespaceMetaLabels, "user"), "bob", labels.LabelSourceK8s),
		},
		DPorts: []*models.Port{
			{
				Port:     443,
				Protocol: models.PortProtocolTCP,
			},
		},
		To: labels.LabelArray{
			labels.NewLabel(k8sConst.PodNamespaceLabel, slim_metav1.NamespaceDefault, labels.LabelSourceK8s),
			labels.NewLabel("role", "frontend", labels.LabelSourceK8s),
		},
		Trace: policy.TRACE_VERBOSE,
	}
	// Should be ACCEPT sense the traffic comes from Bob's namespaces
	// (even if it's a different namespace than `default`) AND port 443.
	c.Assert(repo.AllowsIngressRLocked(&ctx), Equals, api.Allowed)

	// Example 3: Allow all traffic to all pods in this namespace.
	ex3 := []byte(`{
  "kind": "NetworkPolicy",
  "apiVersion": "networking.k8s.io/v1",
  "metadata": {
    "name": "allow-all"
  },
  "spec": {
    "podSelector": null,
    "ingress": [
      {
      }
    ]
  }
}`)

	np = slim_networkingv1.NetworkPolicy{}
	err = json.Unmarshal(ex3, &np)
	c.Assert(err, IsNil)

	rules, err = ParseNetworkPolicy(&np)
	c.Assert(err, IsNil)
	c.Assert(len(rules), Equals, 1)

	repo = testNewPolicyRepository()
	repo.AddList(rules)
	ctx = policy.SearchContext{
		From: labels.LabelArray{
			labels.NewLabel(k8sConst.PodNamespaceLabel, "myns", labels.LabelSourceK8s),
			labels.NewLabel(policy.JoinPath(k8sConst.PodNamespaceMetaLabels, "user"), "bob", labels.LabelSourceK8s),
		},
		To: labels.LabelArray{
			labels.NewLabel(k8sConst.PodNamespaceLabel, slim_metav1.NamespaceDefault, labels.LabelSourceK8s),
			labels.NewLabel("role", "backend", labels.LabelSourceK8s),
		},
		Trace: policy.TRACE_VERBOSE,
	}
	// Should be ACCEPT since it's going to `default` namespace
	c.Assert(repo.AllowsIngressRLocked(&ctx), Equals, api.Allowed)

	ctx = policy.SearchContext{
		From: labels.LabelArray{
			labels.NewLabel(k8sConst.PodNamespaceLabel, slim_metav1.NamespaceDefault, labels.LabelSourceK8s),
			labels.NewLabel(policy.JoinPath(k8sConst.PodNamespaceMetaLabels, "user"), "bob", labels.LabelSourceK8s),
		},
		To: labels.LabelArray{
			labels.NewLabel(k8sConst.PodNamespaceLabel, slim_metav1.NamespaceDefault, labels.LabelSourceK8s),
			labels.NewLabel("role", "backend", labels.LabelSourceK8s),
		},
		Trace: policy.TRACE_VERBOSE,
	}
	// Should be ACCEPT since it's coming from `default` and going to `default` ns
	c.Assert(repo.AllowsIngressRLocked(&ctx), Equals, api.Allowed)

	ctx = policy.SearchContext{
		From: labels.LabelArray{
			labels.NewLabel(k8sConst.PodNamespaceLabel, slim_metav1.NamespaceDefault, labels.LabelSourceK8s),
			labels.NewLabel(policy.JoinPath(k8sConst.PodNamespaceMetaLabels, "user"), "bob", labels.LabelSourceK8s),
		},
		To: labels.LabelArray{
			labels.NewLabel(k8sConst.PodNamespaceLabel, slim_metav1.NamespaceDefault, labels.LabelSourceK8s),
			labels.NewLabel("role", "backend", labels.LabelSourceK8s),
		},
		DPorts: []*models.Port{
			{
				Port:     443,
				Protocol: models.PortProtocolTCP,
			},
		},
		Trace: policy.TRACE_VERBOSE,
	}
	// Should be ACCEPT since it's coming from `default` and going to `default` namespace.
	c.Assert(repo.AllowsIngressRLocked(&ctx), Equals, api.Allowed)

	// Example 4a: Example 4 is similar to example 2 but we will add both network
	// policies to see if the rules are additive for the same podSelector.
	ex4 := []byte(`{
  "kind": "NetworkPolicy",
  "apiVersion": "networking.k8s.io/v1",
  "metadata": {
    "name": "allow-tcp-8080"
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

	np = slim_networkingv1.NetworkPolicy{}
	err = json.Unmarshal(ex4, &np)
	c.Assert(err, IsNil)

	rules, err = ParseNetworkPolicy(&np)
	c.Assert(err, IsNil)
	c.Assert(len(rules), Equals, 1)

	// Example 4b: Example 4 is similar to example 2 but we will add both network
	// policies to see if the rules are additive for the same podSelector.
	ex4 = []byte(`{
  "kind": "NetworkPolicy",
  "apiVersion": "networking.k8s.io/v1",
  "metadata": {
    "name": "allow-tcp-8080"
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

	np = slim_networkingv1.NetworkPolicy{}
	err = json.Unmarshal(ex4, &np)
	c.Assert(err, IsNil)

	rules, err = ParseNetworkPolicy(&np)
	c.Assert(err, IsNil)
	c.Assert(len(rules), Equals, 1)

	repo = testNewPolicyRepository()
	// add example 4
	repo.AddList(rules)

	np = slim_networkingv1.NetworkPolicy{}
	err = json.Unmarshal(ex2, &np)
	c.Assert(err, IsNil)

	rules, err = ParseNetworkPolicy(&np)
	c.Assert(err, IsNil)
	// add example 2
	repo.AddList(rules)

	ctx = policy.SearchContext{
		From: labels.LabelArray{
			labels.NewLabel(k8sConst.PodNamespaceLabel, slim_metav1.NamespaceDefault, labels.LabelSourceK8s),
			labels.NewLabel(policy.JoinPath(k8sConst.PodNamespaceMetaLabels, "user"), "bob", labels.LabelSourceK8s),
		},
		DPorts: []*models.Port{
			{
				Protocol: models.PortProtocolUDP,
				Port:     8080,
			},
		},
		To: labels.LabelArray{
			labels.NewLabel(k8sConst.PodNamespaceLabel, slim_metav1.NamespaceDefault, labels.LabelSourceK8s),
			labels.NewLabel("role", "frontend", labels.LabelSourceK8s),
		},
		Trace: policy.TRACE_VERBOSE,
	}
	// Should be ACCEPT sense traffic comes from Bob's namespaces AND port 8080 as specified in `ex4`.
	c.Assert(repo.AllowsIngressRLocked(&ctx), Equals, api.Allowed)

	ctx = policy.SearchContext{
		From: labels.LabelArray{
			labels.NewLabel(k8sConst.PodNamespaceLabel, slim_metav1.NamespaceDefault, labels.LabelSourceK8s),
			labels.NewLabel(policy.JoinPath(k8sConst.PodNamespaceMetaLabels, "user"), "bob", labels.LabelSourceK8s),
		},
		DPorts: []*models.Port{
			{
				Port:     443,
				Protocol: models.PortProtocolTCP,
			},
		},
		To: labels.LabelArray{
			labels.NewLabel(k8sConst.PodNamespaceLabel, slim_metav1.NamespaceDefault, labels.LabelSourceK8s),
			labels.NewLabel("role", "frontend", labels.LabelSourceK8s),
		},
		Trace: policy.TRACE_VERBOSE,
	}
	// Should be ACCEPT sense traffic comes from Bob's namespaces AND port 443 as specified in `ex2`.
	c.Assert(repo.AllowsIngressRLocked(&ctx), Equals, api.Allowed)

	ctx = policy.SearchContext{
		From: labels.LabelArray{
			labels.NewLabel(k8sConst.PodNamespaceLabel, slim_metav1.NamespaceDefault, labels.LabelSourceK8s),
			labels.NewLabel(policy.JoinPath(k8sConst.PodNamespaceMetaLabels, "user"), "alice", labels.LabelSourceK8s),
		},
		DPorts: []*models.Port{
			{
				Protocol: models.PortProtocolUDP,
				Port:     8080,
			},
		},
		To: labels.LabelArray{
			labels.NewLabel(k8sConst.PodNamespaceLabel, slim_metav1.NamespaceDefault, labels.LabelSourceK8s),
			labels.NewLabel("role", "frontend", labels.LabelSourceK8s),
		},
		Trace: policy.TRACE_VERBOSE,
	}
	// Should be ACCEPT despite coming from Alice's namespaces since it's port 8080 as specified in `ex4`.
	c.Assert(repo.AllowsIngressRLocked(&ctx), Equals, api.Allowed)

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

	np = slim_networkingv1.NetworkPolicy{}
	err = json.Unmarshal(ex5, &np)
	c.Assert(err, IsNil)

	rules, err = ParseNetworkPolicy(&np)
	c.Assert(err, IsNil)
	c.Assert(len(rules), Equals, 1)
	repo.AddList(rules)

	// A reminder: from the kubernetes network policy spec:
	// namespaceSelector:
	//  Selects Namespaces using cluster scoped-labels.  This
	//  matches all pods in all namespaces selected by this label selector.
	//  This field follows standard label selector semantics.
	//  If omitted, this selector selects no namespaces.
	//  If present but empty, this selector selects all namespaces.
	ctx = policy.SearchContext{
		From: labels.LabelArray{
			// doesn't matter the namespace.
			labels.NewLabel(k8sConst.PodNamespaceLabel, "myns", labels.LabelSourceK8s),
			// component==redis is in the policy
			labels.NewLabel(policy.JoinPath(k8sConst.PodNamespaceMetaLabels, "component"), "redis", labels.LabelSourceK8s),
			// tier==cache is in the policy
			labels.NewLabel(policy.JoinPath(k8sConst.PodNamespaceMetaLabels, "tier"), "cache", labels.LabelSourceK8s),
			// environment is not in `dev` which is in the policy
			labels.NewLabel(policy.JoinPath(k8sConst.PodNamespaceMetaLabels, "environment"), "production", labels.LabelSourceK8s),
			// doesn't matter, there isn't any matchExpression denying traffic from any zone.
			labels.NewLabel(policy.JoinPath(k8sConst.PodNamespaceMetaLabels, "zone"), "eu-1", labels.LabelSourceK8s),
		},
		DPorts: []*models.Port{
			{
				Port:     8080,
				Protocol: models.PortProtocolUDP,
			},
		},
		To: labels.LabelArray{
			// Namespace needs to be in `expressions` since the policy is being enforced for that namespace.
			labels.NewLabel(k8sConst.PodNamespaceLabel, "expressions", labels.LabelSourceK8s),
			// component==redis is in the policy.
			labels.NewLabel("component", "redis", labels.LabelSourceK8s),
			// tier==cache is in the policy
			labels.NewLabel("tier", "cache", labels.LabelSourceK8s),
		},
		Trace: policy.TRACE_VERBOSE,
	}
	// Should be ACCEPT since the SearchContext is being covered by the rules.
	c.Assert(repo.AllowsIngressRLocked(&ctx), Equals, api.Allowed)

	ctx.To = labels.LabelArray{
		// Namespace needs to be in `expressions` since the policy is being enforced for that namespace.
		labels.NewLabel(k8sConst.PodNamespaceLabel, "myns", labels.LabelSourceK8s),
		// component==redis is in the policy.
		labels.NewLabel("component", "redis", labels.LabelSourceK8s),
		// tier==cache is in the policy
		labels.NewLabel("tier", "cache", labels.LabelSourceK8s),
	}
	// Should be DENY since the namespace doesn't belong to the policy.
	c.Assert(repo.AllowsIngressRLocked(&ctx), Equals, api.Denied)

	ctx = policy.SearchContext{
		From: labels.LabelArray{
			labels.NewLabel(policy.JoinPath(k8sConst.PodNamespaceMetaLabels, "component"), "redis", labels.LabelSourceK8s),
			labels.NewLabel(policy.JoinPath(k8sConst.PodNamespaceMetaLabels, "tier"), "cache", labels.LabelSourceK8s),
			labels.NewLabel(policy.JoinPath(k8sConst.PodNamespaceMetaLabels, "environment"), "dev", labels.LabelSourceK8s),
			labels.NewLabel(policy.JoinPath(k8sConst.PodNamespaceMetaLabels, "zone"), "eu-1", labels.LabelSourceK8s),
		},
		DPorts: []*models.Port{
			{
				Port:     8080,
				Protocol: models.PortProtocolUDP,
			},
		},
		To: labels.LabelArray{
			labels.NewLabel(k8sConst.PodNamespaceLabel, "expressions", labels.LabelSourceK8s),
			labels.NewLabel("component", "redis", labels.LabelSourceK8s),
			labels.NewLabel("tier", "cache", labels.LabelSourceK8s),
		},
		Trace: policy.TRACE_VERBOSE,
	}
	// Should be DENY since the environment is from dev.
	c.Assert(repo.AllowsIngressRLocked(&ctx), Equals, api.Denied)

	ctx = policy.SearchContext{
		From: labels.LabelArray{
			labels.NewLabel(policy.JoinPath(k8sConst.PodNamespaceMetaLabels, "component"), "redis", labels.LabelSourceK8s),
			labels.NewLabel(policy.JoinPath(k8sConst.PodNamespaceMetaLabels, "tier"), "cache", labels.LabelSourceK8s),
		},
		DPorts: []*models.Port{
			{
				Port:     8080,
				Protocol: models.PortProtocolUDP,
			},
		},
		To: labels.LabelArray{
			labels.NewLabel(k8sConst.PodNamespaceLabel, "expressions", labels.LabelSourceK8s),
			labels.NewLabel("component", "redis", labels.LabelSourceK8s),
			labels.NewLabel("tier", "cache", labels.LabelSourceK8s),
		},
		Trace: policy.TRACE_VERBOSE,
	}
	// Should be ACCEPT since the environment is from dev.
	c.Assert(repo.AllowsIngressRLocked(&ctx), Equals, api.Allowed)
}

func (s *K8sSuite) TestCIDRPolicyExamples(c *C) {
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
	c.Assert(err, IsNil)

	rules, err := ParseNetworkPolicy(&np)
	c.Assert(err, IsNil)
	c.Assert(rules, NotNil)
	c.Assert(len(rules), Equals, 1)
	c.Assert(len(rules[0].Ingress), Equals, 2)

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
	c.Assert(err, IsNil)

	rules, err = ParseNetworkPolicy(&np)
	c.Assert(err, IsNil)
	c.Assert(rules, NotNil)
	c.Assert(len(rules), Equals, 1)
	c.Assert(rules[0].Egress[0].ToCIDRSet[0].Cidr, Equals, api.CIDR("10.0.0.0/8"))

	expectedCIDRs := []api.CIDR{"10.96.0.0/12", "10.255.255.254/32"}
	for k, v := range rules[0].Egress[0].ToCIDRSet[0].ExceptCIDRs {
		c.Assert(v, Equals, expectedCIDRs[k])
	}

	expectedCIDRs = []api.CIDR{"11.96.0.0/12", "11.255.255.254/32"}
	for k, v := range rules[0].Egress[1].ToCIDRSet[0].ExceptCIDRs {
		c.Assert(v, Equals, expectedCIDRs[k])
	}

	c.Assert(len(rules[0].Egress), Equals, 2)

}

func getSelectorPointer(sel api.EndpointSelector) *api.EndpointSelector {
	return &sel
}

func Test_parseNetworkPolicyPeer(t *testing.T) {
	type args struct {
		namespace string
		peer      *slim_networkingv1.NetworkPolicyPeer
	}
	tests := []struct {
		name string
		args args
		want *api.EndpointSelector
	}{
		{
			name: "peer-with-pod-selector",
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
				},
			},
			want: getSelectorPointer(
				api.NewESFromMatchRequirements(
					map[string]string{
						"k8s.foo":                         "bar",
						"k8s.io.kubernetes.pod.namespace": "foo-namespace",
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
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := parseNetworkPolicyPeer(tt.args.namespace, tt.args.peer)
			args := []interface{}{got, tt.want}
			names := []string{"obtained", "expected"}
			if equal, err := checker.DeepEquals.Check(args, names); !equal {
				t.Errorf("Failed to parseNetworkPolicyPeer():\n%s", err)
			}
		})
	}
}

func (s *K8sSuite) TestGetPolicyLabelsv1(c *C) {
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
		c.Assert(lbl.Key, Equals, key)
		c.Assert(lbl.Value, Equals, value)
		c.Assert(lbl.Source, Equals, labels.LabelSourceK8s)
	}

	for _, tt := range tests {
		lbls := GetPolicyLabelsv1(tt.np)

		c.Assert(lbls, NotNil)
		c.Assert(len(lbls), Equals, 4, Commentf(
			"Incorrect number of labels: Expected DerivedFrom, Name, Namespace and UID labels."))
		assertLabel(lbls[0], "io.cilium.k8s.policy.derived-from", tt.derivedFrom)
		assertLabel(lbls[1], "io.cilium.k8s.policy.name", tt.name)
		assertLabel(lbls[2], "io.cilium.k8s.policy.namespace", tt.namespace)
		assertLabel(lbls[3], "io.cilium.k8s.policy.uid", tt.uuid)
	}
}

func (s *K8sSuite) TestIPBlockToCIDRRule(c *C) {
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

		c.Assert(cidrRule.Generated, Equals, false)
		c.Assert(cidrRule.Cidr, Equals, api.CIDR(block.CIDR))

		if block.Except == nil || len(block.Except) == 0 {
			c.Assert(cidrRule.ExceptCIDRs, IsNil)
		} else {
			c.Assert(cidrRule.ExceptCIDRs, checker.DeepEquals, exceptCIDRs)
		}
	}
}

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

// FIXME Remove this file in k8s 1.8

import (
	"encoding/json"
	"fmt"

	"github.com/cilium/cilium/api/v1/models"
	"github.com/cilium/cilium/pkg/comparator"
	k8sconst "github.com/cilium/cilium/pkg/k8s/apis/cilium.io"
	"github.com/cilium/cilium/pkg/labels"
	"github.com/cilium/cilium/pkg/policy"
	"github.com/cilium/cilium/pkg/policy/api"

	. "gopkg.in/check.v1"
	"k8s.io/api/core/v1"
	"k8s.io/api/extensions/v1beta1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/intstr"
)

func (s *K8sSuite) TestParseNetworkPolicyDeprecated(c *C) {
	netPolicy := &v1beta1.NetworkPolicy{
		Spec: v1beta1.NetworkPolicySpec{
			PodSelector: metav1.LabelSelector{
				MatchLabels: map[string]string{
					"foo1": "bar1",
					"foo2": "bar2",
				},
			},
			Ingress: []v1beta1.NetworkPolicyIngressRule{
				{
					From: []v1beta1.NetworkPolicyPeer{
						{
							PodSelector: &metav1.LabelSelector{
								MatchLabels: map[string]string{
									"foo3": "bar3",
									"foo4": "bar4",
								},
							},
						},
					},
					Ports: []v1beta1.NetworkPolicyPort{
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

	rules, err := ParseNetworkPolicyDeprecated(netPolicy)
	c.Assert(err, IsNil)
	c.Assert(len(rules), Equals, 1)

	fromEndpoints := labels.LabelArray{
		labels.NewLabel(k8sconst.PodNamespaceLabel, v1.NamespaceDefault, labels.LabelSourceK8s),
		labels.NewLabel("foo3", "bar3", labels.LabelSourceK8s),
		labels.NewLabel("foo4", "bar4", labels.LabelSourceK8s),
	}
	ctx := policy.SearchContext{
		From: fromEndpoints,
		To: labels.LabelArray{
			labels.NewLabel(k8sconst.PodNamespaceLabel, v1.NamespaceDefault, labels.LabelSourceK8s),
			labels.NewLabel("foo1", "bar1", labels.LabelSourceK8s),
			labels.NewLabel("foo2", "bar2", labels.LabelSourceK8s),
		},
		Trace: policy.TRACE_VERBOSE,
	}

	repo := policy.NewPolicyRepository()
	repo.AddList(rules)
	c.Assert(repo.AllowsRLocked(&ctx), Equals, api.Denied)

	matchLabels := make(map[string]string)
	for _, v := range fromEndpoints {
		matchLabels[fmt.Sprintf("%s.%s", v.Source, v.Key)] = v.Value
	}
	lblSelector := metav1.LabelSelector{
		MatchLabels: matchLabels,
	}
	epSelector := api.EndpointSelector{
		LabelSelector: &lblSelector,
	}

	result, err := repo.ResolveL4Policy(&ctx)
	c.Assert(result, Not(IsNil))
	c.Assert(err, IsNil)
	c.Assert(result, comparator.DeepEquals, &policy.L4Policy{
		Ingress: policy.L4PolicyMap{
			Filters: map[string]policy.L4Filter{
				"80/TCP": {
					Port: 80, Protocol: api.ProtoTCP, U8Proto: 6,
					FromEndpoints:  []api.EndpointSelector{epSelector},
					L7Parser:       "",
					L7RedirectPort: 0, L7RulesPerEp: policy.L7DataMap{},
					Ingress: true,
				},
			},
		},
		Egress: policy.L4PolicyMap{
			Filters: map[string]policy.L4Filter{},
		},
	})

	ctx.To = labels.LabelArray{
		labels.NewLabel("foo2", "bar2", labels.LabelSourceK8s),
	}

	// ctx.To needs to have all labels from the policy in order to be accepted
	c.Assert(repo.CanReachRLocked(&ctx), Not(Equals), api.Allowed)

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
	c.Assert(repo.CanReachRLocked(&ctx), Not(Equals), api.Allowed)
}

func (s *K8sSuite) TestParseNetworkPolicyUnknownProtoDeprecated(c *C) {
	netPolicy := &v1beta1.NetworkPolicy{
		Spec: v1beta1.NetworkPolicySpec{
			Ingress: []v1beta1.NetworkPolicyIngressRule{
				{
					Ports: []v1beta1.NetworkPolicyPort{
						{
							Port: &intstr.IntOrString{
								Type:   intstr.String,
								StrVal: "unknown",
							},
						},
					},
				},
			},
		},
	}

	rules, err := ParseNetworkPolicyDeprecated(netPolicy)
	c.Assert(err, Not(IsNil))
	c.Assert(len(rules), Equals, 0)
}

func (s *K8sSuite) TestParseNetworkPolicyEmptyFromDeprecated(c *C) {
	// From missing, all sources should be allowed
	netPolicy1 := &v1beta1.NetworkPolicy{
		Spec: v1beta1.NetworkPolicySpec{
			PodSelector: metav1.LabelSelector{
				MatchLabels: map[string]string{
					"foo1": "bar1",
				},
			},
			Ingress: []v1beta1.NetworkPolicyIngressRule{
				{},
			},
		},
	}

	rules, err := ParseNetworkPolicyDeprecated(netPolicy1)
	c.Assert(err, IsNil)
	c.Assert(len(rules), Equals, 1)

	ctx := policy.SearchContext{
		From: labels.LabelArray{
			labels.NewLabel(k8sconst.PodNamespaceLabel, v1.NamespaceDefault, labels.LabelSourceK8s),
			labels.NewLabel("foo0", "bar0", labels.LabelSourceK8s),
		},
		To: labels.LabelArray{
			labels.NewLabel(k8sconst.PodNamespaceLabel, v1.NamespaceDefault, labels.LabelSourceK8s),
			labels.NewLabel("foo1", "bar1", labels.LabelSourceK8s),
		},
		Trace: policy.TRACE_VERBOSE,
	}

	repo := policy.NewPolicyRepository()
	repo.AddList(rules)
	c.Assert(repo.CanReachRLocked(&ctx), Equals, api.Allowed)

	// Empty From rules, all sources should be allowed
	netPolicy2 := &v1beta1.NetworkPolicy{
		Spec: v1beta1.NetworkPolicySpec{
			PodSelector: metav1.LabelSelector{
				MatchLabels: map[string]string{
					"foo1": "bar1",
				},
			},
			Ingress: []v1beta1.NetworkPolicyIngressRule{
				{
					From:  []v1beta1.NetworkPolicyPeer{},
					Ports: []v1beta1.NetworkPolicyPort{},
				},
			},
		},
	}

	rules, err = ParseNetworkPolicyDeprecated(netPolicy2)
	c.Assert(err, IsNil)
	c.Assert(len(rules), Equals, 1)
	repo = policy.NewPolicyRepository()
	repo.AddList(rules)
	c.Assert(repo.CanReachRLocked(&ctx), Equals, api.Allowed)
}

func (s *K8sSuite) TestParseNetworkPolicyDenyAllDeprecated(c *C) {
	// From missing, all sources should be allowed
	netPolicy1 := &v1beta1.NetworkPolicy{
		Spec: v1beta1.NetworkPolicySpec{
			PodSelector: metav1.LabelSelector{
				MatchLabels: map[string]string{},
			},
		},
	}

	rules, err := ParseNetworkPolicyDeprecated(netPolicy1)
	c.Assert(err, IsNil)
	c.Assert(len(rules), Equals, 1)

	ctx := policy.SearchContext{
		From: labels.LabelArray{
			labels.NewLabel(k8sconst.PodNamespaceLabel, v1.NamespaceDefault, labels.LabelSourceK8s),
			labels.NewLabel("foo0", "bar0", labels.LabelSourceK8s),
		},
		To: labels.LabelArray{
			labels.NewLabel(k8sconst.PodNamespaceLabel, v1.NamespaceDefault, labels.LabelSourceK8s),
			labels.NewLabel("foo1", "bar1", labels.LabelSourceK8s),
		},
		Trace: policy.TRACE_VERBOSE,
	}

	repo := policy.NewPolicyRepository()
	repo.AddList(rules)
	c.Assert(repo.AllowsRLocked(&ctx), Equals, api.Denied)
}

func (s *K8sSuite) TestParseNetworkPolicyNoIngressDeprecated(c *C) {
	netPolicy := &v1beta1.NetworkPolicy{
		Spec: v1beta1.NetworkPolicySpec{
			PodSelector: metav1.LabelSelector{
				MatchLabels: map[string]string{
					"foo1": "bar1",
					"foo2": "bar2",
				},
			},
		},
	}

	rules, err := ParseNetworkPolicyDeprecated(netPolicy)
	c.Assert(err, IsNil)
	c.Assert(len(rules), Equals, 1)
}

func (s *K8sSuite) TestNetworkPolicyExamplesDeprecated(c *C) {
	// Example 1: Only allow traffic from frontend pods on TCP port 6379 to
	// backend pods in the same namespace `myns`.
	ex1 := []byte(`{
  "kind": "NetworkPolicy",
  "apiVersion": "extensions/v1beta1",
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
	np := v1beta1.NetworkPolicy{}
	err := json.Unmarshal(ex1, &np)
	c.Assert(err, IsNil)

	rules, err := ParseNetworkPolicyDeprecated(&np)
	c.Assert(err, IsNil)
	c.Assert(len(rules), Equals, 1)

	repo := policy.NewPolicyRepository()
	repo.AddList(rules)
	ctx := policy.SearchContext{
		From: labels.LabelArray{
			labels.NewLabel(k8sconst.PodNamespaceLabel, "myns", labels.LabelSourceK8s),
			labels.NewLabel("role", "frontend", labels.LabelSourceK8s),
		},
		To: labels.LabelArray{
			labels.NewLabel("role", "backend", labels.LabelSourceK8s),
		},
		Trace: policy.TRACE_VERBOSE,
	}
	// Doesn't share the same namespace
	c.Assert(repo.AllowsRLocked(&ctx), Equals, api.Denied)

	ctx = policy.SearchContext{
		From: labels.LabelArray{
			labels.NewLabel(k8sconst.PodNamespaceLabel, v1.NamespaceDefault, labels.LabelSourceK8s),
			labels.NewLabel("role", "frontend", labels.LabelSourceK8s),
		},
		To: labels.LabelArray{
			labels.NewLabel("role", "backend", labels.LabelSourceK8s),
		},
		Trace: policy.TRACE_VERBOSE,
	}
	// Doesn't share the same namespace
	c.Assert(repo.AllowsRLocked(&ctx), Equals, api.Denied)

	ctx = policy.SearchContext{
		From: labels.LabelArray{
			labels.NewLabel(k8sconst.PodNamespaceLabel, "myns", labels.LabelSourceK8s),
			labels.NewLabel("role", "frontend", labels.LabelSourceK8s),
		},
		To: labels.LabelArray{
			labels.NewLabel(k8sconst.PodNamespaceLabel, "myns", labels.LabelSourceK8s),
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
	c.Assert(repo.AllowsRLocked(&ctx), Equals, api.Allowed)

	// Example 2: Allow TCP 443 from any source in Bob's namespaces.
	ex2 := []byte(`{
  "kind": "NetworkPolicy",
  "apiVersion": "extensions/v1beta1",
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

	np = v1beta1.NetworkPolicy{}
	err = json.Unmarshal(ex2, &np)
	c.Assert(err, IsNil)

	rules, err = ParseNetworkPolicyDeprecated(&np)
	c.Assert(err, IsNil)
	c.Assert(len(rules), Equals, 1)

	repo = policy.NewPolicyRepository()
	repo.AddList(rules)
	ctx = policy.SearchContext{
		From: labels.LabelArray{
			labels.NewLabel(k8sconst.PodNamespaceLabel, v1.NamespaceDefault, labels.LabelSourceK8s),
			labels.NewLabel(policy.JoinPath(PodNamespaceMetaLabels, "user"), "bob", labels.LabelSourceK8s),
		},
		To: labels.LabelArray{
			labels.NewLabel(k8sconst.PodNamespaceLabel, v1.NamespaceDefault, labels.LabelSourceK8s),
			labels.NewLabel("role", "frontend", labels.LabelSourceK8s),
		},
		Trace: policy.TRACE_VERBOSE,
	}

	// Should be DENY sense the traffic needs to come from
	// namespace `user=bob` AND port 443.
	c.Assert(repo.AllowsRLocked(&ctx), Equals, api.Denied)
	l4Policy, err := repo.ResolveL4Policy(&ctx)
	c.Assert(l4Policy, Not(IsNil))
	c.Assert(err, IsNil)
	l4Veridict := l4Policy.IngressCoversDPorts([]*models.Port{})
	c.Assert(l4Veridict, Equals, api.Denied)

	ctx = policy.SearchContext{
		From: labels.LabelArray{
			labels.NewLabel(k8sconst.PodNamespaceLabel, "myns", labels.LabelSourceK8s),
			labels.NewLabel(policy.JoinPath(PodNamespaceMetaLabels, "user"), "bob", labels.LabelSourceK8s),
		},
		DPorts: []*models.Port{
			{
				Port:     443,
				Protocol: models.PortProtocolTCP,
			},
		},
		To: labels.LabelArray{
			labels.NewLabel(k8sconst.PodNamespaceLabel, v1.NamespaceDefault, labels.LabelSourceK8s),
			labels.NewLabel("role", "frontend", labels.LabelSourceK8s),
		},
		Trace: policy.TRACE_VERBOSE,
	}
	// Should be ACCEPT sense the traffic comes from Bob's namespaces
	// (even if it's a different namespace than `default`) AND port 443.
	c.Assert(repo.AllowsRLocked(&ctx), Equals, api.Allowed)

	// Example 3: Allow all traffic to all pods in this namespace.
	ex3 := []byte(`{
  "kind": "NetworkPolicy",
  "apiVersion": "extensions/v1beta1",
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

	np = v1beta1.NetworkPolicy{}
	err = json.Unmarshal(ex3, &np)
	c.Assert(err, IsNil)

	rules, err = ParseNetworkPolicyDeprecated(&np)
	c.Assert(err, IsNil)
	c.Assert(len(rules), Equals, 1)

	repo = policy.NewPolicyRepository()
	repo.AddList(rules)
	ctx = policy.SearchContext{
		From: labels.LabelArray{
			labels.NewLabel(k8sconst.PodNamespaceLabel, "myns", labels.LabelSourceK8s),
			labels.NewLabel(policy.JoinPath(PodNamespaceMetaLabels, "user"), "bob", labels.LabelSourceK8s),
		},
		To: labels.LabelArray{
			labels.NewLabel(k8sconst.PodNamespaceLabel, v1.NamespaceDefault, labels.LabelSourceK8s),
			labels.NewLabel("role", "backend", labels.LabelSourceK8s),
		},
		Trace: policy.TRACE_VERBOSE,
	}
	// Should be ACCEPT since it's going to `default` namespace
	c.Assert(repo.AllowsRLocked(&ctx), Equals, api.Allowed)

	ctx = policy.SearchContext{
		From: labels.LabelArray{
			labels.NewLabel(k8sconst.PodNamespaceLabel, v1.NamespaceDefault, labels.LabelSourceK8s),
			labels.NewLabel(policy.JoinPath(PodNamespaceMetaLabels, "user"), "bob", labels.LabelSourceK8s),
		},
		To: labels.LabelArray{
			labels.NewLabel(k8sconst.PodNamespaceLabel, v1.NamespaceDefault, labels.LabelSourceK8s),
			labels.NewLabel("role", "backend", labels.LabelSourceK8s),
		},
		Trace: policy.TRACE_VERBOSE,
	}
	// Should be ACCEPT since it's coming from `default` and going to `default` ns
	c.Assert(repo.AllowsRLocked(&ctx), Equals, api.Allowed)

	ctx = policy.SearchContext{
		From: labels.LabelArray{
			labels.NewLabel(k8sconst.PodNamespaceLabel, v1.NamespaceDefault, labels.LabelSourceK8s),
			labels.NewLabel(policy.JoinPath(PodNamespaceMetaLabels, "user"), "bob", labels.LabelSourceK8s),
		},
		To: labels.LabelArray{
			labels.NewLabel(k8sconst.PodNamespaceLabel, v1.NamespaceDefault, labels.LabelSourceK8s),
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
	c.Assert(repo.AllowsRLocked(&ctx), Equals, api.Allowed)

	// Example 4: Example 4 is similar to example 2 but we will add both network
	// policies to see if the rules are additive for the same podSelector.
	ex4 := []byte(`{
  "kind": "NetworkPolicy",
  "apiVersion": "extensions/v1beta1",
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
      }, {
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

	np = v1beta1.NetworkPolicy{}
	err = json.Unmarshal(ex4, &np)
	c.Assert(err, IsNil)

	rules, err = ParseNetworkPolicyDeprecated(&np)
	c.Assert(err, IsNil)
	c.Assert(len(rules), Equals, 1)

	repo = policy.NewPolicyRepository()
	// add example 4
	repo.AddList(rules)

	np = v1beta1.NetworkPolicy{}
	err = json.Unmarshal(ex2, &np)
	c.Assert(err, IsNil)

	rules, err = ParseNetworkPolicyDeprecated(&np)
	// add example 2
	repo.AddList(rules)

	ctx = policy.SearchContext{
		From: labels.LabelArray{
			labels.NewLabel(k8sconst.PodNamespaceLabel, v1.NamespaceDefault, labels.LabelSourceK8s),
			labels.NewLabel(policy.JoinPath(PodNamespaceMetaLabels, "user"), "bob", labels.LabelSourceK8s),
		},
		DPorts: []*models.Port{
			{
				Protocol: models.PortProtocolUDP,
				Port:     8080,
			},
		},
		To: labels.LabelArray{
			labels.NewLabel(k8sconst.PodNamespaceLabel, v1.NamespaceDefault, labels.LabelSourceK8s),
			labels.NewLabel("role", "frontend", labels.LabelSourceK8s),
		},
		Trace: policy.TRACE_VERBOSE,
	}
	// Should be ACCEPT sense traffic comes from Bob's namespaces AND port 8080 as specified in `ex4`.
	c.Assert(repo.AllowsRLocked(&ctx), Equals, api.Allowed)

	ctx = policy.SearchContext{
		From: labels.LabelArray{
			labels.NewLabel(k8sconst.PodNamespaceLabel, v1.NamespaceDefault, labels.LabelSourceK8s),
			labels.NewLabel(policy.JoinPath(PodNamespaceMetaLabels, "user"), "bob", labels.LabelSourceK8s),
		},
		DPorts: []*models.Port{
			{
				Port:     443,
				Protocol: models.PortProtocolTCP,
			},
		},
		To: labels.LabelArray{
			labels.NewLabel(k8sconst.PodNamespaceLabel, v1.NamespaceDefault, labels.LabelSourceK8s),
			labels.NewLabel("role", "frontend", labels.LabelSourceK8s),
		},
		Trace: policy.TRACE_VERBOSE,
	}
	// Should be ACCEPT sense traffic comes from Bob's namespaces AND port 443 as specified in `ex2`.
	c.Assert(repo.AllowsRLocked(&ctx), Equals, api.Allowed)

	// Example 5: Some policies with match expressions.
	ex5 := []byte(`{
  "kind": "NetworkPolicy",
  "apiVersion": "extensions/v1beta1",
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

	np = v1beta1.NetworkPolicy{}
	err = json.Unmarshal(ex5, &np)
	c.Assert(err, IsNil)

	rules, err = ParseNetworkPolicyDeprecated(&np)
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
			labels.NewLabel(k8sconst.PodNamespaceLabel, "myns", labels.LabelSourceK8s),
			// component==redis is in the policy
			labels.NewLabel(policy.JoinPath(PodNamespaceMetaLabels, "component"), "redis", labels.LabelSourceK8s),
			// tier==cache is in the policy
			labels.NewLabel(policy.JoinPath(PodNamespaceMetaLabels, "tier"), "cache", labels.LabelSourceK8s),
			// environment is not in `dev` which is in the policy
			labels.NewLabel(policy.JoinPath(PodNamespaceMetaLabels, "environment"), "production", labels.LabelSourceK8s),
			// doesn't matter, there isn't any matchExpression denying traffic from any zone.
			labels.NewLabel(policy.JoinPath(PodNamespaceMetaLabels, "zone"), "eu-1", labels.LabelSourceK8s),
		},
		DPorts: []*models.Port{
			{
				Port:     8080,
				Protocol: models.PortProtocolUDP,
			},
		},
		To: labels.LabelArray{
			// Namespace needs to be in `expressions` since the policy is being enforced for that namespace.
			labels.NewLabel(k8sconst.PodNamespaceLabel, "expressions", labels.LabelSourceK8s),
			// component==redis is in the policy.
			labels.NewLabel("component", "redis", labels.LabelSourceK8s),
			// tier==cache is in the policy
			labels.NewLabel("tier", "cache", labels.LabelSourceK8s),
		},
		Trace: policy.TRACE_VERBOSE,
	}
	// Should be ACCEPT since the SearchContext is being covered by the rules.
	c.Assert(repo.AllowsRLocked(&ctx), Equals, api.Allowed)

	ctx.To = labels.LabelArray{
		// Namespace needs to be in `expressions` since the policy is being enforced for that namespace.
		labels.NewLabel(k8sconst.PodNamespaceLabel, "myns", labels.LabelSourceK8s),
		// component==redis is in the policy.
		labels.NewLabel("component", "redis", labels.LabelSourceK8s),
		// tier==cache is in the policy
		labels.NewLabel("tier", "cache", labels.LabelSourceK8s),
	}
	// Should be DENY since the namespace doesn't belong to the policy.
	c.Assert(repo.AllowsRLocked(&ctx), Equals, api.Denied)

	ctx = policy.SearchContext{
		From: labels.LabelArray{
			labels.NewLabel(policy.JoinPath(PodNamespaceMetaLabels, "component"), "redis", labels.LabelSourceK8s),
			labels.NewLabel(policy.JoinPath(PodNamespaceMetaLabels, "tier"), "cache", labels.LabelSourceK8s),
			labels.NewLabel(policy.JoinPath(PodNamespaceMetaLabels, "environment"), "dev", labels.LabelSourceK8s),
			labels.NewLabel(policy.JoinPath(PodNamespaceMetaLabels, "zone"), "eu-1", labels.LabelSourceK8s),
		},
		DPorts: []*models.Port{
			{
				Port:     8080,
				Protocol: models.PortProtocolUDP,
			},
		},
		To: labels.LabelArray{
			labels.NewLabel(k8sconst.PodNamespaceLabel, "expressions", labels.LabelSourceK8s),
			labels.NewLabel("component", "redis", labels.LabelSourceK8s),
			labels.NewLabel("tier", "cache", labels.LabelSourceK8s),
		},
		Trace: policy.TRACE_VERBOSE,
	}
	// Should be DENY since the environment is from dev.
	c.Assert(repo.AllowsRLocked(&ctx), Equals, api.Denied)

	ctx = policy.SearchContext{
		From: labels.LabelArray{
			labels.NewLabel(policy.JoinPath(PodNamespaceMetaLabels, "component"), "redis", labels.LabelSourceK8s),
			labels.NewLabel(policy.JoinPath(PodNamespaceMetaLabels, "tier"), "cache", labels.LabelSourceK8s),
		},
		DPorts: []*models.Port{
			{
				Port:     8080,
				Protocol: models.PortProtocolUDP,
			},
		},
		To: labels.LabelArray{
			labels.NewLabel(k8sconst.PodNamespaceLabel, "expressions", labels.LabelSourceK8s),
			labels.NewLabel("component", "redis", labels.LabelSourceK8s),
			labels.NewLabel("tier", "cache", labels.LabelSourceK8s),
		},
		Trace: policy.TRACE_VERBOSE,
	}
	// Should be ACCEPT since the environment is from dev.
	c.Assert(repo.AllowsRLocked(&ctx), Equals, api.Allowed)
}

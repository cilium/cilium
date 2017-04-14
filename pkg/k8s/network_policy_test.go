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
	"testing"

	"github.com/cilium/cilium/common"
	"github.com/cilium/cilium/pkg/labels"
	"github.com/cilium/cilium/pkg/policy"
	"github.com/cilium/cilium/pkg/policy/api"

	. "gopkg.in/check.v1"
	"k8s.io/client-go/1.5/pkg/apis/extensions/v1beta1"
	"k8s.io/client-go/1.5/pkg/util/intstr"
)

// Hook up gocheck into the "go test" runner.
func Test(t *testing.T) {
	TestingT(t)
}

type K8sSuite struct{}

var _ = Suite(&K8sSuite{})

func (s *K8sSuite) TestParseNetworkPolicy(c *C) {
	netPolicy := &v1beta1.NetworkPolicy{
		Spec: v1beta1.NetworkPolicySpec{
			PodSelector: v1beta1.LabelSelector{
				MatchLabels: map[string]string{
					"foo1": "bar1",
					"foo2": "bar2",
				},
			},
			Ingress: []v1beta1.NetworkPolicyIngressRule{
				v1beta1.NetworkPolicyIngressRule{
					From: []v1beta1.NetworkPolicyPeer{
						v1beta1.NetworkPolicyPeer{
							PodSelector: &v1beta1.LabelSelector{
								MatchLabels: map[string]string{
									"foo3": "bar3",
									"foo4": "bar4",
								},
							},
						},
					},
					Ports: []v1beta1.NetworkPolicyPort{
						v1beta1.NetworkPolicyPort{
							Port: &intstr.IntOrString{
								Type:   intstr.String,
								StrVal: "http",
							},
						},
					},
				},
			},
		},
	}

	parent, node, err := ParseNetworkPolicy(netPolicy)
	c.Assert(err, IsNil)
	c.Assert(parent, Equals, DefaultPolicyParentPath)
	c.Assert(node, Not(IsNil))

	ctx := policy.SearchContext{
		From: labels.LabelArray{
			labels.NewLabel("foo3", "bar3", common.K8sLabelSource),
			labels.NewLabel("foo4", "bar4", common.K8sLabelSource),
		},
		To: labels.LabelArray{
			labels.NewLabel("foo1", "bar1", common.K8sLabelSource),
			labels.NewLabel("foo2", "bar2", common.K8sLabelSource),
		},
		Trace: policy.TRACE_VERBOSE,
	}
	c.Assert(node.Allows(&ctx), Equals, api.ALWAYS_ACCEPT)

	result := policy.NewL4Policy()
	node.ResolveL4Policy(&ctx, result)
	c.Assert(result, DeepEquals, &policy.L4Policy{
		Ingress: policy.L4PolicyMap{
			"tcp:80": policy.L4Filter{
				Port: 80, Protocol: "tcp", L7Parser: "",
				L7RedirectPort: 0, L7Rules: []policy.AuxRule(nil),
			},
		},
		Egress: policy.L4PolicyMap{},
	})
}

func (s *K8sSuite) TestParseNetworkPolicyUnknownProto(c *C) {
	netPolicy := &v1beta1.NetworkPolicy{
		Spec: v1beta1.NetworkPolicySpec{
			Ingress: []v1beta1.NetworkPolicyIngressRule{
				v1beta1.NetworkPolicyIngressRule{
					Ports: []v1beta1.NetworkPolicyPort{
						v1beta1.NetworkPolicyPort{
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

	parent, node, err := ParseNetworkPolicy(netPolicy)
	c.Assert(err, Not(IsNil))
	c.Assert(parent, Equals, "")
	c.Assert(node, IsNil)
}

func (s *K8sSuite) TestParseNetworkPolicyEmptyFrom(c *C) {
	// From missing, all sources should be allowed
	netPolicy1 := &v1beta1.NetworkPolicy{
		Spec: v1beta1.NetworkPolicySpec{
			PodSelector: v1beta1.LabelSelector{
				MatchLabels: map[string]string{
					"foo1": "bar1",
				},
			},
			Ingress: []v1beta1.NetworkPolicyIngressRule{
				v1beta1.NetworkPolicyIngressRule{},
			},
		},
	}

	parent, node, err := ParseNetworkPolicy(netPolicy1)
	c.Assert(err, IsNil)
	c.Assert(parent, Equals, DefaultPolicyParentPath)
	c.Assert(node, Not(IsNil))

	ctx := policy.SearchContext{
		From: labels.LabelArray{
			labels.NewLabel("foo0", "bar0", common.K8sLabelSource),
		},
		To: labels.LabelArray{
			labels.NewLabel("foo1", "bar1", common.K8sLabelSource),
		},
		Trace: policy.TRACE_VERBOSE,
	}
	c.Assert(node.Allows(&ctx), Equals, api.ALWAYS_ACCEPT)

	// Empty From rules, all sources should be allowed
	netPolicy2 := &v1beta1.NetworkPolicy{
		Spec: v1beta1.NetworkPolicySpec{
			PodSelector: v1beta1.LabelSelector{
				MatchLabels: map[string]string{
					"foo1": "bar1",
				},
			},
			Ingress: []v1beta1.NetworkPolicyIngressRule{
				v1beta1.NetworkPolicyIngressRule{
					From:  []v1beta1.NetworkPolicyPeer{},
					Ports: []v1beta1.NetworkPolicyPort{},
				},
			},
		},
	}

	parent, node, err = ParseNetworkPolicy(netPolicy2)
	c.Assert(err, IsNil)
	c.Assert(parent, Equals, DefaultPolicyParentPath)
	c.Assert(node, Not(IsNil))
	c.Assert(node.Allows(&ctx), Equals, api.ALWAYS_ACCEPT)
}

func (s *K8sSuite) TestParseNetworkPolicyNoIngress(c *C) {
	netPolicy := &v1beta1.NetworkPolicy{
		Spec: v1beta1.NetworkPolicySpec{
			PodSelector: v1beta1.LabelSelector{
				MatchLabels: map[string]string{
					"foo1": "bar1",
					"foo2": "bar2",
				},
			},
		},
	}

	parent, node, err := ParseNetworkPolicy(netPolicy)
	c.Assert(err, IsNil)
	c.Assert(parent, Equals, DefaultPolicyParentPath)
	c.Assert(node, Not(IsNil))
}

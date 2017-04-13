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
				},
			},
		},
	}

	parent, node, err := ParseNetworkPolicy(netPolicy)
	c.Assert(parent, Equals, DefaultPolicyParentPath)
	c.Assert(node, Not(IsNil))
	c.Assert(err, IsNil)

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
	c.Assert(parent, Equals, DefaultPolicyParentPath)
	c.Assert(node, Not(IsNil))
	c.Assert(err, IsNil)
}

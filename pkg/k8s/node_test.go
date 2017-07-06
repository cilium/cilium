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
	. "gopkg.in/check.v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/pkg/api/v1"
)

func (s *K8sSuite) TestParseNode(c *C) {
	// PodCIDR takes precedence over annotations
	k8sNode := &v1.Node{
		ObjectMeta: metav1.ObjectMeta{
			Name: "node1",
			Annotations: map[string]string{
				Annotationv4CIDRName: "10.254.0.0/16",
				Annotationv6CIDRName: "f00d:aaaa:bbbb:cccc:dddd:eeee::/112",
			},
		},
		Spec: v1.NodeSpec{
			PodCIDR: "10.1.0.0/16",
		},
	}

	n := ParseNode(k8sNode)
	c.Assert(n.Name, Equals, "node1")
	c.Assert(n.IPv4AllocCIDR, NotNil)
	c.Assert(n.IPv4AllocCIDR.String(), Equals, "10.1.0.0/16")
	c.Assert(n.IPv6AllocCIDR, NotNil)
	c.Assert(n.IPv6AllocCIDR.String(), Equals, "f00d:aaaa:bbbb:cccc:dddd:eeee::/112")

	// No IPv6 annotation
	k8sNode = &v1.Node{
		ObjectMeta: metav1.ObjectMeta{
			Name: "node2",
			Annotations: map[string]string{
				Annotationv4CIDRName: "10.254.0.0/16",
			},
		},
		Spec: v1.NodeSpec{
			PodCIDR: "10.1.0.0/16",
		},
	}

	n = ParseNode(k8sNode)
	c.Assert(n.Name, Equals, "node2")
	c.Assert(n.IPv4AllocCIDR, NotNil)
	c.Assert(n.IPv4AllocCIDR.String(), Equals, "10.1.0.0/16")
	c.Assert(n.IPv6AllocCIDR, IsNil)

	// No IPv6 annotation but PodCIDR with v6
	k8sNode = &v1.Node{
		ObjectMeta: metav1.ObjectMeta{
			Name: "node2",
			Annotations: map[string]string{
				Annotationv4CIDRName: "10.254.0.0/16",
			},
		},
		Spec: v1.NodeSpec{
			PodCIDR: "f00d:aaaa:bbbb:cccc:dddd:eeee::/112",
		},
	}

	n = ParseNode(k8sNode)
	c.Assert(n.Name, Equals, "node2")
	c.Assert(n.IPv4AllocCIDR, NotNil)
	c.Assert(n.IPv4AllocCIDR.String(), Equals, "10.254.0.0/16")
	c.Assert(n.IPv6AllocCIDR, NotNil)
	c.Assert(n.IPv6AllocCIDR.String(), Equals, "f00d:aaaa:bbbb:cccc:dddd:eeee::/112")
}

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
	"fmt"
	"time"

	"github.com/cilium/cilium/pkg/comparator"
	"github.com/cilium/cilium/pkg/nodeaddress"

	. "gopkg.in/check.v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	corev1 "k8s.io/client-go/kubernetes/typed/core/v1"
	"k8s.io/client-go/pkg/api/v1"
)

func (s *K8sSuite) TestUseNodeCIDR(c *C) {
	// Test IPv4
	node1 := v1.Node{
		ObjectMeta: metav1.ObjectMeta{
			Name: "node1",
			Annotations: map[string]string{
				Annotationv4CIDRName: "10.254.0.0/16",
			},
		},
		Spec: v1.NodeSpec{
			PodCIDR: "10.2.0.0/16",
		},
	}

	// set buffer to 2 to prevent blocking when calling UseNodeCIDR
	// and we need to wait for the response of the channel.
	updateChan := make(chan bool, 2)
	k8sClient := &Clientset{
		OnCoreV1: func() corev1.CoreV1Interface {
			return &CoreV1Client{
				OnNodes: func() corev1.NodeInterface {
					return &NodeInterfaceClient{
						OnGet: func(name string, options metav1.GetOptions) (*v1.Node, error) {
							c.Assert(name, Equals, "node1")
							c.Assert(options, comparator.DeepEquals, metav1.GetOptions{})
							n1copy := v1.Node(node1)
							return &n1copy, nil
						},
						OnUpdate: func(n *v1.Node) (*v1.Node, error) {
							updateChan <- true
							n1copy := v1.Node(node1)
							n1copy.Annotations[Annotationv4CIDRName] = "10.2.0.0/16"
							n1copy.Annotations[Annotationv6CIDRName] = "beef:beef:beef:beef:aaaa:aaaa:1111:0/96"
							c.Assert(n, comparator.DeepEquals, &n1copy)
							return &n1copy, nil
						},
					}
				},
			}
		},
	}

	node1Cilium := ParseNode(&node1)

	err := nodeaddress.UseNodeCIDR(node1Cilium)
	c.Assert(err, IsNil)
	c.Assert(nodeaddress.GetIPv4AllocRange().String(), Equals, "10.2.0.0/16")
	// IPv6 Node range is not checked because it shouldn't be changed.

	AnnotateNodeCIDR(k8sClient, "node1",
		nodeaddress.GetIPv4AllocRange(),
		nodeaddress.GetIPv6NodeRange())

	c.Assert(err, IsNil)

	select {
	case <-updateChan:
	case <-time.Tick(5 * time.Second):
		c.Errorf("d.k8sClient.CoreV1().Nodes().Update() was not called")
		c.FailNow()
	}

	// Test IPv6
	node2 := v1.Node{
		ObjectMeta: metav1.ObjectMeta{
			Name: "node2",
			Annotations: map[string]string{
				Annotationv4CIDRName: "10.254.0.0/16",
			},
		},
		Spec: v1.NodeSpec{
			PodCIDR: "aaaa:aaaa:aaaa:aaaa:beef:beef::/96",
		},
	}

	failAttempts := 0
	k8sClient = &Clientset{
		OnCoreV1: func() corev1.CoreV1Interface {
			return &CoreV1Client{
				OnNodes: func() corev1.NodeInterface {
					return &NodeInterfaceClient{
						OnGet: func(name string, options metav1.GetOptions) (*v1.Node, error) {
							c.Assert(name, Equals, "node2")
							c.Assert(options, comparator.DeepEquals, metav1.GetOptions{})
							n1copy := v1.Node(node2)
							return &n1copy, nil
						},
						OnUpdate: func(n *v1.Node) (*v1.Node, error) {
							// also test retrying in case of error
							if failAttempts == 0 {
								failAttempts++
								return nil, fmt.Errorf("failing on purpose")
							}
							updateChan <- true
							n1copy := v1.Node(node2)
							n1copy.Annotations[Annotationv4CIDRName] = "10.2.0.0/16"
							n1copy.Annotations[Annotationv6CIDRName] = "aaaa:aaaa:aaaa:aaaa:beef:beef::/96"
							c.Assert(n, comparator.DeepEquals, &n1copy)
							return &n1copy, nil
						},
					}
				},
			}
		},
	}

	node2Cilium := ParseNode(&node2)
	err = nodeaddress.UseNodeCIDR(node2Cilium)
	c.Assert(err, IsNil)

	// We use the node's annotation for the IPv4 and the PodCIDR for the
	// IPv6.
	c.Assert(nodeaddress.GetIPv4AllocRange().String(), Equals, "10.254.0.0/16")
	c.Assert(nodeaddress.GetIPv6NodeRange().String(), Equals, "aaaa:aaaa:aaaa:aaaa:beef:beef::/96")

	err = AnnotateNodeCIDR(k8sClient, "node2",
		nodeaddress.GetIPv4AllocRange(),
		nodeaddress.GetIPv6NodeRange())

	c.Assert(err, IsNil)

	select {
	case <-updateChan:
	case <-time.Tick(5 * time.Second):
		c.Errorf("d.k8sClient.CoreV1().Nodes().Update() was not called")
		c.FailNow()
	}

}

// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

//go:build !privileged_tests

package k8s

import (
	"encoding/json"
	"fmt"
	"net"
	"time"

	. "gopkg.in/check.v1"
	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/kubernetes/fake"
	"k8s.io/client-go/testing"

	"github.com/cilium/cilium/pkg/annotation"
	"github.com/cilium/cilium/pkg/checker"
	slim_corev1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/api/core/v1"
	"github.com/cilium/cilium/pkg/node"
	"github.com/cilium/cilium/pkg/source"
)

func (s *K8sSuite) TestUseNodeCIDR(c *C) {
	// Test IPv4
	node1 := v1.Node{
		ObjectMeta: metav1.ObjectMeta{
			Name: "node1",
			Annotations: map[string]string{
				annotation.V4CIDRName:   "10.254.0.0/16",
				annotation.CiliumHostIP: "10.254.0.1",
			},
		},
		Spec: v1.NodeSpec{
			PodCIDR: "10.2.0.0/16",
		},
	}

	// set buffer to 2 to prevent blocking when calling UseNodeCIDR
	// and we need to wait for the response of the channel.
	patchChan := make(chan bool, 2)
	fakeK8sClient := &fake.Clientset{}
	k8sCLI.Interface = fakeK8sClient
	fakeK8sClient.AddReactor("patch", "nodes",
		func(action testing.Action) (bool, runtime.Object, error) {
			n1copy := node1.DeepCopy()
			n1copy.Annotations[annotation.V4CIDRName] = "10.2.0.0/16"
			raw, err := json.Marshal(n1copy.Annotations)
			if err != nil {
				c.Assert(err, IsNil)
			}
			patchWanted := []byte(fmt.Sprintf(`{"metadata":{"annotations":%s}}`, raw))

			patchReceived := action.(testing.PatchAction).GetPatch()
			c.Assert(string(patchReceived), checker.DeepEquals, string(patchWanted))
			patchChan <- true
			return true, n1copy, nil
		})

	node1Slim := ConvertToNode(node1.DeepCopy()).(*slim_corev1.Node)
	node1Cilium := ParseNode(node1Slim, source.Unspec)

	useNodeCIDR(node1Cilium)
	c.Assert(node.GetIPv4AllocRange().String(), Equals, "10.2.0.0/16")
	// IPv6 Node range is not checked because it shouldn't be changed.

	err := k8sCLI.AnnotateNode("node1",
		0,
		node.GetIPv4AllocRange(),
		node.GetIPv6AllocRange(),
		nil, nil,
		nil, nil,
		net.ParseIP("10.254.0.1"),
		net.ParseIP(""))

	c.Assert(err, IsNil)

	select {
	case <-patchChan:
	case <-time.Tick(10 * time.Second):
		c.Errorf("d.fakeK8sClient.CoreV1().Nodes().Update() was not called")
		c.FailNow()
	}

	// Test IPv6
	node2 := v1.Node{
		ObjectMeta: metav1.ObjectMeta{
			Name: "node2",
			Annotations: map[string]string{
				annotation.V4CIDRName:   "10.254.0.0/16",
				annotation.CiliumHostIP: "10.254.0.1",
			},
		},
		Spec: v1.NodeSpec{
			PodCIDR: "aaaa:aaaa:aaaa:aaaa:beef:beef::/96",
		},
	}

	failAttempts := 0

	fakeK8sClient = &fake.Clientset{}
	k8sCLI.Interface = fakeK8sClient
	fakeK8sClient.AddReactor("patch", "nodes",
		func(action testing.Action) (bool, runtime.Object, error) {
			// first call will be a patch for annotations
			if failAttempts == 0 {
				failAttempts++
				return true, nil, fmt.Errorf("failing on purpose")
			}
			n2Copy := node2.DeepCopy()
			n2Copy.Annotations[annotation.V4CIDRName] = "10.254.0.0/16"
			n2Copy.Annotations[annotation.V6CIDRName] = "aaaa:aaaa:aaaa:aaaa:beef:beef::/96"
			raw, err := json.Marshal(n2Copy.Annotations)
			if err != nil {
				c.Assert(err, IsNil)
			}
			patchWanted := []byte(fmt.Sprintf(`{"metadata":{"annotations":%s}}`, raw))

			patchReceived := action.(testing.PatchAction).GetPatch()
			c.Assert(string(patchReceived), checker.DeepEquals, string(patchWanted))
			patchChan <- true
			return true, n2Copy, nil
		})

	node2Slim := ConvertToNode(node2.DeepCopy()).(*slim_corev1.Node)
	node2Cilium := ParseNode(node2Slim, source.Unspec)
	useNodeCIDR(node2Cilium)

	// We use the node's annotation for the IPv4 and the PodCIDR for the
	// IPv6.
	c.Assert(node.GetIPv4AllocRange().String(), Equals, "10.254.0.0/16")
	c.Assert(node.GetIPv6AllocRange().String(), Equals, "aaaa:aaaa:aaaa:aaaa:beef:beef::/96")

	err = k8sCLI.AnnotateNode("node2",
		0,
		node.GetIPv4AllocRange(),
		node.GetIPv6AllocRange(),
		nil, nil,
		nil, nil,
		net.ParseIP("10.254.0.1"),
		net.ParseIP(""))

	c.Assert(err, IsNil)

	select {
	case <-patchChan:
	case <-time.Tick(10 * time.Second):
		c.Errorf("d.fakeK8sClient.CoreV1().Nodes().Update() was not called")
		c.FailNow()
	}
}

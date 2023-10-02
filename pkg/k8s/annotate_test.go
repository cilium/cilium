// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package k8s

import (
	"encoding/json"
	"fmt"
	"net"
	"time"

	. "github.com/cilium/checkmate"

	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/kubernetes/fake"
	"k8s.io/client-go/testing"

	"github.com/cilium/cilium/pkg/annotation"
	"github.com/cilium/cilium/pkg/checker"
	slim_corev1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/api/core/v1"
	slim_metav1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/apis/meta/v1"
	"github.com/cilium/cilium/pkg/node"
	"github.com/cilium/cilium/pkg/option"
	"github.com/cilium/cilium/pkg/source"
)

func (s *K8sSuite) TestPrepareRemoveNodeAnnotationsPayload(c *C) {
	tests := []struct {
		name       string
		annotation nodeAnnotation
		wantJson   string
	}{
		{
			name: "Test remove one annotation",
			annotation: nodeAnnotation{
				annotation.V4CIDRName: "cidr",
			},
			wantJson: "[{\"op\":\"remove\",\"path\":\"/metadata/annotations/network.cilium.io~1ipv4-pod-cidr\",\"value\":null}]",
		},
		{
			name:       "Test remove zero annotations",
			annotation: nodeAnnotation{},
			wantJson:   "[]",
		},
	}

	for _, tt := range tests {
		got, err := prepareRemoveNodeAnnotationsPayload(tt.annotation)
		c.Assert(err, IsNil)
		c.Assert(string(got), Equals, tt.wantJson, Commentf("Test Name: %s", tt.name))
	}
}

func (s *K8sSuite) TestPatchingCIDRAnnotation(c *C) {
	node.WithTestLocalNodeStore(func() {
		prevAnnotateK8sNode := option.Config.AnnotateK8sNode
		option.Config.AnnotateK8sNode = true
		defer func() {
			option.Config.AnnotateK8sNode = prevAnnotateK8sNode
		}()

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

		node1Cilium := ParseNode(toSlimNode(node1.DeepCopy()), source.Unspec)
		node1Cilium.SetCiliumInternalIP(net.ParseIP("10.254.0.1"))
		node.SetIPv4AllocRange(node1Cilium.IPv4AllocCIDR)

		c.Assert(node.GetIPv4AllocRange().String(), Equals, "10.2.0.0/16")
		// IPv6 Node range is not checked because it shouldn't be changed.

		_, err := AnnotateNode(fakeK8sClient, "node1", *node1Cilium, 0)

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

		node2Cilium := ParseNode(toSlimNode(node2.DeepCopy()), source.Unspec)
		node2Cilium.SetCiliumInternalIP(net.ParseIP("10.254.0.1"))
		node.SetIPv4AllocRange(node2Cilium.IPv4AllocCIDR)
		node.SetIPv6NodeRange(node2Cilium.IPv6AllocCIDR)

		// We use the node's annotation for the IPv4 and the PodCIDR for the
		// IPv6.
		c.Assert(node.GetIPv4AllocRange().String(), Equals, "10.254.0.0/16")
		c.Assert(node.GetIPv6AllocRange().String(), Equals, "aaaa:aaaa:aaaa:aaaa:beef:beef::/96")

		_, err = AnnotateNode(fakeK8sClient, "node2", *node2Cilium, 0)

		c.Assert(err, IsNil)

		select {
		case <-patchChan:
		case <-time.Tick(10 * time.Second):
			c.Errorf("d.fakeK8sClient.CoreV1().Nodes().Update() was not called")
			c.FailNow()
		}
	})
}

func (s *K8sSuite) TestRemovalOfNodeAnnotations(c *C) {
	node1 := v1.Node{
		ObjectMeta: metav1.ObjectMeta{
			Name: "node1",
			Annotations: map[string]string{
				annotation.V4CIDRName: "10.254.0.0/16",
			},
		},
	}

	patchChan := make(chan bool, 1)
	fakeK8sClient := &fake.Clientset{}
	fakeK8sClient.AddReactor("patch", "nodes",
		func(action testing.Action) (bool, runtime.Object, error) {
			n1copy := node1.DeepCopy()
			delete(n1copy.Annotations, annotation.V4CIDRName)
			patchWanted := []byte("[{\"op\":\"remove\",\"path\":\"/metadata/annotations/network.cilium.io~1ipv4-pod-cidr\",\"value\":null}]")
			patchReceived := action.(testing.PatchAction).GetPatch()
			c.Assert(string(patchReceived), checker.DeepEquals, string(patchWanted))
			patchChan <- true
			return true, n1copy, nil
		})

	err := RemoveNodeAnnotations(fakeK8sClient, "node1", map[string]string{annotation.V4CIDRName: "10.254.0.0/16"})
	c.Assert(err, IsNil)

	select {
	case <-patchChan:
	case <-time.Tick(10 * time.Second):
		c.Errorf("d.fakeK8sClient.CoreV1().Nodes().Update() was not called")
		c.FailNow()
	}
}

func toSlimNode(node *v1.Node) *slim_corev1.Node {
	return &slim_corev1.Node{
		TypeMeta: slim_metav1.TypeMeta{
			Kind:       node.TypeMeta.Kind,
			APIVersion: node.TypeMeta.APIVersion,
		},
		ObjectMeta: slim_metav1.ObjectMeta{
			Name:            node.ObjectMeta.Name,
			Namespace:       node.ObjectMeta.Namespace,
			UID:             node.ObjectMeta.UID,
			ResourceVersion: node.ObjectMeta.ResourceVersion,
			Labels:          node.ObjectMeta.Labels,
			Annotations:     node.ObjectMeta.Annotations,
		},
		Spec: slim_corev1.NodeSpec{
			PodCIDR:  node.Spec.PodCIDR,
			PodCIDRs: node.Spec.PodCIDRs,
			Taints:   convertToTaints(node.Spec.Taints),
		},
		Status: slim_corev1.NodeStatus{
			Addresses: convertToAddress(node.Status.Addresses),
		},
	}
}

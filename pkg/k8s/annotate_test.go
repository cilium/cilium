// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package k8s

import (
	"encoding/json"
	"fmt"
	"net"
	"testing"
	"time"

	"github.com/cilium/hive/hivetest"
	"github.com/stretchr/testify/require"
	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/kubernetes/fake"
	k8stesting "k8s.io/client-go/testing"

	"github.com/cilium/cilium/pkg/annotation"
	slim_corev1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/api/core/v1"
	slim_metav1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/apis/meta/v1"
	"github.com/cilium/cilium/pkg/node"
	"github.com/cilium/cilium/pkg/option"
	"github.com/cilium/cilium/pkg/source"
)

func TestPrepareRemoveNodeAnnotationsPayload(t *testing.T) {
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
		require.NoError(t, err)
		require.Equal(t, tt.wantJson, string(got), "Test Name: %s", tt.name)
	}
}

func TestPatchingCIDRAnnotation(t *testing.T) {
	logger := hivetest.Logger(t)
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
			func(action k8stesting.Action) (bool, runtime.Object, error) {
				n1copy := node1.DeepCopy()
				n1copy.Annotations[annotation.V4CIDRName] = "10.2.0.0/16"
				raw, err := json.Marshal(n1copy.Annotations)
				if err != nil {
					require.NoError(t, err)
				}
				patchWanted := fmt.Appendf(nil, `{"metadata":{"annotations":%s}}`, raw)

				patchReceived := action.(k8stesting.PatchAction).GetPatch()
				require.Equal(t, string(patchWanted), string(patchReceived))
				patchChan <- true
				return true, n1copy, nil
			})

		node1Cilium := ParseNode(logger, toSlimNode(node1.DeepCopy()), source.Unspec)
		node1Cilium.SetCiliumInternalIP(net.ParseIP("10.254.0.1"))
		node.SetIPv4AllocRange(node1Cilium.IPv4AllocCIDR)

		require.Equal(t, "10.2.0.0/16", node.GetIPv4AllocRange(logger).String())
		// IPv6 Node range is not checked because it shouldn't be changed.

		_, err := AnnotateNode(logger, fakeK8sClient, "node1", *node1Cilium, 0)

		require.NoError(t, err)

		select {
		case <-patchChan:
		case <-time.Tick(10 * time.Second):
			t.Errorf("d.fakeK8sClient.CoreV1().Nodes().Update() was not called")
			t.FailNow()
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
			func(action k8stesting.Action) (bool, runtime.Object, error) {
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
					require.NoError(t, err)
				}
				patchWanted := fmt.Appendf(nil, `{"metadata":{"annotations":%s}}`, raw)

				patchReceived := action.(k8stesting.PatchAction).GetPatch()
				require.Equal(t, string(patchWanted), string(patchReceived))
				patchChan <- true
				return true, n2Copy, nil
			})

		node2Cilium := ParseNode(hivetest.Logger(t), toSlimNode(node2.DeepCopy()), source.Unspec)
		node2Cilium.SetCiliumInternalIP(net.ParseIP("10.254.0.1"))
		node.SetIPv4AllocRange(node2Cilium.IPv4AllocCIDR)
		node.SetIPv6NodeRange(node2Cilium.IPv6AllocCIDR)

		// We use the node's annotation for the IPv4 and the PodCIDR for the
		// IPv6.
		require.Equal(t, "10.254.0.0/16", node.GetIPv4AllocRange(logger).String())
		require.Equal(t, "aaaa:aaaa:aaaa:aaaa:beef:beef::/96", node.GetIPv6AllocRange(logger).String())

		_, err = AnnotateNode(hivetest.Logger(t), fakeK8sClient, "node2", *node2Cilium, 0)

		require.NoError(t, err)

		select {
		case <-patchChan:
		case <-time.Tick(10 * time.Second):
			t.Errorf("d.fakeK8sClient.CoreV1().Nodes().Update() was not called")
			t.FailNow()
		}
	})
}

func TestRemovalOfNodeAnnotations(t *testing.T) {
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
		func(action k8stesting.Action) (bool, runtime.Object, error) {
			n1copy := node1.DeepCopy()
			delete(n1copy.Annotations, annotation.V4CIDRName)
			patchWanted := []byte("[{\"op\":\"remove\",\"path\":\"/metadata/annotations/network.cilium.io~1ipv4-pod-cidr\",\"value\":null}]")
			patchReceived := action.(k8stesting.PatchAction).GetPatch()
			require.Equal(t, string(patchWanted), string(patchReceived))
			patchChan <- true
			return true, n1copy, nil
		})

	err := RemoveNodeAnnotations(fakeK8sClient, "node1", map[string]string{annotation.V4CIDRName: "10.254.0.0/16"})
	require.NoError(t, err)

	select {
	case <-patchChan:
	case <-time.Tick(10 * time.Second):
		t.Errorf("d.fakeK8sClient.CoreV1().Nodes().Update() was not called")
		t.FailNow()
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

// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package watchers

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/kubernetes/fake"
	k8sTesting "k8s.io/client-go/testing"
	"k8s.io/client-go/util/workqueue"

	"github.com/cilium/cilium/pkg/k8s"
	slim_corev1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/api/core/v1"
	slim_metav1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/apis/meta/v1"
	pkgOption "github.com/cilium/cilium/pkg/option"
	"github.com/cilium/cilium/pkg/testutils"
)

type fakeNodeGetter struct {
	OnGetK8sSlimNode func(nodeName string) (*slim_corev1.Node, error)
}

func (f *fakeNodeGetter) GetK8sSlimNode(nodeName string) (*slim_corev1.Node, error) {
	if f.OnGetK8sSlimNode != nil {
		return f.OnGetK8sSlimNode(nodeName)
	}
	panic("OnGetK8sSlimNode called but not implemented!")
}

func (f *fakeNodeGetter) ListK8sSlimNode() []*slim_corev1.Node {
	panic("not implemented!")
}

func TestNodeTaintWithoutCondition(t *testing.T) {
	mno = markNodeOptions{
		RemoveNodeTaint:        true,
		SetNodeTaint:           true,
		SetCiliumIsUpCondition: false,
	}

	// create node1 with taint and without CiliumIsUp Condition
	node1WithTaintWithoutCondition := &slim_corev1.Node{
		ObjectMeta: slim_metav1.ObjectMeta{
			Name: "k8s1",
		},
		Spec: slim_corev1.NodeSpec{
			Taints: []slim_corev1.Taint{
				{
					Key: pkgOption.Config.AgentNotReadyNodeTaintValue(), Value: "Foo",
				},
				{
					Key: "DoNoRemoveThisTaint", Value: "Foo",
				},
			},
		},
		Status: slim_corev1.NodeStatus{
			Conditions: nil,
		},
	}

	ciliumPodOnNode1 := &slim_corev1.Pod{
		Spec: slim_corev1.PodSpec{
			NodeName: "k8s1",
		},
		Status: slim_corev1.PodStatus{
			Conditions: []slim_corev1.PodCondition{
				{
					Type:   slim_corev1.PodReady,
					Status: slim_corev1.ConditionTrue,
				},
			},
		},
	}

	// Add the cilium pod that is running on k8s1
	err := ciliumPodsStore.Add(ciliumPodOnNode1)
	require.NoError(t, err)

	patchReceived := make(chan struct{})

	// Create a fake client to receive the patch from cilium-operator
	fakeClient := &fake.Clientset{}
	fakeClient.AddReactor("patch", "nodes", func(action k8sTesting.Action) (handled bool, ret runtime.Object, err error) {
		// If we are updating the spec, the subresource should be empty.
		// If we update the status the subresource is 'status'
		require.Empty(t, action.GetSubresource())

		pa := action.(k8sTesting.PatchAction)
		expectedJSONPatch := []k8s.JSONPatch{
			{
				OP:   "test",
				Path: "/spec/taints",
				Value: []slim_corev1.Taint{
					{
						Key: pkgOption.Config.AgentNotReadyNodeTaintValue(), Value: "Foo",
					},
					{
						Key: "DoNoRemoveThisTaint", Value: "Foo",
					},
				},
			},
			{
				OP:   "replace",
				Path: "/spec/taints",
				Value: []slim_corev1.Taint{
					{
						Key: "DoNoRemoveThisTaint", Value: "Foo",
					},
				},
			},
		}
		expectedPatch, err := json.Marshal(expectedJSONPatch)
		require.NoError(t, err)
		require.Equal(t, expectedPatch, pa.GetPatch())

		patchReceived <- struct{}{}
		return true, nil, nil
	})

	fng := &fakeNodeGetter{
		OnGetK8sSlimNode: func(nodeName string) (*slim_corev1.Node, error) {
			require.Equal(t, "k8s1", nodeName)
			return node1WithTaintWithoutCondition, nil
		},
	}

	nodeQueue := workqueue.NewNamedRateLimitingQueue(workqueue.DefaultControllerRateLimiter(), "node-queue")

	key, err := queueKeyFunc(node1WithTaintWithoutCondition)
	require.NoError(t, err)

	nodeQueue.Add(key)

	continueProcess := checkTaintForNextNodeItem(fakeClient, fng, nodeQueue)
	require.True(t, continueProcess)

	err = testutils.WaitUntil(func() bool {
		select {
		case <-patchReceived:
			return true
		default:
			return false
		}
	}, 1*time.Second)
	require.NoError(t, err, "Patch was never received by k8s fake client")

	// Test if we create the same patch if we receive an event from Cilium pods
	ciliumPodQueue := workqueue.NewNamedRateLimitingQueue(workqueue.DefaultControllerRateLimiter(), "cilium-pod-queue")

	key, err = queueKeyFunc(ciliumPodOnNode1)
	require.NoError(t, err)

	ciliumPodQueue.Add(key)

	continueProcess = processNextCiliumPodItem(fakeClient, fng, ciliumPodQueue)
	require.True(t, continueProcess)

	err = testutils.WaitUntil(func() bool {
		select {
		case <-patchReceived:
			return true
		default:
			return false
		}
	}, 1*time.Second)
	require.NoError(t, err, "Patch was never received by k8s fake client")
}

func TestNodeCondition(t *testing.T) {
	mno = markNodeOptions{
		RemoveNodeTaint:        false,
		SetNodeTaint:           false,
		SetCiliumIsUpCondition: true,
	}

	// create node1 with taint and with CiliumIsUp Condition. The taint
	// shouldn't be removed because we have marked it as 'false' in the
	// markNodeOptions
	node1WithTaintWithoutCondition := &slim_corev1.Node{
		ObjectMeta: slim_metav1.ObjectMeta{
			Name: "k8s1",
		},
		Spec: slim_corev1.NodeSpec{
			Taints: []slim_corev1.Taint{
				{
					Key: pkgOption.Config.AgentNotReadyNodeTaintValue(), Value: "Foo",
				},
				{
					Key: "DoNoRemoveThisTaint", Value: "Foo",
				},
			},
		},
		Status: slim_corev1.NodeStatus{
			Conditions: nil,
		},
	}

	ciliumPodOnNode1 := &slim_corev1.Pod{
		Spec: slim_corev1.PodSpec{
			NodeName: "k8s1",
		},
		Status: slim_corev1.PodStatus{
			Conditions: []slim_corev1.PodCondition{
				{
					Type:   slim_corev1.PodReady,
					Status: slim_corev1.ConditionTrue,
				},
			},
		},
	}

	// Add the cilium pod that is running on k8s1
	err := ciliumPodsStore.Add(ciliumPodOnNode1)
	require.NoError(t, err)

	patchReceived := make(chan struct{})

	// Create a fake client to receive the patch from cilium-operator
	fakeClient := &fake.Clientset{}
	fakeClient.AddReactor("patch", "nodes", func(action k8sTesting.Action) (handled bool, ret runtime.Object, err error) {
		// If we are updating the spec, the subresource should be empty.
		// If we update the status the subresource is 'status'
		require.Equal(t, "status", action.GetSubresource())

		pa := action.(k8sTesting.PatchAction)
		expectedPatch := map[string]map[string][]corev1.NodeCondition{
			"status": {
				"conditions": []corev1.NodeCondition{
					{
						Type:    corev1.NodeNetworkUnavailable,
						Status:  corev1.ConditionFalse,
						Reason:  ciliumNodeConditionReason,
						Message: "Cilium is running on this node",
						// Set a dummy time since we can't mock time.Now()
						LastTransitionTime: metav1.NewTime(time.Time{}),
						LastHeartbeatTime:  metav1.NewTime(time.Time{}),
					},
				},
			},
		}
		var receivedPatch map[string]map[string][]corev1.NodeCondition
		err = json.Unmarshal(pa.GetPatch(), &receivedPatch)
		require.NoError(t, err)

		receivedPatch["status"]["conditions"][0].LastTransitionTime = metav1.NewTime(time.Time{})
		receivedPatch["status"]["conditions"][0].LastHeartbeatTime = metav1.NewTime(time.Time{})

		require.Equal(t, expectedPatch, receivedPatch)

		patchReceived <- struct{}{}
		return true, nil, nil
	})

	fng := &fakeNodeGetter{
		OnGetK8sSlimNode: func(nodeName string) (*slim_corev1.Node, error) {
			require.Equal(t, "k8s1", nodeName)
			return node1WithTaintWithoutCondition, nil
		},
	}

	nodeQueue := workqueue.NewNamedRateLimitingQueue(workqueue.DefaultControllerRateLimiter(), "node-queue")

	key, err := queueKeyFunc(node1WithTaintWithoutCondition)
	require.NoError(t, err)

	nodeQueue.Add(key)

	continueProcess := checkTaintForNextNodeItem(fakeClient, fng, nodeQueue)
	require.True(t, continueProcess)

	err = testutils.WaitUntil(func() bool {
		select {
		case <-patchReceived:
			return true
		default:
			return false
		}
	}, 1*time.Second)
	require.NoError(t, err, "Patch was never received by k8s fake client")

	// Test if we create the same patch if we receive an event from Cilium pods
	ciliumPodQueue := workqueue.NewNamedRateLimitingQueue(workqueue.DefaultControllerRateLimiter(), "cilium-pod-queue")

	key, err = queueKeyFunc(ciliumPodOnNode1)
	require.NoError(t, err)

	ciliumPodQueue.Add(key)

	continueProcess = processNextCiliumPodItem(fakeClient, fng, ciliumPodQueue)
	require.True(t, continueProcess)

	err = testutils.WaitUntil(func() bool {
		select {
		case <-patchReceived:
			return true
		default:
			return false
		}
	}, 1*time.Second)
	require.NoError(t, err, "Patch was never received by k8s fake client")
}

func TestNodeConditionIfCiliumIsNotReady(t *testing.T) {
	mno = markNodeOptions{
		RemoveNodeTaint:        true,
		SetNodeTaint:           true,
		SetCiliumIsUpCondition: true,
	}

	// create node1 with taint and with CiliumIsUp Condition. The taint
	// shouldn't be removed because we have marked it as 'false' in the
	// markNodeOptions
	node1WithTaintWithoutCondition := &slim_corev1.Node{
		ObjectMeta: slim_metav1.ObjectMeta{
			Name: "k8s1",
		},
		Spec: slim_corev1.NodeSpec{
			Taints: []slim_corev1.Taint{
				{
					Key: pkgOption.Config.AgentNotReadyNodeTaintValue(), Value: "Foo",
				},
				{
					Key: "DoNoRemoveThisTaint", Value: "Foo",
				},
			},
		},
		Status: slim_corev1.NodeStatus{
			Conditions: nil,
		},
	}

	// Cilium Pod is not ready thus we should not update the condition nor its
	// node taint.
	ciliumPodOnNode1 := &slim_corev1.Pod{
		Spec: slim_corev1.PodSpec{
			NodeName: "k8s1",
		},
		Status: slim_corev1.PodStatus{
			Conditions: []slim_corev1.PodCondition{
				{
					Type:   slim_corev1.PodReady,
					Status: slim_corev1.ConditionFalse,
				},
			},
		},
	}

	// Add the cilium pod that is running on k8s1
	err := ciliumPodsStore.Add(ciliumPodOnNode1)
	require.NoError(t, err)

	patchReceived := make(chan struct{})

	// Create a fake client to receive the patch from cilium-operator
	fakeClient := &fake.Clientset{}
	fakeClient.AddReactor("*", "*", func(action k8sTesting.Action) (handled bool, ret runtime.Object, err error) {
		patchReceived <- struct{}{}
		return true, nil, nil
	})

	fng := &fakeNodeGetter{
		OnGetK8sSlimNode: func(nodeName string) (*slim_corev1.Node, error) {
			require.Equal(t, "k8s1", nodeName)
			return node1WithTaintWithoutCondition, nil
		},
	}

	nodeQueue := workqueue.NewNamedRateLimitingQueue(workqueue.DefaultControllerRateLimiter(), "node-queue")

	key, err := queueKeyFunc(node1WithTaintWithoutCondition)
	require.NoError(t, err)

	nodeQueue.Add(key)

	continueProcess := checkTaintForNextNodeItem(fakeClient, fng, nodeQueue)
	require.True(t, continueProcess)

	err = testutils.WaitUntil(func() bool {
		select {
		case <-patchReceived:
			return true
		default:
			return false
		}
	}, 1*time.Second)
	require.Error(t, err, "Something was sent to kube-apiserver and it shouldn't have been")

	// Test if we create the same patch if we receive an event from Cilium pods
	ciliumPodQueue := workqueue.NewNamedRateLimitingQueue(workqueue.DefaultControllerRateLimiter(), "cilium-pod-queue")

	key, err = queueKeyFunc(ciliumPodOnNode1)
	require.NoError(t, err)

	ciliumPodQueue.Add(key)

	continueProcess = processNextCiliumPodItem(fakeClient, fng, ciliumPodQueue)
	require.True(t, continueProcess)

	err = testutils.WaitUntil(func() bool {
		select {
		case <-patchReceived:
			return true
		default:
			return false
		}
	}, 1*time.Second)
	require.Error(t, err, "Something was sent to kube-apiserver and it shouldn't have been")
}

func TestNodeConditionIfCiliumAndNodeAreReady(t *testing.T) {
	mno = markNodeOptions{
		RemoveNodeTaint:        true,
		SetCiliumIsUpCondition: true,
		SetNodeTaint:           false, // we don't test _setting_ node taints here, just because it's unergonomic
	}

	// create node1 with a taint and with CiliumIsUp Condition.
	node1WithTaintWithoutCondition := &slim_corev1.Node{
		ObjectMeta: slim_metav1.ObjectMeta{
			Name: "k8s1",
		},
		Spec: slim_corev1.NodeSpec{
			Taints: []slim_corev1.Taint{
				{
					Key: "DoNoRemoveThisTaint", Value: "Foo",
				},
			},
		},
		Status: slim_corev1.NodeStatus{
			Conditions: []slim_corev1.NodeCondition{
				{
					Type:   slim_corev1.NodeNetworkUnavailable,
					Status: slim_corev1.ConditionFalse,
					Reason: ciliumNodeConditionReason,
				},
			},
		},
	}

	// Cilium Pod is ready
	ciliumPodOnNode1 := &slim_corev1.Pod{
		Spec: slim_corev1.PodSpec{
			NodeName: "k8s1",
		},
		Status: slim_corev1.PodStatus{
			Conditions: []slim_corev1.PodCondition{
				{
					Type:   slim_corev1.PodReady,
					Status: slim_corev1.ConditionFalse,
				},
			},
		},
	}

	// Add the cilium pod that is running on k8s1
	err := ciliumPodsStore.Add(ciliumPodOnNode1)
	require.NoError(t, err)

	patchReceived := make(chan struct{})

	// Create a fake client to receive the patch from cilium-operator
	fakeClient := &fake.Clientset{}
	fakeClient.AddReactor("*", "*", func(action k8sTesting.Action) (handled bool, ret runtime.Object, err error) {
		patchReceived <- struct{}{}
		return true, nil, nil
	})

	fng := &fakeNodeGetter{
		OnGetK8sSlimNode: func(nodeName string) (*slim_corev1.Node, error) {
			require.Equal(t, "k8s1", nodeName)
			return node1WithTaintWithoutCondition, nil
		},
	}

	nodeQueue := workqueue.NewNamedRateLimitingQueue(workqueue.DefaultControllerRateLimiter(), "node-queue")

	key, err := queueKeyFunc(node1WithTaintWithoutCondition)
	require.NoError(t, err)

	nodeQueue.Add(key)

	continueProcess := checkTaintForNextNodeItem(fakeClient, fng, nodeQueue)
	require.True(t, continueProcess)

	err = testutils.WaitUntil(func() bool {
		select {
		case <-patchReceived:
			return true
		default:
			return false
		}
	}, 1*time.Second)
	require.Error(t, err, "Something was sent to kube-apiserver and it shouldn't have been")

	// Test if we don't send any patch because the node and cilium pods are ready
	ciliumPodQueue := workqueue.NewNamedRateLimitingQueue(workqueue.DefaultControllerRateLimiter(), "cilium-pod-queue")

	key, err = queueKeyFunc(ciliumPodOnNode1)
	require.NoError(t, err)

	ciliumPodQueue.Add(key)

	continueProcess = processNextCiliumPodItem(fakeClient, fng, ciliumPodQueue)
	require.True(t, continueProcess)

	err = testutils.WaitUntil(func() bool {
		select {
		case <-patchReceived:
			return true
		default:
			return false
		}
	}, 1*time.Second)
	require.Error(t, err, "Something was sent to kube-apiserver and it shouldn't have been")
}

// TestTaintNodeCiliumDown checks that taints are correctly managed on nodes as Cilium
// pods go up and down.
func TestTaintNodeCiliumDown(t *testing.T) {
	mno = markNodeOptions{
		RemoveNodeTaint:        true,
		SetCiliumIsUpCondition: false,
		SetNodeTaint:           true,
	}

	// create node1 with an unrelated taint
	node1 := &slim_corev1.Node{
		ObjectMeta: slim_metav1.ObjectMeta{
			Name: "k8s1",
		},
		Spec: slim_corev1.NodeSpec{
			Taints: []slim_corev1.Taint{
				{
					Key: "DoNoRemoveThisTaint", Value: "Foo",
				},
			},
		},
	}

	// Cilium Pod is not ready
	ciliumPodOnNode1 := &slim_corev1.Pod{
		Spec: slim_corev1.PodSpec{
			NodeName: "k8s1",
		},
		Status: slim_corev1.PodStatus{
			Conditions: []slim_corev1.PodCondition{
				{
					Type:   slim_corev1.PodReady,
					Status: slim_corev1.ConditionFalse,
				},
			},
		},
	}

	// Add the cilium pod that is running on k8s1
	err := ciliumPodsStore.Add(ciliumPodOnNode1)
	require.NoError(t, err)

	// Create a fake client to receive the patch from cilium-operator
	fakeClient := &fake.Clientset{}

	patchReceived := make(chan bool)
	// emit a true on the patchReceived chan if a patch comes where the taint is set
	// false if the taint is not set
	fakeClient.AddReactor("patch", "nodes", func(action k8sTesting.Action) (handled bool, ret runtime.Object, err error) {
		// If we are updating the spec, the subresource should be empty.
		// If we update the status the subresource is 'status'
		require.Empty(t, action.GetSubresource())

		pa := action.(k8sTesting.PatchAction)

		patches := []struct {
			OP    string              `json:"op,omitempty"`
			Path  string              `json:"path,omitempty"`
			Value []slim_corev1.Taint `json:"value"`
		}{}
		err = json.Unmarshal(pa.GetPatch(), &patches)
		require.NoError(t, err)
		require.Len(t, patches, 2)

		patch := patches[1]
		require.Equal(t, "replace", patch.OP)
		require.Equal(t, "/spec/taints", patch.Path)

		// Check to see if our taint is included
		for _, taint := range patch.Value {
			if taint.Key == pkgOption.Config.AgentNotReadyNodeTaintValue() {
				patchReceived <- true
				return true, nil, nil
			}
		}

		patchReceived <- false
		return true, nil, nil
	})

	fng := &fakeNodeGetter{
		OnGetK8sSlimNode: func(nodeName string) (*slim_corev1.Node, error) {
			require.Equal(t, "k8s1", nodeName)
			return node1, nil
		},
	}

	ciliumPodQueue := workqueue.NewNamedRateLimitingQueue(workqueue.DefaultControllerRateLimiter(), "cilium-pod-queue")

	// Trigger the watcher with
	// - node taint: not set
	// - pod: scheduled, not ready
	key, err := queueKeyFunc(ciliumPodOnNode1)
	require.NoError(t, err)
	ciliumPodQueue.Add(key)
	continueProcess := processNextCiliumPodItem(fakeClient, fng, ciliumPodQueue)
	require.True(t, continueProcess)

	// Ensure taint was set
	taintSet := false
	err = testutils.WaitUntil(func() bool {
		select {
		case p := <-patchReceived:
			taintSet = p
			return true
		default:
			return false
		}
	}, 1*time.Second)
	require.NoError(t, err)
	require.True(t, taintSet, "NotReady Pod should cause node taint to be set")

	node1.Spec.Taints = []slim_corev1.Taint{
		{
			Key: pkgOption.Config.AgentNotReadyNodeTaintValue(), Value: "Foo",
		},
		{
			Key: "DoNoRemoveThisTaint", Value: "Foo",
		},
	}

	// Re-trigger pod; ensure no patch is received,
	ciliumPodQueue.Add(key)
	continueProcess = processNextCiliumPodItem(fakeClient, fng, ciliumPodQueue)
	require.True(t, continueProcess)

	err = testutils.WaitUntil(func() bool {
		select {
		case <-patchReceived:
			return true
		default:
			return false
		}
	}, 1*time.Second)
	require.Error(t, err, "no patch should have been received; code should short-circuit")

	// Set pod to Ready, ensure taint is removed
	ciliumPodOnNode1.Status.Conditions[0].Status = slim_corev1.ConditionTrue
	ciliumPodQueue.Add(key)
	continueProcess = processNextCiliumPodItem(fakeClient, fng, ciliumPodQueue)
	require.True(t, continueProcess)
	err = testutils.WaitUntil(func() bool {
		select {
		case p := <-patchReceived:
			taintSet = p
			return true
		default:
			return false
		}
	}, 1*time.Second)
	require.NoError(t, err)
	require.False(t, taintSet, "Ready Pod should cause node taint to be removed")

	// Re-trigger pod; ensure no patch is received,
	node1.Spec.Taints = []slim_corev1.Taint{node1.Spec.Taints[1]}
	ciliumPodQueue.Add(key)
	continueProcess = processNextCiliumPodItem(fakeClient, fng, ciliumPodQueue)
	require.True(t, continueProcess)

	err = testutils.WaitUntil(func() bool {
		select {
		case <-patchReceived:
			return true
		default:
			return false
		}
	}, 1*time.Second)
	require.Error(t, err, "no patch should have been received; code should short-circuit")
}

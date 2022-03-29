// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

//go:build !privileged_tests
// +build !privileged_tests

package watchers

import (
	"encoding/json"
	"testing"
	"time"

	"gopkg.in/check.v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/kubernetes/fake"
	k8sTesting "k8s.io/client-go/testing"
	"k8s.io/client-go/util/workqueue"

	"github.com/cilium/cilium/pkg/checker"
	"github.com/cilium/cilium/pkg/k8s"
	slim_corev1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/api/core/v1"
	slim_metav1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/apis/meta/v1"
	pkgOption "github.com/cilium/cilium/pkg/option"
	"github.com/cilium/cilium/pkg/testutils"
)

func Test(t *testing.T) {
	check.TestingT(t)
}

type NodeTaintSuite struct{}

var _ = check.Suite(&NodeTaintSuite{})

type fakeNodeGetter struct {
	OnGetK8sSlimNode func(nodeName string) (*slim_corev1.Node, error)
}

func (f *fakeNodeGetter) GetK8sSlimNode(nodeName string) (*slim_corev1.Node, error) {
	if f.OnGetK8sSlimNode != nil {
		return f.OnGetK8sSlimNode(nodeName)
	}
	panic("OnGetK8sSlimNode called but not implemented!")
}

func (n *NodeTaintSuite) TestNodeTaintWithoutCondition(c *check.C) {
	mno = markNodeOptions{
		RemoveNodeTaint:        true,
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
	c.Assert(err, check.IsNil)

	patchReceived := make(chan struct{})

	// Create a fake client to receive the patch from cilium-operator
	fakeClient := &fake.Clientset{}
	fakeClient.AddReactor("patch", "nodes", func(action k8sTesting.Action) (handled bool, ret runtime.Object, err error) {
		// If we are updating the spec, the subresource should be empty.
		// If we update the status the subresource is 'status'
		c.Assert(action.GetSubresource(), check.Equals, "")

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
		c.Assert(err, check.IsNil)
		c.Assert(pa.GetPatch(), checker.DeepEquals, expectedPatch)

		patchReceived <- struct{}{}
		return true, nil, nil
	})

	fng := &fakeNodeGetter{
		OnGetK8sSlimNode: func(nodeName string) (*slim_corev1.Node, error) {
			c.Assert(nodeName, check.Equals, "k8s1")
			return node1WithTaintWithoutCondition, nil
		},
	}

	nodeQueue := workqueue.NewNamedRateLimitingQueue(workqueue.DefaultControllerRateLimiter(), "node-queue")

	key, err := queueKeyFunc(node1WithTaintWithoutCondition)
	c.Assert(err, check.IsNil)

	nodeQueue.Add(key)

	continueProcess := checkTaintForNextNodeItem(fakeClient, fng, nodeQueue)
	c.Assert(continueProcess, check.Equals, true)

	err = testutils.WaitUntil(func() bool {
		select {
		case <-patchReceived:
			return true
		default:
			return false
		}
	}, 1*time.Second)
	c.Assert(err, check.IsNil, check.Commentf("Patch was never received by k8s fake client"))

	// Test if we create the same patch if we receive an event from Cilium pods
	ciliumPodQueue := workqueue.NewNamedRateLimitingQueue(workqueue.DefaultControllerRateLimiter(), "cilium-pod-queue")

	key, err = queueKeyFunc(ciliumPodOnNode1)
	c.Assert(err, check.IsNil)

	ciliumPodQueue.Add(key)

	continueProcess = processNextCiliumPodItem(fakeClient, fng, ciliumPodQueue)
	c.Assert(continueProcess, check.Equals, true)

	err = testutils.WaitUntil(func() bool {
		select {
		case <-patchReceived:
			return true
		default:
			return false
		}
	}, 1*time.Second)
	c.Assert(err, check.IsNil, check.Commentf("Patch was never received by k8s fake client"))
}

func (n *NodeTaintSuite) TestNodeCondition(c *check.C) {
	mno = markNodeOptions{
		RemoveNodeTaint:        false,
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
	c.Assert(err, check.IsNil)

	patchReceived := make(chan struct{})

	// Create a fake client to receive the patch from cilium-operator
	fakeClient := &fake.Clientset{}
	fakeClient.AddReactor("patch", "nodes", func(action k8sTesting.Action) (handled bool, ret runtime.Object, err error) {
		// If we are updating the spec, the subresource should be empty.
		// If we update the status the subresource is 'status'
		c.Assert(action.GetSubresource(), check.Equals, "status")

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
		c.Assert(err, check.IsNil)

		receivedPatch["status"]["conditions"][0].LastTransitionTime = metav1.NewTime(time.Time{})
		receivedPatch["status"]["conditions"][0].LastHeartbeatTime = metav1.NewTime(time.Time{})

		c.Assert(receivedPatch, checker.DeepEquals, expectedPatch)

		patchReceived <- struct{}{}
		return true, nil, nil
	})

	fng := &fakeNodeGetter{
		OnGetK8sSlimNode: func(nodeName string) (*slim_corev1.Node, error) {
			c.Assert(nodeName, check.Equals, "k8s1")
			return node1WithTaintWithoutCondition, nil
		},
	}

	nodeQueue := workqueue.NewNamedRateLimitingQueue(workqueue.DefaultControllerRateLimiter(), "node-queue")

	key, err := queueKeyFunc(node1WithTaintWithoutCondition)
	c.Assert(err, check.IsNil)

	nodeQueue.Add(key)

	continueProcess := checkTaintForNextNodeItem(fakeClient, fng, nodeQueue)
	c.Assert(continueProcess, check.Equals, true)

	err = testutils.WaitUntil(func() bool {
		select {
		case <-patchReceived:
			return true
		default:
			return false
		}
	}, 1*time.Second)
	c.Assert(err, check.IsNil, check.Commentf("Patch was never received by k8s fake client"))

	// Test if we create the same patch if we receive an event from Cilium pods
	ciliumPodQueue := workqueue.NewNamedRateLimitingQueue(workqueue.DefaultControllerRateLimiter(), "cilium-pod-queue")

	key, err = queueKeyFunc(ciliumPodOnNode1)
	c.Assert(err, check.IsNil)

	ciliumPodQueue.Add(key)

	continueProcess = processNextCiliumPodItem(fakeClient, fng, ciliumPodQueue)
	c.Assert(continueProcess, check.Equals, true)

	err = testutils.WaitUntil(func() bool {
		select {
		case <-patchReceived:
			return true
		default:
			return false
		}
	}, 1*time.Second)
	c.Assert(err, check.IsNil, check.Commentf("Patch was never received by k8s fake client"))
}

func (n *NodeTaintSuite) TestNodeConditionIfCiliumIsNotReady(c *check.C) {
	mno = markNodeOptions{
		RemoveNodeTaint:        true,
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
	c.Assert(err, check.IsNil)

	patchReceived := make(chan struct{})

	// Create a fake client to receive the patch from cilium-operator
	fakeClient := &fake.Clientset{}
	fakeClient.AddReactor("*", "*", func(action k8sTesting.Action) (handled bool, ret runtime.Object, err error) {
		patchReceived <- struct{}{}
		return true, nil, nil
	})

	fng := &fakeNodeGetter{
		OnGetK8sSlimNode: func(nodeName string) (*slim_corev1.Node, error) {
			c.Assert(nodeName, check.Equals, "k8s1")
			return node1WithTaintWithoutCondition, nil
		},
	}

	nodeQueue := workqueue.NewNamedRateLimitingQueue(workqueue.DefaultControllerRateLimiter(), "node-queue")

	key, err := queueKeyFunc(node1WithTaintWithoutCondition)
	c.Assert(err, check.IsNil)

	nodeQueue.Add(key)

	continueProcess := checkTaintForNextNodeItem(fakeClient, fng, nodeQueue)
	c.Assert(continueProcess, check.Equals, true)

	err = testutils.WaitUntil(func() bool {
		select {
		case <-patchReceived:
			return true
		default:
			return false
		}
	}, 1*time.Second)
	c.Assert(err, check.Not(check.IsNil), check.Commentf("Something was sent to kube-apiserver and it shouldn't have been"))

	// Test if we create the same patch if we receive an event from Cilium pods
	ciliumPodQueue := workqueue.NewNamedRateLimitingQueue(workqueue.DefaultControllerRateLimiter(), "cilium-pod-queue")

	key, err = queueKeyFunc(ciliumPodOnNode1)
	c.Assert(err, check.IsNil)

	ciliumPodQueue.Add(key)

	continueProcess = processNextCiliumPodItem(fakeClient, fng, ciliumPodQueue)
	c.Assert(continueProcess, check.Equals, true)

	err = testutils.WaitUntil(func() bool {
		select {
		case <-patchReceived:
			return true
		default:
			return false
		}
	}, 1*time.Second)
	c.Assert(err, check.Not(check.IsNil), check.Commentf("Something was sent to kube-apiserver and it shouldn't have been"))
}

func (n *NodeTaintSuite) TestNodeConditionIfCiliumAndNodeAreReady(c *check.C) {
	mno = markNodeOptions{
		RemoveNodeTaint:        true,
		SetCiliumIsUpCondition: true,
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
	c.Assert(err, check.IsNil)

	patchReceived := make(chan struct{})

	// Create a fake client to receive the patch from cilium-operator
	fakeClient := &fake.Clientset{}
	fakeClient.AddReactor("*", "*", func(action k8sTesting.Action) (handled bool, ret runtime.Object, err error) {
		patchReceived <- struct{}{}
		return true, nil, nil
	})

	fng := &fakeNodeGetter{
		OnGetK8sSlimNode: func(nodeName string) (*slim_corev1.Node, error) {
			c.Assert(nodeName, check.Equals, "k8s1")
			return node1WithTaintWithoutCondition, nil
		},
	}

	nodeQueue := workqueue.NewNamedRateLimitingQueue(workqueue.DefaultControllerRateLimiter(), "node-queue")

	key, err := queueKeyFunc(node1WithTaintWithoutCondition)
	c.Assert(err, check.IsNil)

	nodeQueue.Add(key)

	continueProcess := checkTaintForNextNodeItem(fakeClient, fng, nodeQueue)
	c.Assert(continueProcess, check.Equals, true)

	err = testutils.WaitUntil(func() bool {
		select {
		case <-patchReceived:
			return true
		default:
			return false
		}
	}, 1*time.Second)
	c.Assert(err, check.Not(check.IsNil), check.Commentf("Something was sent to kube-apiserver and it shouldn't have been since the node is ready and it does not have a taint set"))

	// Test if we don't send any patch because the node and cilium pods are ready
	ciliumPodQueue := workqueue.NewNamedRateLimitingQueue(workqueue.DefaultControllerRateLimiter(), "cilium-pod-queue")

	key, err = queueKeyFunc(ciliumPodOnNode1)
	c.Assert(err, check.IsNil)

	ciliumPodQueue.Add(key)

	continueProcess = processNextCiliumPodItem(fakeClient, fng, ciliumPodQueue)
	c.Assert(continueProcess, check.Equals, true)

	err = testutils.WaitUntil(func() bool {
		select {
		case <-patchReceived:
			return true
		default:
			return false
		}
	}, 1*time.Second)
	c.Assert(err, check.Not(check.IsNil), check.Commentf("Something was sent to kube-apiserver and it shouldn't have been since the node is ready and it does not have a taint set"))
}

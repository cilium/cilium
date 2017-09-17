/*
Copyright 2015 The Kubernetes Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package scheduling

import (
	"fmt"
	"time"

	"k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/util/sets"
	"k8s.io/apimachinery/pkg/util/uuid"
	clientset "k8s.io/client-go/kubernetes"
	"k8s.io/kubernetes/test/e2e/common"
	"k8s.io/kubernetes/test/e2e/framework"
	testutils "k8s.io/kubernetes/test/utils"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	_ "github.com/stretchr/testify/assert"
)

const maxNumberOfPods int64 = 10
const minPodCPURequest int64 = 500

// variable set in BeforeEach, never modified afterwards
var masterNodes sets.String

type pausePodConfig struct {
	Name                              string
	Affinity                          *v1.Affinity
	Annotations, Labels, NodeSelector map[string]string
	Resources                         *v1.ResourceRequirements
	Tolerations                       []v1.Toleration
	NodeName                          string
	Ports                             []v1.ContainerPort
	OwnerReferences                   []metav1.OwnerReference
}

var _ = SIGDescribe("SchedulerPredicates [Serial]", func() {
	var cs clientset.Interface
	var nodeList *v1.NodeList
	var systemPodsNo int
	var totalPodCapacity int64
	var RCName string
	var ns string
	f := framework.NewDefaultFramework("sched-pred")
	ignoreLabels := framework.ImagePullerLabels

	AfterEach(func() {
		rc, err := cs.CoreV1().ReplicationControllers(ns).Get(RCName, metav1.GetOptions{})
		if err == nil && *(rc.Spec.Replicas) != 0 {
			By("Cleaning up the replication controller")
			err := framework.DeleteRCAndPods(f.ClientSet, f.InternalClientset, ns, RCName)
			framework.ExpectNoError(err)
		}
	})

	BeforeEach(func() {
		cs = f.ClientSet
		ns = f.Namespace.Name
		nodeList = &v1.NodeList{}

		framework.WaitForAllNodesHealthy(cs, time.Minute)
		masterNodes, nodeList = framework.GetMasterAndWorkerNodesOrDie(cs)

		err := framework.CheckTestingNSDeletedExcept(cs, ns)
		framework.ExpectNoError(err)

		// Every test case in this suite assumes that cluster add-on pods stay stable and
		// cannot be run in parallel with any other test that touches Nodes or Pods.
		// It is so because we need to have precise control on what's running in the cluster.
		systemPods, err := framework.GetPodsInNamespace(cs, ns, ignoreLabels)
		Expect(err).NotTo(HaveOccurred())
		systemPodsNo = 0
		for _, pod := range systemPods {
			if !masterNodes.Has(pod.Spec.NodeName) && pod.DeletionTimestamp == nil {
				systemPodsNo++
			}
		}

		err = framework.WaitForPodsRunningReady(cs, metav1.NamespaceSystem, int32(systemPodsNo), 0, framework.PodReadyBeforeTimeout, ignoreLabels)
		Expect(err).NotTo(HaveOccurred())

		err = framework.WaitForPodsSuccess(cs, metav1.NamespaceSystem, framework.ImagePullerLabels, framework.ImagePrePullingTimeout)
		Expect(err).NotTo(HaveOccurred())

		for _, node := range nodeList.Items {
			framework.Logf("\nLogging pods the kubelet thinks is on node %v before test", node.Name)
			framework.PrintAllKubeletPods(cs, node.Name)
		}

	})

	// This test verifies that max-pods flag works as advertised. It assumes that cluster add-on pods stay stable
	// and cannot be run in parallel with any other test that touches Nodes or Pods. It is so because to check
	// if max-pods is working we need to fully saturate the cluster and keep it in this state for few seconds.
	//
	// Slow PR #13315 (8 min)
	It("validates MaxPods limit number of pods that are allowed to run [Slow]", func() {
		totalPodCapacity = 0

		for _, node := range nodeList.Items {
			framework.Logf("Node: %v", node)
			podCapacity, found := node.Status.Capacity[v1.ResourcePods]
			Expect(found).To(Equal(true))
			totalPodCapacity += podCapacity.Value()
		}

		currentlyScheduledPods := framework.WaitForStableCluster(cs, masterNodes)
		podsNeededForSaturation := int(totalPodCapacity) - currentlyScheduledPods

		By(fmt.Sprintf("Starting additional %v Pods to fully saturate the cluster max pods and trying to start another one", podsNeededForSaturation))

		// As the pods are distributed randomly among nodes,
		// it can easily happen that all nodes are satured
		// and there is no need to create additional pods.
		// StartPods requires at least one pod to replicate.
		if podsNeededForSaturation > 0 {
			framework.ExpectNoError(testutils.StartPods(cs, podsNeededForSaturation, ns, "maxp",
				*initPausePod(f, pausePodConfig{
					Name:   "",
					Labels: map[string]string{"name": ""},
				}), true, framework.Logf))
		}
		podName := "additional-pod"
		WaitForSchedulerAfterAction(f, createPausePodAction(f, pausePodConfig{
			Name:   podName,
			Labels: map[string]string{"name": "additional"},
		}), podName, false)
		verifyResult(cs, podsNeededForSaturation, 1, ns)
	})

	// This test verifies we don't allow scheduling of pods in a way that sum of local ephemeral storage limits of pods is greater than machines capacity.
	// It assumes that cluster add-on pods stay stable and cannot be run in parallel with any other test that touches Nodes or Pods.
	// It is so because we need to have precise control on what's running in the cluster.
	It("validates local ephemeral storage resource limits of pods that are allowed to run [Feature:LocalStorageCapacityIsolation]", func() {
		nodeMaxAllocatable := int64(0)

		nodeToAllocatableMap := make(map[string]int64)
		for _, node := range nodeList.Items {
			allocatable, found := node.Status.Allocatable[v1.ResourceEphemeralStorage]
			Expect(found).To(Equal(true))
			nodeToAllocatableMap[node.Name] = allocatable.MilliValue()
			if nodeMaxAllocatable < allocatable.MilliValue() {
				nodeMaxAllocatable = allocatable.MilliValue()
			}
		}
		framework.WaitForStableCluster(cs, masterNodes)

		pods, err := cs.CoreV1().Pods(metav1.NamespaceAll).List(metav1.ListOptions{})
		framework.ExpectNoError(err)
		for _, pod := range pods.Items {
			_, found := nodeToAllocatableMap[pod.Spec.NodeName]
			if found && pod.Status.Phase != v1.PodSucceeded && pod.Status.Phase != v1.PodFailed {
				framework.Logf("Pod %v requesting local ephemeral resource =%vm on Node %v", pod.Name, getRequestedStorageEphemeralStorage(pod), pod.Spec.NodeName)
				nodeToAllocatableMap[pod.Spec.NodeName] -= getRequestedStorageEphemeralStorage(pod)
			}
		}

		var podsNeededForSaturation int

		milliEphemeralStoragePerPod := nodeMaxAllocatable / maxNumberOfPods

		framework.Logf("Using pod capacity: %vm", milliEphemeralStoragePerPod)
		for name, leftAllocatable := range nodeToAllocatableMap {
			framework.Logf("Node: %v has local ephemeral resource allocatable: %vm", name, leftAllocatable)
			podsNeededForSaturation += (int)(leftAllocatable / milliEphemeralStoragePerPod)
		}

		By(fmt.Sprintf("Starting additional %v Pods to fully saturate the cluster local ephemeral resource and trying to start another one", podsNeededForSaturation))

		// As the pods are distributed randomly among nodes,
		// it can easily happen that all nodes are saturated
		// and there is no need to create additional pods.
		// StartPods requires at least one pod to replicate.
		if podsNeededForSaturation > 0 {
			framework.ExpectNoError(testutils.StartPods(cs, podsNeededForSaturation, ns, "overcommit",
				*initPausePod(f, pausePodConfig{
					Name:   "",
					Labels: map[string]string{"name": ""},
					Resources: &v1.ResourceRequirements{
						Limits: v1.ResourceList{
							v1.ResourceEphemeralStorage: *resource.NewMilliQuantity(milliEphemeralStoragePerPod, "DecimalSI"),
						},
						Requests: v1.ResourceList{
							v1.ResourceEphemeralStorage: *resource.NewMilliQuantity(milliEphemeralStoragePerPod, "DecimalSI"),
						},
					},
				}), true, framework.Logf))
		}
		podName := "additional-pod"
		conf := pausePodConfig{
			Name:   podName,
			Labels: map[string]string{"name": "additional"},
			Resources: &v1.ResourceRequirements{
				Limits: v1.ResourceList{
					v1.ResourceEphemeralStorage: *resource.NewMilliQuantity(milliEphemeralStoragePerPod, "DecimalSI"),
				},
			},
		}
		WaitForSchedulerAfterAction(f, createPausePodAction(f, conf), podName, false)
		verifyResult(cs, podsNeededForSaturation, 1, ns)
	})

	// This test verifies we don't allow scheduling of pods in a way that sum of limits of pods is greater than machines capacity.
	// It assumes that cluster add-on pods stay stable and cannot be run in parallel with any other test that touches Nodes or Pods.
	// It is so because we need to have precise control on what's running in the cluster.
	It("validates resource limits of pods that are allowed to run [Conformance]", func() {
		nodeMaxAllocatable := int64(0)

		nodeToAllocatableMap := make(map[string]int64)
		for _, node := range nodeList.Items {
			allocatable, found := node.Status.Allocatable[v1.ResourceCPU]
			Expect(found).To(Equal(true))
			nodeToAllocatableMap[node.Name] = allocatable.MilliValue()
			if nodeMaxAllocatable < allocatable.MilliValue() {
				nodeMaxAllocatable = allocatable.MilliValue()
			}
		}
		framework.WaitForStableCluster(cs, masterNodes)

		pods, err := cs.CoreV1().Pods(metav1.NamespaceAll).List(metav1.ListOptions{})
		framework.ExpectNoError(err)
		for _, pod := range pods.Items {
			_, found := nodeToAllocatableMap[pod.Spec.NodeName]
			if found && pod.Status.Phase != v1.PodSucceeded && pod.Status.Phase != v1.PodFailed {
				framework.Logf("Pod %v requesting resource cpu=%vm on Node %v", pod.Name, getRequestedCPU(pod), pod.Spec.NodeName)
				nodeToAllocatableMap[pod.Spec.NodeName] -= getRequestedCPU(pod)
			}
		}

		var podsNeededForSaturation int

		milliCpuPerPod := nodeMaxAllocatable / maxNumberOfPods
		if milliCpuPerPod < minPodCPURequest {
			milliCpuPerPod = minPodCPURequest
		}
		framework.Logf("Using pod capacity: %vm", milliCpuPerPod)
		for name, leftAllocatable := range nodeToAllocatableMap {
			framework.Logf("Node: %v has cpu allocatable: %vm", name, leftAllocatable)
			podsNeededForSaturation += (int)(leftAllocatable / milliCpuPerPod)
		}

		By(fmt.Sprintf("Starting additional %v Pods to fully saturate the cluster CPU and trying to start another one", podsNeededForSaturation))

		// As the pods are distributed randomly among nodes,
		// it can easily happen that all nodes are saturated
		// and there is no need to create additional pods.
		// StartPods requires at least one pod to replicate.
		if podsNeededForSaturation > 0 {
			framework.ExpectNoError(testutils.StartPods(cs, podsNeededForSaturation, ns, "overcommit",
				*initPausePod(f, pausePodConfig{
					Name:   "",
					Labels: map[string]string{"name": ""},
					Resources: &v1.ResourceRequirements{
						Limits: v1.ResourceList{
							v1.ResourceCPU: *resource.NewMilliQuantity(milliCpuPerPod, "DecimalSI"),
						},
						Requests: v1.ResourceList{
							v1.ResourceCPU: *resource.NewMilliQuantity(milliCpuPerPod, "DecimalSI"),
						},
					},
				}), true, framework.Logf))
		}
		podName := "additional-pod"
		conf := pausePodConfig{
			Name:   podName,
			Labels: map[string]string{"name": "additional"},
			Resources: &v1.ResourceRequirements{
				Limits: v1.ResourceList{
					v1.ResourceCPU: *resource.NewMilliQuantity(milliCpuPerPod, "DecimalSI"),
				},
			},
		}
		WaitForSchedulerAfterAction(f, createPausePodAction(f, conf), podName, false)
		verifyResult(cs, podsNeededForSaturation, 1, ns)
	})

	// Test Nodes does not have any label, hence it should be impossible to schedule Pod with
	// nonempty Selector set.
	It("validates that NodeSelector is respected if not matching [Conformance]", func() {
		By("Trying to schedule Pod with nonempty NodeSelector.")
		podName := "restricted-pod"

		framework.WaitForStableCluster(cs, masterNodes)

		conf := pausePodConfig{
			Name:   podName,
			Labels: map[string]string{"name": "restricted"},
			NodeSelector: map[string]string{
				"label": "nonempty",
			},
		}

		WaitForSchedulerAfterAction(f, createPausePodAction(f, conf), podName, false)
		verifyResult(cs, 0, 1, ns)
	})

	It("validates that a pod with an invalid NodeAffinity is rejected", func() {
		By("Trying to launch a pod with an invalid Affinity data.")
		podName := "without-label"
		_, err := cs.CoreV1().Pods(ns).Create(initPausePod(f, pausePodConfig{
			Name: podName,
			Affinity: &v1.Affinity{
				NodeAffinity: &v1.NodeAffinity{
					RequiredDuringSchedulingIgnoredDuringExecution: &v1.NodeSelector{
						NodeSelectorTerms: []v1.NodeSelectorTerm{
							{
								MatchExpressions: []v1.NodeSelectorRequirement{},
							},
						},
					},
				},
			},
		}))

		if err == nil || !errors.IsInvalid(err) {
			framework.Failf("Expect error of invalid, got : %v", err)
		}
	})

	It("validates that NodeSelector is respected if matching [Conformance]", func() {
		nodeName := GetNodeThatCanRunPod(f)

		By("Trying to apply a random label on the found node.")
		k := fmt.Sprintf("kubernetes.io/e2e-%s", string(uuid.NewUUID()))
		v := "42"
		framework.AddOrUpdateLabelOnNode(cs, nodeName, k, v)
		framework.ExpectNodeHasLabel(cs, nodeName, k, v)
		defer framework.RemoveLabelOffNode(cs, nodeName, k)

		By("Trying to relaunch the pod, now with labels.")
		labelPodName := "with-labels"
		createPausePod(f, pausePodConfig{
			Name: labelPodName,
			NodeSelector: map[string]string{
				k: v,
			},
		})

		// check that pod got scheduled. We intentionally DO NOT check that the
		// pod is running because this will create a race condition with the
		// kubelet and the scheduler: the scheduler might have scheduled a pod
		// already when the kubelet does not know about its new label yet. The
		// kubelet will then refuse to launch the pod.
		framework.ExpectNoError(framework.WaitForPodNotPending(cs, ns, labelPodName))
		labelPod, err := cs.CoreV1().Pods(ns).Get(labelPodName, metav1.GetOptions{})
		framework.ExpectNoError(err)
		Expect(labelPod.Spec.NodeName).To(Equal(nodeName))
	})

	// Test Nodes does not have any label, hence it should be impossible to schedule Pod with
	// non-nil NodeAffinity.RequiredDuringSchedulingIgnoredDuringExecution.
	It("validates that NodeAffinity is respected if not matching", func() {
		By("Trying to schedule Pod with nonempty NodeSelector.")
		podName := "restricted-pod"

		framework.WaitForStableCluster(cs, masterNodes)

		conf := pausePodConfig{
			Name: podName,
			Affinity: &v1.Affinity{
				NodeAffinity: &v1.NodeAffinity{
					RequiredDuringSchedulingIgnoredDuringExecution: &v1.NodeSelector{
						NodeSelectorTerms: []v1.NodeSelectorTerm{
							{
								MatchExpressions: []v1.NodeSelectorRequirement{
									{
										Key:      "foo",
										Operator: v1.NodeSelectorOpIn,
										Values:   []string{"bar", "value2"},
									},
								},
							}, {
								MatchExpressions: []v1.NodeSelectorRequirement{
									{
										Key:      "diffkey",
										Operator: v1.NodeSelectorOpIn,
										Values:   []string{"wrong", "value2"},
									},
								},
							},
						},
					},
				},
			},
			Labels: map[string]string{"name": "restricted"},
		}
		WaitForSchedulerAfterAction(f, createPausePodAction(f, conf), podName, false)
		verifyResult(cs, 0, 1, ns)
	})

	// Keep the same steps with the test on NodeSelector,
	// but specify Affinity in Pod.Spec.Affinity, instead of NodeSelector.
	It("validates that required NodeAffinity setting is respected if matching", func() {
		nodeName := GetNodeThatCanRunPod(f)

		By("Trying to apply a random label on the found node.")
		k := fmt.Sprintf("kubernetes.io/e2e-%s", string(uuid.NewUUID()))
		v := "42"
		framework.AddOrUpdateLabelOnNode(cs, nodeName, k, v)
		framework.ExpectNodeHasLabel(cs, nodeName, k, v)
		defer framework.RemoveLabelOffNode(cs, nodeName, k)

		By("Trying to relaunch the pod, now with labels.")
		labelPodName := "with-labels"
		createPausePod(f, pausePodConfig{
			Name: labelPodName,
			Affinity: &v1.Affinity{
				NodeAffinity: &v1.NodeAffinity{
					RequiredDuringSchedulingIgnoredDuringExecution: &v1.NodeSelector{
						NodeSelectorTerms: []v1.NodeSelectorTerm{
							{
								MatchExpressions: []v1.NodeSelectorRequirement{
									{
										Key:      k,
										Operator: v1.NodeSelectorOpIn,
										Values:   []string{v},
									},
								},
							},
						},
					},
				},
			},
		})

		// check that pod got scheduled. We intentionally DO NOT check that the
		// pod is running because this will create a race condition with the
		// kubelet and the scheduler: the scheduler might have scheduled a pod
		// already when the kubelet does not know about its new label yet. The
		// kubelet will then refuse to launch the pod.
		framework.ExpectNoError(framework.WaitForPodNotPending(cs, ns, labelPodName))
		labelPod, err := cs.CoreV1().Pods(ns).Get(labelPodName, metav1.GetOptions{})
		framework.ExpectNoError(err)
		Expect(labelPod.Spec.NodeName).To(Equal(nodeName))
	})

	// 1. Run a pod to get an available node, then delete the pod
	// 2. Taint the node with a random taint
	// 3. Try to relaunch the pod with tolerations tolerate the taints on node,
	// and the pod's nodeName specified to the name of node found in step 1
	It("validates that taints-tolerations is respected if matching", func() {
		nodeName := getNodeThatCanRunPodWithoutToleration(f)

		By("Trying to apply a random taint on the found node.")
		testTaint := v1.Taint{
			Key:    fmt.Sprintf("kubernetes.io/e2e-taint-key-%s", string(uuid.NewUUID())),
			Value:  "testing-taint-value",
			Effect: v1.TaintEffectNoSchedule,
		}
		framework.AddOrUpdateTaintOnNode(cs, nodeName, testTaint)
		framework.ExpectNodeHasTaint(cs, nodeName, &testTaint)
		defer framework.RemoveTaintOffNode(cs, nodeName, testTaint)

		By("Trying to apply a random label on the found node.")
		labelKey := fmt.Sprintf("kubernetes.io/e2e-label-key-%s", string(uuid.NewUUID()))
		labelValue := "testing-label-value"
		framework.AddOrUpdateLabelOnNode(cs, nodeName, labelKey, labelValue)
		framework.ExpectNodeHasLabel(cs, nodeName, labelKey, labelValue)
		defer framework.RemoveLabelOffNode(cs, nodeName, labelKey)

		By("Trying to relaunch the pod, now with tolerations.")
		tolerationPodName := "with-tolerations"
		createPausePod(f, pausePodConfig{
			Name:         tolerationPodName,
			Tolerations:  []v1.Toleration{{Key: testTaint.Key, Value: testTaint.Value, Effect: testTaint.Effect}},
			NodeSelector: map[string]string{labelKey: labelValue},
		})

		// check that pod got scheduled. We intentionally DO NOT check that the
		// pod is running because this will create a race condition with the
		// kubelet and the scheduler: the scheduler might have scheduled a pod
		// already when the kubelet does not know about its new taint yet. The
		// kubelet will then refuse to launch the pod.
		framework.ExpectNoError(framework.WaitForPodNotPending(cs, ns, tolerationPodName))
		deployedPod, err := cs.CoreV1().Pods(ns).Get(tolerationPodName, metav1.GetOptions{})
		framework.ExpectNoError(err)
		Expect(deployedPod.Spec.NodeName).To(Equal(nodeName))
	})

	// 1. Run a pod to get an available node, then delete the pod
	// 2. Taint the node with a random taint
	// 3. Try to relaunch the pod still no tolerations,
	// and the pod's nodeName specified to the name of node found in step 1
	It("validates that taints-tolerations is respected if not matching", func() {
		nodeName := getNodeThatCanRunPodWithoutToleration(f)

		By("Trying to apply a random taint on the found node.")
		testTaint := v1.Taint{
			Key:    fmt.Sprintf("kubernetes.io/e2e-taint-key-%s", string(uuid.NewUUID())),
			Value:  "testing-taint-value",
			Effect: v1.TaintEffectNoSchedule,
		}
		framework.AddOrUpdateTaintOnNode(cs, nodeName, testTaint)
		framework.ExpectNodeHasTaint(cs, nodeName, &testTaint)
		defer framework.RemoveTaintOffNode(cs, nodeName, testTaint)

		By("Trying to apply a random label on the found node.")
		labelKey := fmt.Sprintf("kubernetes.io/e2e-label-key-%s", string(uuid.NewUUID()))
		labelValue := "testing-label-value"
		framework.AddOrUpdateLabelOnNode(cs, nodeName, labelKey, labelValue)
		framework.ExpectNodeHasLabel(cs, nodeName, labelKey, labelValue)
		defer framework.RemoveLabelOffNode(cs, nodeName, labelKey)

		By("Trying to relaunch the pod, still no tolerations.")
		podNameNoTolerations := "still-no-tolerations"
		conf := pausePodConfig{
			Name:         podNameNoTolerations,
			NodeSelector: map[string]string{labelKey: labelValue},
		}

		WaitForSchedulerAfterAction(f, createPausePodAction(f, conf), podNameNoTolerations, false)
		verifyResult(cs, 0, 1, ns)

		By("Removing taint off the node")
		WaitForSchedulerAfterAction(f, removeTaintFromNodeAction(cs, nodeName, testTaint), podNameNoTolerations, true)
		verifyResult(cs, 1, 0, ns)
	})
})

func initPausePod(f *framework.Framework, conf pausePodConfig) *v1.Pod {
	pod := &v1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Name:            conf.Name,
			Labels:          conf.Labels,
			Annotations:     conf.Annotations,
			OwnerReferences: conf.OwnerReferences,
		},
		Spec: v1.PodSpec{
			NodeSelector: conf.NodeSelector,
			Affinity:     conf.Affinity,
			Containers: []v1.Container{
				{
					Name:  conf.Name,
					Image: framework.GetPauseImageName(f.ClientSet),
					Ports: conf.Ports,
				},
			},
			Tolerations: conf.Tolerations,
			NodeName:    conf.NodeName,
		},
	}
	if conf.Resources != nil {
		pod.Spec.Containers[0].Resources = *conf.Resources
	}
	return pod
}

func createPausePod(f *framework.Framework, conf pausePodConfig) *v1.Pod {
	pod, err := f.ClientSet.CoreV1().Pods(f.Namespace.Name).Create(initPausePod(f, conf))
	framework.ExpectNoError(err)
	return pod
}

func runPausePod(f *framework.Framework, conf pausePodConfig) *v1.Pod {
	pod := createPausePod(f, conf)
	framework.ExpectNoError(framework.WaitForPodRunningInNamespace(f.ClientSet, pod))
	pod, err := f.ClientSet.CoreV1().Pods(f.Namespace.Name).Get(conf.Name, metav1.GetOptions{})
	framework.ExpectNoError(err)
	return pod
}

func runPodAndGetNodeName(f *framework.Framework, conf pausePodConfig) string {
	// launch a pod to find a node which can launch a pod. We intentionally do
	// not just take the node list and choose the first of them. Depending on the
	// cluster and the scheduler it might be that a "normal" pod cannot be
	// scheduled onto it.
	pod := runPausePod(f, conf)

	By("Explicitly delete pod here to free the resource it takes.")
	err := f.ClientSet.CoreV1().Pods(f.Namespace.Name).Delete(pod.Name, metav1.NewDeleteOptions(0))
	framework.ExpectNoError(err)

	return pod.Spec.NodeName
}

func getRequestedCPU(pod v1.Pod) int64 {
	var result int64
	for _, container := range pod.Spec.Containers {
		result += container.Resources.Requests.Cpu().MilliValue()
	}
	return result
}

func getRequestedStorageEphemeralStorage(pod v1.Pod) int64 {
	var result int64
	for _, container := range pod.Spec.Containers {
		result += container.Resources.Requests.StorageEphemeral().MilliValue()
	}
	return result
}

// removeTaintFromNodeAction returns a closure that removes the given taint
// from the given node upon invocation.
func removeTaintFromNodeAction(cs clientset.Interface, nodeName string, testTaint v1.Taint) common.Action {
	return func() error {
		framework.RemoveTaintOffNode(cs, nodeName, testTaint)
		return nil
	}
}

// createPausePodAction returns a closure that creates a pause pod upon invocation.
func createPausePodAction(f *framework.Framework, conf pausePodConfig) common.Action {
	return func() error {
		_, err := f.ClientSet.CoreV1().Pods(f.Namespace.Name).Create(initPausePod(f, conf))
		return err
	}
}

// WaitForSchedulerAfterAction performs the provided action and then waits for
// scheduler to act on the given pod.
func WaitForSchedulerAfterAction(f *framework.Framework, action common.Action, podName string, expectSuccess bool) {
	predicate := scheduleFailureEvent(podName)
	if expectSuccess {
		predicate = scheduleSuccessEvent(podName, "" /* any node */)
	}
	success, err := common.ObserveEventAfterAction(f, predicate, action)
	Expect(err).NotTo(HaveOccurred())
	Expect(success).To(Equal(true))
}

// TODO: upgrade calls in PodAffinity tests when we're able to run them
func verifyResult(c clientset.Interface, expectedScheduled int, expectedNotScheduled int, ns string) {
	allPods, err := c.CoreV1().Pods(ns).List(metav1.ListOptions{})
	framework.ExpectNoError(err)
	scheduledPods, notScheduledPods := framework.GetPodsScheduled(masterNodes, allPods)

	printed := false
	printOnce := func(msg string) string {
		if !printed {
			printed = true
			return msg
		} else {
			return ""
		}
	}

	Expect(len(notScheduledPods)).To(Equal(expectedNotScheduled), printOnce(fmt.Sprintf("Not scheduled Pods: %#v", notScheduledPods)))
	Expect(len(scheduledPods)).To(Equal(expectedScheduled), printOnce(fmt.Sprintf("Scheduled Pods: %#v", scheduledPods)))
}

// verifyReplicasResult is wrapper of verifyResult for a group pods with same "name: labelName" label, which means they belong to same RC
func verifyReplicasResult(c clientset.Interface, expectedScheduled int, expectedNotScheduled int, ns string, labelName string) {
	allPods := getPodsByLabels(c, ns, map[string]string{"name": labelName})
	scheduledPods, notScheduledPods := framework.GetPodsScheduled(masterNodes, allPods)

	printed := false
	printOnce := func(msg string) string {
		if !printed {
			printed = true
			return msg
		} else {
			return ""
		}
	}

	Expect(len(notScheduledPods)).To(Equal(expectedNotScheduled), printOnce(fmt.Sprintf("Not scheduled Pods: %#v", notScheduledPods)))
	Expect(len(scheduledPods)).To(Equal(expectedScheduled), printOnce(fmt.Sprintf("Scheduled Pods: %#v", scheduledPods)))
}

func getPodsByLabels(c clientset.Interface, ns string, labelsMap map[string]string) *v1.PodList {
	selector := labels.SelectorFromSet(labels.Set(labelsMap))
	allPods, err := c.CoreV1().Pods(ns).List(metav1.ListOptions{LabelSelector: selector.String()})
	framework.ExpectNoError(err)
	return allPods
}

func runAndKeepPodWithLabelAndGetNodeName(f *framework.Framework) (string, string) {
	// launch a pod to find a node which can launch a pod. We intentionally do
	// not just take the node list and choose the first of them. Depending on the
	// cluster and the scheduler it might be that a "normal" pod cannot be
	// scheduled onto it.
	By("Trying to launch a pod with a label to get a node which can launch it.")
	pod := runPausePod(f, pausePodConfig{
		Name:   "with-label-" + string(uuid.NewUUID()),
		Labels: map[string]string{"security": "S1"},
	})
	return pod.Spec.NodeName, pod.Name
}

func GetNodeThatCanRunPod(f *framework.Framework) string {
	By("Trying to launch a pod without a label to get a node which can launch it.")
	return runPodAndGetNodeName(f, pausePodConfig{Name: "without-label"})
}

func getNodeThatCanRunPodWithoutToleration(f *framework.Framework) string {
	By("Trying to launch a pod without a toleration to get a node which can launch it.")
	return runPodAndGetNodeName(f, pausePodConfig{Name: "without-toleration"})
}

func CreateHostPortPods(f *framework.Framework, id string, replicas int, expectRunning bool) {
	By(fmt.Sprintf("Running RC which reserves host port"))
	config := &testutils.RCConfig{
		Client:         f.ClientSet,
		InternalClient: f.InternalClientset,
		Name:           id,
		Namespace:      f.Namespace.Name,
		Timeout:        defaultTimeout,
		Image:          framework.GetPauseImageName(f.ClientSet),
		Replicas:       replicas,
		HostPorts:      map[string]int{"port1": 4321},
	}
	err := framework.RunRC(*config)
	if expectRunning {
		framework.ExpectNoError(err)
	}
}

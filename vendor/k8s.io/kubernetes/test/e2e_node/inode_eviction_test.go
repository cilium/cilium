/*
Copyright 2016 The Kubernetes Authors.

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

package e2e_node

import (
	"fmt"
	"path/filepath"
	"time"

	"k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	nodeutil "k8s.io/kubernetes/pkg/api/v1/node"
	"k8s.io/kubernetes/pkg/kubelet/apis/kubeletconfig"
	kubeletmetrics "k8s.io/kubernetes/pkg/kubelet/metrics"
	"k8s.io/kubernetes/test/e2e/framework"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

// Eviction Policy is described here:
// https://github.com/kubernetes/kubernetes/blob/master/docs/proposals/kubelet-eviction.md

const (
	postTestConditionMonitoringPeriod = 2 * time.Minute
	evictionPollInterval              = 2 * time.Second
	// pressure conditions often surface after evictions because of delay in propegation of metrics to pressure
	// we wait this period after evictions to make sure that we wait out this delay
	pressureDelay = 20 * time.Second
)

var _ = framework.KubeDescribe("InodeEviction [Slow] [Serial] [Disruptive] [Flaky]", func() {
	f := framework.NewDefaultFramework("inode-eviction-test")

	volumeMountPath := "/test-empty-dir-mnt"
	podTestSpecs := []podTestSpec{
		{
			evictionPriority: 1, // This pod should be evicted before the normal memory usage pod
			pod: &v1.Pod{
				ObjectMeta: metav1.ObjectMeta{Name: "container-inode-hog-pod"},
				Spec: v1.PodSpec{
					RestartPolicy: v1.RestartPolicyNever,
					Containers: []v1.Container{
						{
							Image:   busyboxImage,
							Name:    "container-inode-hog-container",
							Command: getInodeConsumingCommand(""),
						},
					},
				},
			},
		},
		{
			evictionPriority: 1, // This pod should be evicted before the normal memory usage pod
			pod: &v1.Pod{
				ObjectMeta: metav1.ObjectMeta{Name: "volume-inode-hog-pod"},
				Spec: v1.PodSpec{
					RestartPolicy: v1.RestartPolicyNever,
					Containers: []v1.Container{
						{
							Image:   busyboxImage,
							Name:    "volume-inode-hog-container",
							Command: getInodeConsumingCommand(volumeMountPath),
							VolumeMounts: []v1.VolumeMount{
								{MountPath: volumeMountPath, Name: "test-empty-dir"},
							},
						},
					},
					Volumes: []v1.Volume{
						{Name: "test-empty-dir", VolumeSource: v1.VolumeSource{EmptyDir: &v1.EmptyDirVolumeSource{}}},
					},
				},
			},
		},
		{
			evictionPriority: 0, // This pod should never be evicted
			pod:              getInnocentPod(),
		},
	}
	evictionTestTimeout := 30 * time.Minute
	testCondition := "Disk Pressure due to Inodes"

	Context(fmt.Sprintf("when we run containers that should cause %s", testCondition), func() {
		tempSetCurrentKubeletConfig(f, func(initialConfig *kubeletconfig.KubeletConfiguration) {
			initialConfig.EvictionHard = "nodefs.inodesFree<70%"
		})
		// Place the remainder of the test within a context so that the kubelet config is set before and after the test.
		Context("With kubeconfig updated", func() {
			runEvictionTest(f, testCondition, podTestSpecs, evictionTestTimeout, hasInodePressure)
		})
	})
})

// Struct used by runEvictionTest that specifies the pod, and when that pod should be evicted, relative to other pods
type podTestSpec struct {
	// 0 should never be evicted, 1 shouldn't evict before 2, etc.
	// If two are ranked at 1, either is permitted to fail before the other.
	// The test ends when all other than the 0 have been evicted
	evictionPriority int
	pod              *v1.Pod
}

// runEvictionTest sets up a testing environment given the provided nodes, and checks a few things:
//		It ensures that the desired testCondition is actually triggered.
//		It ensures that evictionPriority 0 pods are not evicted
//		It ensures that lower evictionPriority pods are always evicted before higher evictionPriority pods (2 evicted before 1, etc.)
//		It ensures that all lower evictionPriority pods are eventually evicted.
// runEvictionTest then cleans up the testing environment by deleting provided nodes, and ensures that testCondition no longer exists
func runEvictionTest(f *framework.Framework, testCondition string, podTestSpecs []podTestSpec, evictionTestTimeout time.Duration,
	hasPressureCondition func(*framework.Framework, string) (bool, error)) {
	BeforeEach(func() {
		By("seting up pods to be used by tests")
		for _, spec := range podTestSpecs {
			By(fmt.Sprintf("creating pod with container: %s", spec.pod.Name))
			f.PodClient().CreateSync(spec.pod)
		}
	})

	It(fmt.Sprintf("should eventually see %s, and then evict all of the correct pods", testCondition), func() {
		configEnabled, err := isKubeletConfigEnabled(f)
		framework.ExpectNoError(err)
		if !configEnabled {
			framework.Skipf("Dynamic kubelet config must be enabled for this test to run.")
		}
		Eventually(func() error {
			hasPressure, err := hasPressureCondition(f, testCondition)
			if err != nil {
				return err
			}
			if hasPressure {
				return nil
			}
			return fmt.Errorf("Condition: %s not encountered", testCondition)
		}, evictionTestTimeout, evictionPollInterval).Should(BeNil())

		Eventually(func() error {
			// Gather current information
			updatedPodList, err := f.ClientSet.Core().Pods(f.Namespace.Name).List(metav1.ListOptions{})
			updatedPods := updatedPodList.Items
			for _, p := range updatedPods {
				framework.Logf("fetching pod %s; phase= %v", p.Name, p.Status.Phase)
			}
			logKubeletMetrics(kubeletmetrics.EvictionStatsAgeKey)
			_, err = hasPressureCondition(f, testCondition)
			if err != nil {
				return err
			}

			By("checking eviction ordering and ensuring important pods dont fail")
			done := true
			for _, priorityPodSpec := range podTestSpecs {
				var priorityPod v1.Pod
				for _, p := range updatedPods {
					if p.Name == priorityPodSpec.pod.Name {
						priorityPod = p
					}
				}
				Expect(priorityPod).NotTo(BeNil())

				// Check eviction ordering.
				// Note: it is alright for a priority 1 and priority 2 pod (for example) to fail in the same round
				for _, lowPriorityPodSpec := range podTestSpecs {
					var lowPriorityPod v1.Pod
					for _, p := range updatedPods {
						if p.Name == lowPriorityPodSpec.pod.Name {
							lowPriorityPod = p
						}
					}
					Expect(lowPriorityPod).NotTo(BeNil())
					if priorityPodSpec.evictionPriority < lowPriorityPodSpec.evictionPriority && lowPriorityPod.Status.Phase == v1.PodRunning {
						Expect(priorityPod.Status.Phase).NotTo(Equal(v1.PodFailed),
							fmt.Sprintf("%s pod failed before %s pod", priorityPodSpec.pod.Name, lowPriorityPodSpec.pod.Name))
					}
				}

				// EvictionPriority 0 pods should not fail
				if priorityPodSpec.evictionPriority == 0 {
					Expect(priorityPod.Status.Phase).NotTo(Equal(v1.PodFailed),
						fmt.Sprintf("%s pod failed (and shouldn't have failed)", priorityPod.Name))
				}

				// If a pod that is not evictionPriority 0 has not been evicted, we are not done
				if priorityPodSpec.evictionPriority != 0 && priorityPod.Status.Phase != v1.PodFailed {
					done = false
				}
			}
			if done {
				return nil
			}
			return fmt.Errorf("pods that caused %s have not been evicted.", testCondition)
		}, evictionTestTimeout, evictionPollInterval).Should(BeNil())

		// We observe pressure from the API server.  The eviction manager observes pressure from the kubelet internal stats.
		// This means the eviction manager will observe pressure before we will, creating a delay between when the eviction manager
		// evicts a pod, and when we observe the pressure by querrying the API server.  Add a delay here to account for this delay
		By("making sure pressure from test has surfaced before continuing")
		time.Sleep(pressureDelay)

		By("making sure conditions eventually return to normal")
		Eventually(func() error {
			hasPressure, err := hasPressureCondition(f, testCondition)
			if err != nil {
				return err
			}
			if hasPressure {
				return fmt.Errorf("Conditions havent returned to normal, we still have %s", testCondition)
			}
			return nil
		}, evictionTestTimeout, evictionPollInterval).Should(BeNil())

		By("making sure conditions do not return, and that pods that shouldnt fail dont fail")
		Consistently(func() error {
			hasPressure, err := hasPressureCondition(f, testCondition)
			if err != nil {
				// Race conditions sometimes occur when checking pressure condition due to #38710 (Docker bug)
				// Do not fail the test when this occurs, since this is expected to happen occasionally.
				framework.Logf("Failed to check pressure condition. Error: %v", err)
				return nil
			}
			if hasPressure {
				return fmt.Errorf("%s dissappeared and then reappeared", testCondition)
			}
			// Gather current information
			updatedPodList, _ := f.ClientSet.Core().Pods(f.Namespace.Name).List(metav1.ListOptions{})
			for _, priorityPodSpec := range podTestSpecs {
				// EvictionPriority 0 pods should not fail
				if priorityPodSpec.evictionPriority == 0 {
					for _, p := range updatedPodList.Items {
						if p.Name == priorityPodSpec.pod.Name && p.Status.Phase == v1.PodFailed {
							logKubeletMetrics(kubeletmetrics.EvictionStatsAgeKey)
							return fmt.Errorf("%s pod failed (delayed) and shouldn't have failed", p.Name)
						}
					}
				}
			}
			return nil
		}, postTestConditionMonitoringPeriod, evictionPollInterval).Should(BeNil())

		By("making sure we can start a new pod after the test")
		podName := "test-admit-pod"
		f.PodClient().CreateSync(&v1.Pod{
			ObjectMeta: metav1.ObjectMeta{
				Name: podName,
			},
			Spec: v1.PodSpec{
				RestartPolicy: v1.RestartPolicyNever,
				Containers: []v1.Container{
					{
						Image: framework.GetPauseImageNameForHostArch(),
						Name:  podName,
					},
				},
			},
		})
	})

	AfterEach(func() {
		By("deleting pods")
		for _, spec := range podTestSpecs {
			By(fmt.Sprintf("deleting pod: %s", spec.pod.Name))
			f.PodClient().DeleteSync(spec.pod.Name, &metav1.DeleteOptions{}, framework.DefaultPodDeletionTimeout)
		}

		if CurrentGinkgoTestDescription().Failed {
			if framework.TestContext.DumpLogsOnFailure {
				logPodEvents(f)
				logNodeEvents(f)
			}
			By("sleeping to allow for cleanup of test")
			time.Sleep(postTestConditionMonitoringPeriod)
		}
	})
}

// Returns TRUE if the node has disk pressure due to inodes exists on the node, FALSE otherwise
func hasInodePressure(f *framework.Framework, testCondition string) (bool, error) {
	localNodeStatus := getLocalNode(f).Status
	_, pressure := nodeutil.GetNodeCondition(&localNodeStatus, v1.NodeDiskPressure)
	Expect(pressure).NotTo(BeNil())
	hasPressure := pressure.Status == v1.ConditionTrue
	By(fmt.Sprintf("checking if pod has %s: %v", testCondition, hasPressure))

	// Additional Logging relating to Inodes
	summary, err := getNodeSummary()
	if err != nil {
		return false, err
	}
	if summary.Node.Runtime != nil && summary.Node.Runtime.ImageFs != nil && summary.Node.Runtime.ImageFs.Inodes != nil && summary.Node.Runtime.ImageFs.InodesFree != nil {
		framework.Logf("imageFsInfo.Inodes: %d, imageFsInfo.InodesFree: %d", *summary.Node.Runtime.ImageFs.Inodes, *summary.Node.Runtime.ImageFs.InodesFree)
	}
	if summary.Node.Fs != nil && summary.Node.Fs.Inodes != nil && summary.Node.Fs.InodesFree != nil {
		framework.Logf("rootFsInfo.Inodes: %d, rootFsInfo.InodesFree: %d", *summary.Node.Fs.Inodes, *summary.Node.Fs.InodesFree)
	}
	for _, pod := range summary.Pods {
		framework.Logf("Pod: %s", pod.PodRef.Name)
		for _, container := range pod.Containers {
			if container.Rootfs != nil && container.Rootfs.InodesUsed != nil {
				framework.Logf("--- summary Container: %s inodeUsage: %d", container.Name, *container.Rootfs.InodesUsed)
			}
		}
		for _, volume := range pod.VolumeStats {
			if volume.FsStats.InodesUsed != nil {
				framework.Logf("--- summary Volume: %s inodeUsage: %d", volume.Name, *volume.FsStats.InodesUsed)
			}
		}
	}
	return hasPressure, nil
}

// returns a pod that does not use any resources
func getInnocentPod() *v1.Pod {
	return &v1.Pod{
		ObjectMeta: metav1.ObjectMeta{Name: "innocent-pod"},
		Spec: v1.PodSpec{
			RestartPolicy: v1.RestartPolicyNever,
			Containers: []v1.Container{
				{
					Image: busyboxImage,
					Name:  "innocent-container",
					Command: []string{
						"sh",
						"-c", //make one large file
						"dd if=/dev/urandom of=largefile bs=5000000000 count=1; while true; do sleep 5; done",
					},
				},
			},
		},
	}
}

func getInodeConsumingCommand(path string) []string {
	return []string{
		"sh",
		"-c",
		fmt.Sprintf("i=0; while true; do touch %s${i}.txt; sleep 0.001; i=$((i+=1)); done;", filepath.Join(path, "smallfile")),
	}
}

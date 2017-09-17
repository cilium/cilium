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

package node

import (
	"fmt"
	"path/filepath"
	"strings"
	"time"

	"k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/sets"
	"k8s.io/apimachinery/pkg/util/uuid"
	"k8s.io/apimachinery/pkg/util/wait"
	clientset "k8s.io/client-go/kubernetes"
	"k8s.io/kubernetes/pkg/api/testapi"
	"k8s.io/kubernetes/test/e2e/framework"
	testutils "k8s.io/kubernetes/test/utils"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	imageutils "k8s.io/kubernetes/test/utils/image"
)

const (
	// Interval to framework.Poll /runningpods on a node
	pollInterval = 1 * time.Second
	// Interval to framework.Poll /stats/container on a node
	containerStatsPollingInterval = 5 * time.Second
	// Maximum number of nodes that we constraint to
	maxNodesToCheck = 10
)

// getPodMatches returns a set of pod names on the given node that matches the
// podNamePrefix and namespace.
func getPodMatches(c clientset.Interface, nodeName string, podNamePrefix string, namespace string) sets.String {
	matches := sets.NewString()
	framework.Logf("Checking pods on node %v via /runningpods endpoint", nodeName)
	runningPods, err := framework.GetKubeletPods(c, nodeName)
	if err != nil {
		framework.Logf("Error checking running pods on %v: %v", nodeName, err)
		return matches
	}
	for _, pod := range runningPods.Items {
		if pod.Namespace == namespace && strings.HasPrefix(pod.Name, podNamePrefix) {
			matches.Insert(pod.Name)
		}
	}
	return matches
}

// waitTillNPodsRunningOnNodes polls the /runningpods endpoint on kubelet until
// it finds targetNumPods pods that match the given criteria (namespace and
// podNamePrefix). Note that we usually use label selector to filter pods that
// belong to the same RC. However, we use podNamePrefix with namespace here
// because pods returned from /runningpods do not contain the original label
// information; they are reconstructed by examining the container runtime. In
// the scope of this test, we do not expect pod naming conflicts so
// podNamePrefix should be sufficient to identify the pods.
func waitTillNPodsRunningOnNodes(c clientset.Interface, nodeNames sets.String, podNamePrefix string, namespace string, targetNumPods int, timeout time.Duration) error {
	return wait.Poll(pollInterval, timeout, func() (bool, error) {
		matchCh := make(chan sets.String, len(nodeNames))
		for _, item := range nodeNames.List() {
			// Launch a goroutine per node to check the pods running on the nodes.
			nodeName := item
			go func() {
				matchCh <- getPodMatches(c, nodeName, podNamePrefix, namespace)
			}()
		}

		seen := sets.NewString()
		for i := 0; i < len(nodeNames.List()); i++ {
			seen = seen.Union(<-matchCh)
		}
		if seen.Len() == targetNumPods {
			return true, nil
		}
		framework.Logf("Waiting for %d pods to be running on the node; %d are currently running;", targetNumPods, seen.Len())
		return false, nil
	})
}

// updates labels of nodes given by nodeNames.
// In case a given label already exists, it overwrites it. If label to remove doesn't exist
// it silently ignores it.
// TODO: migrate to use framework.AddOrUpdateLabelOnNode/framework.RemoveLabelOffNode
func updateNodeLabels(c clientset.Interface, nodeNames sets.String, toAdd, toRemove map[string]string) {
	const maxRetries = 5
	for nodeName := range nodeNames {
		var node *v1.Node
		var err error
		for i := 0; i < maxRetries; i++ {
			node, err = c.CoreV1().Nodes().Get(nodeName, metav1.GetOptions{})
			if err != nil {
				framework.Logf("Error getting node %s: %v", nodeName, err)
				continue
			}
			if toAdd != nil {
				for k, v := range toAdd {
					node.ObjectMeta.Labels[k] = v
				}
			}
			if toRemove != nil {
				for k := range toRemove {
					delete(node.ObjectMeta.Labels, k)
				}
			}
			_, err = c.CoreV1().Nodes().Update(node)
			if err != nil {
				framework.Logf("Error updating node %s: %v", nodeName, err)
			} else {
				break
			}
		}
		Expect(err).NotTo(HaveOccurred())
	}
}

// Restart the passed-in nfs-server by issuing a `/usr/sbin/rpc.nfsd 1` command in the
// pod's (only) container. This command changes the number of nfs server threads from
// (presumably) zero back to 1, and therefore allows nfs to open connections again.
func restartNfsServer(serverPod *v1.Pod) {
	const startcmd = "/usr/sbin/rpc.nfsd 1"
	ns := fmt.Sprintf("--namespace=%v", serverPod.Namespace)
	framework.RunKubectlOrDie("exec", ns, serverPod.Name, "--", "/bin/sh", "-c", startcmd)
}

// Stop the passed-in nfs-server by issuing a `/usr/sbin/rpc.nfsd 0` command in the
// pod's (only) container. This command changes the number of nfs server threads to 0,
// thus closing all open nfs connections.
func stopNfsServer(serverPod *v1.Pod) {
	const stopcmd = "/usr/sbin/rpc.nfsd 0"
	ns := fmt.Sprintf("--namespace=%v", serverPod.Namespace)
	framework.RunKubectlOrDie("exec", ns, serverPod.Name, "--", "/bin/sh", "-c", stopcmd)
}

// Creates a pod that mounts an nfs volume that is served by the nfs-server pod. The container
// will execute the passed in shell cmd. Waits for the pod to start.
// Note: the nfs plugin is defined inline, no PV or PVC.
func createPodUsingNfs(f *framework.Framework, c clientset.Interface, ns, nfsIP, cmd string) *v1.Pod {
	By("create pod using nfs volume")

	isPrivileged := true
	cmdLine := []string{"-c", cmd}
	pod := &v1.Pod{
		TypeMeta: metav1.TypeMeta{
			Kind:       "Pod",
			APIVersion: testapi.Groups[v1.GroupName].GroupVersion().String(),
		},
		ObjectMeta: metav1.ObjectMeta{
			GenerateName: "pod-nfs-vol-",
			Namespace:    ns,
		},
		Spec: v1.PodSpec{
			Containers: []v1.Container{
				{
					Name:    "pod-nfs-vol",
					Image:   imageutils.GetBusyBoxImage(),
					Command: []string{"/bin/sh"},
					Args:    cmdLine,
					VolumeMounts: []v1.VolumeMount{
						{
							Name:      "nfs-vol",
							MountPath: "/mnt",
						},
					},
					SecurityContext: &v1.SecurityContext{
						Privileged: &isPrivileged,
					},
				},
			},
			RestartPolicy: v1.RestartPolicyNever, //don't restart pod
			Volumes: []v1.Volume{
				{
					Name: "nfs-vol",
					VolumeSource: v1.VolumeSource{
						NFS: &v1.NFSVolumeSource{
							Server:   nfsIP,
							Path:     "/exports",
							ReadOnly: false,
						},
					},
				},
			},
		},
	}
	rtnPod, err := c.CoreV1().Pods(ns).Create(pod)
	Expect(err).NotTo(HaveOccurred())

	err = f.WaitForPodReady(rtnPod.Name) // running & ready
	Expect(err).NotTo(HaveOccurred())

	rtnPod, err = c.CoreV1().Pods(ns).Get(rtnPod.Name, metav1.GetOptions{}) // return fresh pod
	Expect(err).NotTo(HaveOccurred())
	return rtnPod
}

// Checks for a lingering nfs mount and/or uid directory on the pod's host. The host IP is used
// so that this test runs in GCE, where it appears that SSH cannot resolve the hostname.
// If expectClean is true then we expect the node to be cleaned up and thus commands like
// `ls <uid-dir>` should fail (since that dir was removed). If expectClean is false then we expect
// the node is not cleaned up, and thus cmds like `ls <uid-dir>` should succeed. We wait for the
// kubelet to be cleaned up, afterwhich an error is reported.
func checkPodCleanup(c clientset.Interface, pod *v1.Pod, expectClean bool) {
	timeout := 5 * time.Minute
	poll := 20 * time.Second
	podDir := filepath.Join("/var/lib/kubelet/pods", string(pod.UID))
	mountDir := filepath.Join(podDir, "volumes", "kubernetes.io~nfs")
	// use ip rather than hostname in GCE
	nodeIP, err := framework.GetHostExternalAddress(c, pod)
	Expect(err).NotTo(HaveOccurred())

	condMsg := "deleted"
	if !expectClean {
		condMsg = "present"
	}

	// table of host tests to perform (order may matter so not using a map)
	type testT struct {
		feature string // feature to test
		cmd     string // remote command to execute on node
	}
	tests := []testT{
		{
			feature: "pod UID directory",
			cmd:     fmt.Sprintf("sudo ls %v", podDir),
		},
		{
			feature: "pod nfs mount",
			cmd:     fmt.Sprintf("sudo mount | grep %v", mountDir),
		},
	}

	for _, test := range tests {
		framework.Logf("Wait up to %v for host's (%v) %q to be %v", timeout, nodeIP, test.feature, condMsg)
		err = wait.Poll(poll, timeout, func() (bool, error) {
			result, err := framework.NodeExec(nodeIP, test.cmd)
			Expect(err).NotTo(HaveOccurred())
			framework.LogSSHResult(result)
			ok := (result.Code == 0 && len(result.Stdout) > 0 && len(result.Stderr) == 0)
			if expectClean && ok { // keep trying
				return false, nil
			}
			if !expectClean && !ok { // stop wait loop
				return true, fmt.Errorf("%v is gone but expected to exist", test.feature)
			}
			return true, nil // done, host is as expected
		})
		Expect(err).NotTo(HaveOccurred(), fmt.Sprintf("Host (%v) cleanup error: %v. Expected %q to be %v", nodeIP, err, test.feature, condMsg))
	}

	if expectClean {
		framework.Logf("Pod's host has been cleaned up")
	} else {
		framework.Logf("Pod's host has not been cleaned up (per expectation)")
	}
}

var _ = SIGDescribe("kubelet", func() {
	var (
		c  clientset.Interface
		ns string
	)
	f := framework.NewDefaultFramework("kubelet")

	BeforeEach(func() {
		c = f.ClientSet
		ns = f.Namespace.Name
	})

	SIGDescribe("Clean up pods on node", func() {
		var (
			numNodes        int
			nodeNames       sets.String
			nodeLabels      map[string]string
			resourceMonitor *framework.ResourceMonitor
		)
		type DeleteTest struct {
			podsPerNode int
			timeout     time.Duration
		}

		deleteTests := []DeleteTest{
			{podsPerNode: 10, timeout: 1 * time.Minute},
		}

		BeforeEach(func() {
			// Use node labels to restrict the pods to be assigned only to the
			// nodes we observe initially.
			nodeLabels = make(map[string]string)
			nodeLabels["kubelet_cleanup"] = "true"
			nodes := framework.GetReadySchedulableNodesOrDie(c)
			numNodes = len(nodes.Items)
			Expect(numNodes).NotTo(BeZero())
			nodeNames = sets.NewString()
			// If there are a lot of nodes, we don't want to use all of them
			// (if there are 1000 nodes in the cluster, starting 10 pods/node
			// will take ~10 minutes today). And there is also deletion phase.
			// Instead, we choose at most 10 nodes.
			if numNodes > maxNodesToCheck {
				numNodes = maxNodesToCheck
			}
			for i := 0; i < numNodes; i++ {
				nodeNames.Insert(nodes.Items[i].Name)
			}
			updateNodeLabels(c, nodeNames, nodeLabels, nil)

			// Start resourceMonitor only in small clusters.
			if len(nodes.Items) <= maxNodesToCheck {
				resourceMonitor = framework.NewResourceMonitor(f.ClientSet, framework.TargetContainers(), containerStatsPollingInterval)
				resourceMonitor.Start()
			}
		})

		AfterEach(func() {
			if resourceMonitor != nil {
				resourceMonitor.Stop()
			}
			// If we added labels to nodes in this test, remove them now.
			updateNodeLabels(c, nodeNames, nil, nodeLabels)
		})

		for _, itArg := range deleteTests {
			name := fmt.Sprintf(
				"kubelet should be able to delete %d pods per node in %v.", itArg.podsPerNode, itArg.timeout)
			It(name, func() {
				totalPods := itArg.podsPerNode * numNodes
				By(fmt.Sprintf("Creating a RC of %d pods and wait until all pods of this RC are running", totalPods))
				rcName := fmt.Sprintf("cleanup%d-%s", totalPods, string(uuid.NewUUID()))

				Expect(framework.RunRC(testutils.RCConfig{
					Client:         f.ClientSet,
					InternalClient: f.InternalClientset,
					Name:           rcName,
					Namespace:      f.Namespace.Name,
					Image:          framework.GetPauseImageName(f.ClientSet),
					Replicas:       totalPods,
					NodeSelector:   nodeLabels,
				})).NotTo(HaveOccurred())
				// Perform a sanity check so that we know all desired pods are
				// running on the nodes according to kubelet. The timeout is set to
				// only 30 seconds here because framework.RunRC already waited for all pods to
				// transition to the running status.
				Expect(waitTillNPodsRunningOnNodes(f.ClientSet, nodeNames, rcName, ns, totalPods,
					time.Second*30)).NotTo(HaveOccurred())
				if resourceMonitor != nil {
					resourceMonitor.LogLatest()
				}

				By("Deleting the RC")
				framework.DeleteRCAndPods(f.ClientSet, f.InternalClientset, f.Namespace.Name, rcName)
				// Check that the pods really are gone by querying /runningpods on the
				// node. The /runningpods handler checks the container runtime (or its
				// cache) and  returns a list of running pods. Some possible causes of
				// failures are:
				//   - kubelet deadlock
				//   - a bug in graceful termination (if it is enabled)
				//   - docker slow to delete pods (or resource problems causing slowness)
				start := time.Now()
				Expect(waitTillNPodsRunningOnNodes(f.ClientSet, nodeNames, rcName, ns, 0,
					itArg.timeout)).NotTo(HaveOccurred())
				framework.Logf("Deleting %d pods on %d nodes completed in %v after the RC was deleted", totalPods, len(nodeNames),
					time.Since(start))
				if resourceMonitor != nil {
					resourceMonitor.LogCPUSummary()
				}
			})
		}
	})

	// Test host cleanup when disrupting the volume environment.
	SIGDescribe("host cleanup with volume mounts [sig-storage][HostCleanup][Flaky]", func() {

		type hostCleanupTest struct {
			itDescr string
			podCmd  string
		}

		// Disrupt the nfs-server pod after a client pod accesses the nfs volume.
		// Note: the nfs-server is stopped NOT deleted. This is done to preserve its ip addr.
		//       If the nfs-server pod is deleted the client pod's mount can not be unmounted.
		//       If the nfs-server pod is deleted and re-created, due to having a different ip
		//       addr, the client pod's mount still cannot be unmounted.
		Context("Host cleanup after disrupting NFS volume [NFS]", func() {
			// issue #31272
			var (
				nfsServerPod *v1.Pod
				nfsIP        string
				NFSconfig    framework.VolumeTestConfig
				pod          *v1.Pod // client pod
			)

			// fill in test slice for this context
			testTbl := []hostCleanupTest{
				{
					itDescr: "after stopping the nfs-server and deleting the (sleeping) client pod, the NFS mount and the pod's UID directory should be removed.",
					podCmd:  "sleep 6000", // keep pod running
				},
				{
					itDescr: "after stopping the nfs-server and deleting the (active) client pod, the NFS mount and the pod's UID directory should be removed.",
					podCmd:  "while true; do echo FeFieFoFum >>/mnt/SUCCESS; sleep 1; cat /mnt/SUCCESS; done",
				},
			}

			BeforeEach(func() {
				framework.SkipUnlessProviderIs(framework.ProvidersWithSSH...)
				NFSconfig, nfsServerPod, nfsIP = framework.NewNFSServer(c, ns, []string{"-G", "777", "/exports"})
			})

			AfterEach(func() {
				framework.ExpectNoError(framework.DeletePodWithWait(f, c, pod), "AfterEach: Failed to delete pod ", pod.Name)
				framework.ExpectNoError(framework.DeletePodWithWait(f, c, nfsServerPod), "AfterEach: Failed to delete pod ", nfsServerPod.Name)
			})

			// execute It blocks from above table of tests
			for _, t := range testTbl {
				It(t.itDescr, func() {
					pod = createPodUsingNfs(f, c, ns, nfsIP, t.podCmd)

					By("Stop the NFS server")
					stopNfsServer(nfsServerPod)

					By("Delete the pod mounted to the NFS volume")
					framework.ExpectNoError(framework.DeletePodWithWait(f, c, pod), "Failed to delete pod ", pod.Name)
					// pod object is now stale, but is intentionally not nil

					By("Check if pod's host has been cleaned up -- expect not")
					checkPodCleanup(c, pod, false)

					By("Restart the nfs server")
					restartNfsServer(nfsServerPod)

					By("Verify host running the deleted pod is now cleaned up")
					checkPodCleanup(c, pod, true)
				})
			}
		})
	})
})

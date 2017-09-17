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

package storage

import (
	"fmt"
	"strings"
	"time"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	"k8s.io/api/core/v1"
	apierrs "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	clientset "k8s.io/client-go/kubernetes"
	"k8s.io/kubernetes/test/e2e/framework"
)

type testBody func(c clientset.Interface, f *framework.Framework, clientPod *v1.Pod, pvc *v1.PersistentVolumeClaim, pv *v1.PersistentVolume)
type disruptiveTest struct {
	testItStmt string
	runTest    testBody
}
type kubeletOpt string

const (
	MinNodes                    = 2
	NodeStateTimeout            = 1 * time.Minute
	kStart           kubeletOpt = "start"
	kStop            kubeletOpt = "stop"
	kRestart         kubeletOpt = "restart"
)

var _ = SIGDescribe("PersistentVolumes[Disruptive][Flaky]", func() {

	f := framework.NewDefaultFramework("disruptive-pv")
	var (
		c                         clientset.Interface
		ns                        string
		nfsServerPod              *v1.Pod
		nfsPVconfig               framework.PersistentVolumeConfig
		pvcConfig                 framework.PersistentVolumeClaimConfig
		nfsServerIP, clientNodeIP string
		clientNode                *v1.Node
		volLabel                  labels.Set
		selector                  *metav1.LabelSelector
	)

	BeforeEach(func() {
		// To protect the NFS volume pod from the kubelet restart, we isolate it on its own node.
		framework.SkipUnlessNodeCountIsAtLeast(MinNodes)
		framework.SkipIfProviderIs("local")

		c = f.ClientSet
		ns = f.Namespace.Name
		volLabel = labels.Set{framework.VolumeSelectorKey: ns}
		selector = metav1.SetAsLabelSelector(volLabel)
		// Start the NFS server pod.
		_, nfsServerPod, nfsServerIP = framework.NewNFSServer(c, ns, []string{"-G", "777", "/exports"})
		nfsPVconfig = framework.PersistentVolumeConfig{
			NamePrefix: "nfs-",
			Labels:     volLabel,
			PVSource: v1.PersistentVolumeSource{
				NFS: &v1.NFSVolumeSource{
					Server:   nfsServerIP,
					Path:     "/exports",
					ReadOnly: false,
				},
			},
		}
		pvcConfig = framework.PersistentVolumeClaimConfig{
			Annotations: map[string]string{
				v1.BetaStorageClassAnnotation: "",
			},
			Selector: selector,
		}
		// Get the first ready node IP that is not hosting the NFS pod.
		if clientNodeIP == "" {
			framework.Logf("Designating test node")
			nodes := framework.GetReadySchedulableNodesOrDie(c)
			for _, node := range nodes.Items {
				if node.Name != nfsServerPod.Spec.NodeName {
					clientNode = &node
					clientNodeIP = framework.GetNodeExternalIP(clientNode)
					break
				}
			}
			Expect(clientNodeIP).NotTo(BeEmpty())
		}
	})

	AfterEach(func() {
		framework.DeletePodWithWait(f, c, nfsServerPod)
	})

	Context("when kubelet restarts", func() {
		var (
			clientPod *v1.Pod
			pv        *v1.PersistentVolume
			pvc       *v1.PersistentVolumeClaim
		)

		BeforeEach(func() {
			framework.Logf("Initializing test spec")
			clientPod, pv, pvc = initTestCase(f, c, nfsPVconfig, pvcConfig, ns, clientNode.Name)
		})

		AfterEach(func() {
			framework.Logf("Tearing down test spec")
			tearDownTestCase(c, f, ns, clientPod, pvc, pv)
			pv, pvc, clientPod = nil, nil, nil
		})

		// Test table housing the It() title string and test spec.  runTest is type testBody, defined at
		// the start of this file.  To add tests, define a function mirroring the testBody signature and assign
		// to runTest.
		disruptiveTestTable := []disruptiveTest{
			{
				testItStmt: "Should test that a file written to the mount before kubelet restart is readable after restart.",
				runTest:    testKubeletRestartsAndRestoresMount,
			},
			{
				testItStmt: "Should test that a volume mounted to a pod that is deleted while the kubelet is down unmounts when the kubelet returns.",
				runTest:    testVolumeUnmountsFromDeletedPod,
			},
		}

		// Test loop executes each disruptiveTest iteratively.
		for _, test := range disruptiveTestTable {
			func(t disruptiveTest) {
				It(t.testItStmt, func() {
					By("Executing Spec")
					t.runTest(c, f, clientPod, pvc, pv)
				})
			}(test)
		}
	})
})

// testKubeletRestartsAndRestoresMount tests that a volume mounted to a pod remains mounted after a kubelet restarts
func testKubeletRestartsAndRestoresMount(c clientset.Interface, f *framework.Framework, clientPod *v1.Pod, pvc *v1.PersistentVolumeClaim, pv *v1.PersistentVolume) {
	By("Writing to the volume.")
	file := "/mnt/_SUCCESS"
	out, err := podExec(clientPod, fmt.Sprintf("touch %s", file))
	framework.Logf(out)
	Expect(err).NotTo(HaveOccurred())

	By("Restarting kubelet")
	kubeletCommand(kRestart, c, clientPod)

	By("Testing that written file is accessible.")
	out, err = podExec(clientPod, fmt.Sprintf("cat %s", file))
	framework.Logf(out)
	Expect(err).NotTo(HaveOccurred())
	framework.Logf("Volume mount detected on pod %s and written file %s is readable post-restart.", clientPod.Name, file)
}

// testVolumeUnmountsFromDeletedPod tests that a volume unmounts if the client pod was deleted while the kubelet was down.
func testVolumeUnmountsFromDeletedPod(c clientset.Interface, f *framework.Framework, clientPod *v1.Pod, pvc *v1.PersistentVolumeClaim, pv *v1.PersistentVolume) {
	nodeIP, err := framework.GetHostExternalAddress(c, clientPod)
	Expect(err).NotTo(HaveOccurred())
	nodeIP = nodeIP + ":22"

	By("Expecting the volume mount to be found.")
	result, err := framework.SSH(fmt.Sprintf("mount | grep %s", clientPod.UID), nodeIP, framework.TestContext.Provider)
	framework.LogSSHResult(result)
	Expect(err).NotTo(HaveOccurred(), "Encountered SSH error.")
	Expect(result.Code).To(BeZero(), fmt.Sprintf("Expected grep exit code of 0, got %d", result.Code))

	By("Stopping the kubelet.")
	kubeletCommand(kStop, c, clientPod)
	defer func() {
		if err != nil {
			kubeletCommand(kStart, c, clientPod)
		}
	}()
	By(fmt.Sprintf("Deleting Pod %q", clientPod.Name))
	err = c.Core().Pods(clientPod.Namespace).Delete(clientPod.Name, &metav1.DeleteOptions{})
	Expect(err).NotTo(HaveOccurred())
	By("Starting the kubelet and waiting for pod to delete.")
	kubeletCommand(kStart, c, clientPod)
	err = f.WaitForPodTerminated(clientPod.Name, "")
	if !apierrs.IsNotFound(err) && err != nil {
		Expect(err).NotTo(HaveOccurred(), "Expected pod to terminate.")
	}

	By("Expecting the volume mount not to be found.")
	result, err = framework.SSH(fmt.Sprintf("mount | grep %s", clientPod.UID), nodeIP, framework.TestContext.Provider)
	framework.LogSSHResult(result)
	Expect(err).NotTo(HaveOccurred(), "Encountered SSH error.")
	Expect(result.Stdout).To(BeEmpty(), "Expected grep stdout to be empty (i.e. no mount found).")
	framework.Logf("Volume unmounted on node %s", clientPod.Spec.NodeName)
}

// initTestCase initializes spec resources (pv, pvc, and pod) and returns pointers to be consumed
// by the test.
func initTestCase(f *framework.Framework, c clientset.Interface, pvConfig framework.PersistentVolumeConfig, pvcConfig framework.PersistentVolumeClaimConfig, ns, nodeName string) (*v1.Pod, *v1.PersistentVolume, *v1.PersistentVolumeClaim) {
	pv, pvc, err := framework.CreatePVPVC(c, pvConfig, pvcConfig, ns, false)
	defer func() {
		if err != nil {
			framework.DeletePersistentVolumeClaim(c, pvc.Name, ns)
			framework.DeletePersistentVolume(c, pv.Name)
		}
	}()
	Expect(err).NotTo(HaveOccurred())
	pod := framework.MakePod(ns, []*v1.PersistentVolumeClaim{pvc}, true, "")
	pod.Spec.NodeName = nodeName
	framework.Logf("Creating NFS client pod.")
	pod, err = c.CoreV1().Pods(ns).Create(pod)
	framework.Logf("NFS client Pod %q created on Node %q", pod.Name, nodeName)
	Expect(err).NotTo(HaveOccurred())
	defer func() {
		if err != nil {
			framework.DeletePodWithWait(f, c, pod)
		}
	}()
	err = framework.WaitForPodRunningInNamespace(c, pod)
	Expect(err).NotTo(HaveOccurred(), fmt.Sprintf("Pod %q timed out waiting for phase: Running", pod.Name))
	// Return created api objects
	pod, err = c.CoreV1().Pods(ns).Get(pod.Name, metav1.GetOptions{})
	Expect(err).NotTo(HaveOccurred())
	pvc, err = c.CoreV1().PersistentVolumeClaims(ns).Get(pvc.Name, metav1.GetOptions{})
	Expect(err).NotTo(HaveOccurred())
	pv, err = c.CoreV1().PersistentVolumes().Get(pv.Name, metav1.GetOptions{})
	Expect(err).NotTo(HaveOccurred())
	return pod, pv, pvc
}

// tearDownTestCase destroy resources created by initTestCase.
func tearDownTestCase(c clientset.Interface, f *framework.Framework, ns string, client *v1.Pod, pvc *v1.PersistentVolumeClaim, pv *v1.PersistentVolume) {
	// Ignore deletion errors.  Failing on them will interrupt test cleanup.
	framework.DeletePodWithWait(f, c, client)
	framework.DeletePersistentVolumeClaim(c, pvc.Name, ns)
	framework.DeletePersistentVolume(c, pv.Name)
}

// kubeletCommand performs `start`, `restart`, or `stop` on the kubelet running on the node of the target pod and waits
// for the desired statues..
// - First issues the command via `systemctl`
// - If `systemctl` returns stderr "command not found, issues the command via `service`
// - If `service` also returns stderr "command not found", the test is aborted.
// Allowed kubeletOps are `kStart`, `kStop`, and `kRestart`
func kubeletCommand(kOp kubeletOpt, c clientset.Interface, pod *v1.Pod) {
	nodeIP, err := framework.GetHostExternalAddress(c, pod)
	Expect(err).NotTo(HaveOccurred())
	nodeIP = nodeIP + ":22"
	systemctlCmd := fmt.Sprintf("sudo systemctl %s kubelet", string(kOp))
	framework.Logf("Attempting `%s`", systemctlCmd)
	sshResult, err := framework.SSH(systemctlCmd, nodeIP, framework.TestContext.Provider)
	Expect(err).NotTo(HaveOccurred(), fmt.Sprintf("SSH to Node %q errored.", pod.Spec.NodeName))
	framework.LogSSHResult(sshResult)
	if strings.Contains(sshResult.Stderr, "command not found") {
		serviceCmd := fmt.Sprintf("sudo service kubelet %s", string(kOp))
		framework.Logf("Attempting `%s`", serviceCmd)
		sshResult, err = framework.SSH(serviceCmd, nodeIP, framework.TestContext.Provider)
		Expect(err).NotTo(HaveOccurred(), fmt.Sprintf("SSH to Node %q errored.", pod.Spec.NodeName))
		framework.LogSSHResult(sshResult)
	}
	Expect(sshResult.Code).To(BeZero(), "Failed to [%s] kubelet:\n%#v", string(kOp), sshResult)
	// On restart, waiting for node NotReady prevents a race condition where the node takes a few moments to leave the
	// Ready state which in turn short circuits WaitForNodeToBeReady()
	if kOp == kStop || kOp == kRestart {
		if ok := framework.WaitForNodeToBeNotReady(c, pod.Spec.NodeName, NodeStateTimeout); !ok {
			framework.Failf("Node %s failed to enter NotReady state", pod.Spec.NodeName)
		}
	}
	if kOp == kStart || kOp == kRestart {
		if ok := framework.WaitForNodeToBeReady(c, pod.Spec.NodeName, NodeStateTimeout); !ok {
			framework.Failf("Node %s failed to enter Ready state", pod.Spec.NodeName)
		}
	}
}

// podExec wraps RunKubectl to execute a bash cmd in target pod
func podExec(pod *v1.Pod, bashExec string) (string, error) {
	return framework.RunKubectl("exec", fmt.Sprintf("--namespace=%s", pod.Namespace), pod.Name, "--", "/bin/sh", "-c", bashExec)
}

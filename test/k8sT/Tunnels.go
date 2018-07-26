// Copyright 2017 Authors of Cilium
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

package k8sTest

import (
	"fmt"
	"time"

	. "github.com/cilium/cilium/test/ginkgo-ext"
	"github.com/cilium/cilium/test/helpers"

	. "github.com/onsi/gomega"
	"github.com/sirupsen/logrus"
)

var _ = Describe("K8sTunnelTest", func() {

	var kubectl *helpers.Kubectl
	var demoDSPath string

	BeforeAll(func() {
		kubectl = helpers.CreateKubectl(helpers.K8s1VMName(), logger)
		demoDSPath = helpers.ManifestGet("demo_ds.yaml")

		kubectl.Exec("kubectl -n kube-system delete ds cilium")

		waitToDeleteCilium(kubectl, logger)
	})

	BeforeEach(func() {
		kubectl.Apply(demoDSPath).ExpectSuccess("cannot install Demo application")
		kubectl.NodeCleanMetadata()
	})

	AfterEach(func() {
		kubectl.Delete(demoDSPath)
		ExpectAllPodsTerminated(kubectl)
	})

	AfterFailed(func() {
		kubectl.CiliumReport(helpers.KubeSystemNamespace,
			"cilium bpf tunnel list",
			"cilium endpoint list")
	})

	JustAfterEach(func() {
		kubectl.ValidateNoErrorsOnLogs(CurrentGinkgoTestDescription().Duration)
	})

	cleanService := func() {
		// To avoid hit GH-4384
		kubectl.DeleteResource("service", "test-nodeport testds-service").ExpectSuccess(
			"Service is deleted")
	}

	Context("VXLan", func() {
		AfterEach(func() {
			// Do not assert on success in AfterEach intentionally to avoid
			// incomplete teardown.
			_ = kubectl.DeleteResource(
				"ds", fmt.Sprintf("-n %s cilium", helpers.KubeSystemNamespace))
			waitToDeleteCilium(kubectl, logger)
		})

		It("Check VXLAN mode", func() {

			err := kubectl.CiliumInstall(helpers.CiliumDSPath)
			Expect(err).To(BeNil(), "Cilium cannot be installed")

			ExpectCiliumReady(kubectl)

			err = kubectl.WaitforPods(helpers.DefaultNamespace, "", 300)
			Expect(err).Should(BeNil(), "Pods are not ready after timeout")

			ciliumPod, err := kubectl.GetCiliumPodOnNode(helpers.KubeSystemNamespace, helpers.K8s1)
			Expect(err).Should(BeNil())

			By("Making sure all endpoints are in ready state")
			err = kubectl.CiliumEndpointWaitReady()
			Expect(err).To(BeNil(), "Endpoints are not ready after timeout")

			_, err = kubectl.CiliumNodesWait()
			Expect(err).Should(BeNil())

			By("Checking that BPF tunnels are in place")
			status := kubectl.CiliumExec(ciliumPod, "cilium bpf tunnel list | wc -l")
			status.ExpectSuccess()
			Expect(status.IntOutput()).Should(Equal(5))

			By("Checking that BPF tunnels are working correctly")
			tunnStatus := isNodeNetworkingWorking(kubectl, "zgroup=testDS")
			Expect(tunnStatus).Should(BeTrue())

			// FIXME GH-4456
			cleanService()
		}, 600)
	})

	Context("Geneve", func() {

		AfterEach(func() {
			// Do not assert on success in AfterEach intentionally to avoid
			// incomplete teardown.
			_ = kubectl.DeleteResource(
				"ds", fmt.Sprintf("-n %s cilium", helpers.KubeSystemNamespace))
			waitToDeleteCilium(kubectl, logger)
		})

		It("Check Geneve mode", func() {

			err := kubectl.CiliumInstall("cilium_ds_geneve.jsonnet")
			Expect(err).To(BeNil(), "Cilium cannot be installed")

			ExpectCiliumReady(kubectl)

			err = kubectl.WaitforPods(helpers.DefaultNamespace, "", 300)
			Expect(err).Should(BeNil(), "Pods are not ready after timeout")

			ciliumPod, err := kubectl.GetCiliumPodOnNode(helpers.KubeSystemNamespace, helpers.K8s1)
			Expect(err).Should(BeNil())

			_, err = kubectl.CiliumNodesWait()
			Expect(err).Should(BeNil())

			By("Making sure all endpoints are in ready state")
			err = kubectl.CiliumEndpointWaitReady()
			Expect(err).To(BeNil(), "Endpoints are not ready after timeout")

			//Check that cilium detects a
			By("Checking that BPF tunnels are in place")
			status := kubectl.CiliumExec(ciliumPod, "cilium bpf tunnel list | wc -l")
			status.ExpectSuccess()
			Expect(status.IntOutput()).Should(Equal(5))

			By("Checking that BPF tunnels are working correctly")
			tunnStatus := isNodeNetworkingWorking(kubectl, "zgroup=testDS")
			Expect(tunnStatus).Should(BeTrue())

			// FIXME GH-4456
			cleanService()
		}, 600)

	})

})

func isNodeNetworkingWorking(kubectl *helpers.Kubectl, filter string) bool {
	err := kubectl.WaitforPods(helpers.DefaultNamespace, fmt.Sprintf("-l %s", filter), 3000)
	Expect(err).Should(BeNil())
	pods, err := kubectl.GetPodNames(helpers.DefaultNamespace, filter)
	Expect(err).Should(BeNil())
	podIP, err := kubectl.Get(
		helpers.DefaultNamespace,
		fmt.Sprintf("pod %s -o json", pods[1])).Filter("{.status.podIP}")
	Expect(err).Should(BeNil())
	res := kubectl.ExecPodCmd(helpers.DefaultNamespace, pods[0], helpers.Ping(podIP.String()))
	return res.WasSuccessful()
}

func waitToDeleteCilium(kubectl *helpers.Kubectl, logger *logrus.Entry) {
	status := 1
	for status > 0 {
		pods, err := kubectl.GetCiliumPods(helpers.KubeSystemNamespace)
		status := len(pods)
		logger.Infof("Cilium pods terminating '%d' err='%v' pods='%v'", status, err, pods)
		if status == 0 {
			return
		}
		time.Sleep(1 * time.Second)
	}
}

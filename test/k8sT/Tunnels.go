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
	"sync"
	"time"

	. "github.com/cilium/cilium/test/ginkgo-ext"
	"github.com/cilium/cilium/test/helpers"

	. "github.com/onsi/gomega"
	"github.com/sirupsen/logrus"
)

var _ = Describe("K8sValidatedTunnelTest", func() {

	var kubectl *helpers.Kubectl
	var demoDSPath string
	var once sync.Once
	var logger *logrus.Entry

	initialize := func() {
		logger = log.WithFields(logrus.Fields{"testName": "K8sTunnelTest"})
		logger.Info("Starting")

		kubectl = helpers.CreateKubectl(helpers.K8s1VMName(), logger)
		demoDSPath = helpers.ManifestGet("demo_ds.yaml")
		kubectl.Exec("kubectl -n kube-system delete ds cilium")
		// Expect(res.Correct()).Should(BeTrue())

		waitToDeleteCilium(kubectl, logger)
	}

	BeforeEach(func() {
		once.Do(initialize)
		kubectl.NodeCleanMetadata()
		kubectl.Apply(demoDSPath)
	}, 600)

	AfterFailed(func() {
		kubectl.CiliumReport(helpers.KubeSystemNamespace,
			"cilium bpf tunnel list",
			"cilium endpoint list")
	})

	JustAfterEach(func() {
		kubectl.ValidateNoErrorsOnLogs(CurrentGinkgoTestDescription().Duration)
	})

	AfterEach(func() {
		kubectl.Delete(demoDSPath)
		ExpectAllPodsTerminated(kubectl)
	})

	Context("VXLan", func() {

		var (
			vxlanDSPath string
		)

		BeforeEach(func() {
			vxlanDSPath = helpers.ManifestGet("cilium_ds.yaml")
		})

		AfterEach(func() {
			// Do not assert on success in AfterEach intentionally to avoid
			// incomplete teardown.
			_ = kubectl.Delete(vxlanDSPath)
			waitToDeleteCilium(kubectl, logger)
		})

		It("Check VXLAN mode", func() {
			res := kubectl.Apply(vxlanDSPath)
			res.ExpectSuccess("Unable to apply %q", vxlanDSPath)

			ExpectCiliumReady(kubectl)

			ciliumPod, err := kubectl.GetCiliumPodOnNode(helpers.KubeSystemNamespace, helpers.K8s1)
			Expect(err).Should(BeNil())

			_, err = kubectl.CiliumNodesWait()
			Expect(err).Should(BeNil())

			By("Checking that BPF tunnels are in place")
			status := kubectl.CiliumExec(ciliumPod, "cilium bpf tunnel list | wc -l")
			status.ExpectSuccess()
			Expect(status.IntOutput()).Should(Equal(5))

			By("Checking that BPF tunnels are working correctly")
			tunnStatus := isNodeNetworkingWorking(kubectl, "zgroup=testDS")
			Expect(tunnStatus).Should(BeTrue())
		}, 600)
	})

	Context("Geneve", func() {

		var (
			geneveDSPath string
		)

		BeforeEach(func() {
			geneveDSPath = helpers.ManifestGet("cilium_ds_geneve.yaml")
		})

		AfterEach(func() {
			// Do not assert on success in AfterEach intentionally to avoid
			// incomplete teardown.
			_ = kubectl.Delete(geneveDSPath)
			waitToDeleteCilium(kubectl, logger)
		})

		It("Check Geneve mode", func() {
			res := kubectl.Apply(geneveDSPath)
			res.ExpectSuccess("unable to apply %s", geneveDSPath)
			ExpectCiliumReady(kubectl)

			ciliumPod, err := kubectl.GetCiliumPodOnNode(helpers.KubeSystemNamespace, helpers.K8s1)
			Expect(err).Should(BeNil())

			_, err = kubectl.CiliumNodesWait()
			Expect(err).Should(BeNil())

			//Check that cilium detects a
			By("Checking that BPF tunnels are in place")
			status := kubectl.CiliumExec(ciliumPod, "cilium bpf tunnel list | wc -l")
			status.ExpectSuccess()
			Expect(status.IntOutput()).Should(Equal(5))

			By("Checking that BPF tunnels are working correctly")
			tunnStatus := isNodeNetworkingWorking(kubectl, "zgroup=testDS")
			Expect(tunnStatus).Should(BeTrue())
			//FIXME: Maybe added here a cilium bpf tunnel status?
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

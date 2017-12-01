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

	"github.com/cilium/cilium/test/helpers"
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"

	"github.com/sirupsen/logrus"
)

var _ = Describe("K8sTunnelTest", func() {

	var kubectl *helpers.Kubectl
	var demoDSPath string
	var initialized bool
	var logger *logrus.Entry

	initialize := func() {
		if initialized == true {
			return
		}
		logger = log.WithFields(logrus.Fields{"testName": "K8sTunnelTest"})
		logger.Info("Starting")

		kubectl = helpers.CreateKubectl(helpers.K8s1VMName(), logger)
		demoDSPath = fmt.Sprintf("%s/demo_ds.yaml", kubectl.ManifestsPath())
		kubectl.Exec("kubectl -n kube-system delete ds cilium")
		// Expect(res.Correct()).Should(BeTrue())

		waitToDeleteCilium(kubectl, logger)
		initialized = true
	}

	BeforeEach(func() {
		initialize()
		kubectl.NodeCleanMetadata()
		kubectl.Apply(demoDSPath)
	}, 600)

	AfterEach(func() {
		kubectl.Delete(demoDSPath)
	})

	It("Check VXLAN mode", func() {
		path := fmt.Sprintf("%s/cilium_ds.yaml", kubectl.ManifestsPath())
		kubectl.Apply(path)
		_, err := kubectl.WaitforPods(helpers.KubeSystemNamespace, "-l k8s-app=cilium", 5000)
		Expect(err).Should(BeNil())

		ciliumPod, err := kubectl.GetCiliumPodOnNode(helpers.KubeSystemNamespace, helpers.K8s1)
		Expect(err).Should(BeNil())

		_, err = kubectl.CiliumNodesWait()
		Expect(err).Should(BeNil())
		//Make sure that we delete the ds in case of fail
		defer kubectl.Delete(path)

		By("Checking that BPF tunnels are in place")
		status := kubectl.CiliumExec(ciliumPod, "cilium bpf tunnel list | wc -l")
		if tunnels, _ := status.IntOutput(); tunnels != 4 {
			cmds := []string{
				"cilium bpf tunnel list",
			}
			kubectl.CiliumReport(helpers.KubeSystemNamespace, ciliumPod, cmds)
		}

		status.ExpectSuccess()
		Expect(status.IntOutput()).Should(Equal(4))

		By("Checking that BPF tunnels are working correctly")
		tunnStatus := isNodeNetworkingWorking(kubectl, "zgroup=testDS")
		Expect(tunnStatus).Should(BeTrue())
		kubectl.Delete(path)
		waitToDeleteCilium(kubectl, logger)
	}, 600)

	It("Check Geneve mode", func() {
		path := fmt.Sprintf("%s/cilium_ds_geneve.yaml", kubectl.ManifestsPath())
		kubectl.Apply(path)
		_, err := kubectl.WaitforPods(helpers.KubeSystemNamespace, "-l k8s-app=cilium", 5000)
		Expect(err).Should(BeNil())

		ciliumPod, err := kubectl.GetCiliumPodOnNode(helpers.KubeSystemNamespace, helpers.K8s1)
		Expect(err).Should(BeNil())

		_, err = kubectl.CiliumNodesWait()
		Expect(err).Should(BeNil())

		//Make sure that we delete the ds in case of fail
		defer kubectl.Delete(path)

		//Check that cilium detects a
		By("Checking that BPF tunnels are in place")
		status := kubectl.CiliumExec(ciliumPod, "cilium bpf tunnel list | wc -l")
		status.ExpectSuccess()
		if tunnels, _ := status.IntOutput(); tunnels != 4 {
			cmds := []string{
				"cilium bpf tunnel list",
			}
			kubectl.CiliumReport(helpers.KubeSystemNamespace, ciliumPod, cmds)
		}
		Expect(status.IntOutput()).Should(Equal(4))

		By("Checking that BPF tunnels are working correctly")
		tunnStatus := isNodeNetworkingWorking(kubectl, "zgroup=testDS")
		Expect(tunnStatus).Should(BeTrue())
		//FIXME: Maybe added here a cilium bpf tunnel status?
		kubectl.Delete(path)
		waitToDeleteCilium(kubectl, logger)
	}, 600)
})

func isNodeNetworkingWorking(kubectl *helpers.Kubectl, filter string) bool {
	waitReady, _ := kubectl.WaitforPods(helpers.DefaultNamespace, fmt.Sprintf("-l %s", filter), 3000)
	Expect(waitReady).Should(BeTrue())
	pods, err := kubectl.GetPodNames(helpers.DefaultNamespace, filter)
	Expect(err).Should(BeNil())
	podIP, err := kubectl.Get(
		helpers.DefaultNamespace,
		fmt.Sprintf("pod %s -o json", pods[1])).Filter("{.status.podIP}")
	Expect(err).Should(BeNil())
	_, err = kubectl.ExecPodCmd(helpers.DefaultNamespace, pods[0], helpers.Ping(podIP.String()))
	if err != nil {
		return false
	}
	return true
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

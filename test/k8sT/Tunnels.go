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

	log "github.com/sirupsen/logrus"
)

var _ = Describe("K8sTunnelTest", func() {

	var kubectl *helpers.Kubectl
	var demoDSPath string
	var logger *log.Entry
	var initialized bool

	initialize := func() {
		if initialized == true {
			return
		}
		logger = log.WithFields(log.Fields{"testName": "K8sTunnelTest"})
		logger.Info("Starting")

		kubectl = helpers.CreateKubectl("k8s1", logger)
		demoDSPath = fmt.Sprintf("%s/demo_ds.yaml", kubectl.ManifestsPath())
		kubectl.Node.Exec("kubectl -n kube-system delete ds cilium")
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
		_, err := kubectl.WaitforPods("kube-system", "-l k8s-app=cilium", 5000)
		Expect(err).Should(BeNil())

		ciliumPod, err := kubectl.GetCiliumPodOnNode("kube-system", "k8s1")
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
			kubectl.CiliumReport("kube-system", ciliumPod, cmds)
		}

		Expect(status.WasSuccessful()).Should(BeTrue())
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
		_, err := kubectl.WaitforPods("kube-system", "-l k8s-app=cilium", 5000)
		Expect(err).Should(BeNil())

		ciliumPod, err := kubectl.GetCiliumPodOnNode("kube-system", "k8s1")
		Expect(err).Should(BeNil())

		_, err = kubectl.CiliumNodesWait()
		Expect(err).Should(BeNil())

		//Make sure that we delete the ds in case of fail
		defer kubectl.Delete(path)

		//Check that cilium detects a
		By("Checking that BPF tunnels are in place")
		status := kubectl.CiliumExec(ciliumPod, "cilium bpf tunnel list | wc -l")
		Expect(status.WasSuccessful()).Should(BeTrue())
		if tunnels, _ := status.IntOutput(); tunnels != 4 {
			cmds := []string{
				"cilium bpf tunnel list",
			}
			kubectl.CiliumReport("kube-system", ciliumPod, cmds)
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
	waitReady, _ := kubectl.WaitforPods("default", fmt.Sprintf("-l %s", filter), 3000)
	Expect(waitReady).Should(BeTrue())
	pods, err := kubectl.GetPodNames("default", filter)
	Expect(err).Should(BeNil())
	podIP, err := kubectl.Get(
		"default",
		fmt.Sprintf("pod %s -o json", pods[1])).Filter("{.status.podIP}")
	Expect(err).Should(BeNil())
	_, err = kubectl.Exec("default", pods[0], fmt.Sprintf("ping -c 1 %s", podIP))
	if err != nil {
		return false
	}
	return true
}

func waitToDeleteCilium(kubectl *helpers.Kubectl, logger *log.Entry) {
	status := 1
	for status > 0 {
		pods, err := kubectl.GetCiliumPods("kube-system")
		status := len(pods)
		logger.Infof("Cilium pods termintating '%d' err='%v' pods='%v'", status, err, pods)
		if status == 0 {
			return
		}
		time.Sleep(1 * time.Second)
	}
}

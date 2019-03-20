// Copyright 2017-2019 Authors of Cilium
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

var _ = Describe("K8sDatapathConfig", func() {

	var kubectl *helpers.Kubectl
	var demoDSPath string
	var ipsecKeysPath string

	BeforeAll(func() {
		kubectl = helpers.CreateKubectl(helpers.K8s1VMName(), logger)
		demoDSPath = helpers.ManifestGet("demo_ds.yaml")
		ipsecKeysPath = helpers.ManifestGet("ipsec_keys.yaml")

		kubectl.Exec("kubectl -n kube-system delete ds cilium")

		waitToDeleteCilium(kubectl, logger)
	})

	BeforeEach(func() {
		kubectl.Apply(demoDSPath).ExpectSuccess("cannot install Demo application")
		kubectl.Apply(ipsecKeysPath).ExpectSuccess("cannot install IPsec keys")
		kubectl.NodeCleanMetadata()
	})

	AfterEach(func() {
		kubectl.Delete(demoDSPath)
		kubectl.Delete(ipsecKeysPath)
		ExpectAllPodsTerminated(kubectl)

		// Do not assert on success in AfterEach intentionally to avoid
		// incomplete teardown.
		_ = kubectl.DeleteResource(
			"ds", fmt.Sprintf("-n %s cilium", helpers.KubeSystemNamespace))
		waitToDeleteCilium(kubectl, logger)
	})

	AfterFailed(func() {
		kubectl.CiliumReport(helpers.KubeSystemNamespace,
			"cilium bpf tunnel list",
			"cilium endpoint list")
	})

	JustAfterEach(func() {
		kubectl.ValidateNoErrorsInLogs(CurrentGinkgoTestDescription().Duration)
	})

	cleanService := func() {
		// To avoid hit GH-4384
		kubectl.DeleteResource("service", "test-nodeport testds-service").ExpectSuccess(
			"Service is deleted")
	}

	deployCilium := func(ciliumDaemonSetPatchFile string) {
		_ = kubectl.Apply(helpers.DNSDeployment())

		err := kubectl.DeployETCDOperator()
		ExpectWithOffset(1, err).To(BeNil(), "Unable to deploy etcd operator")

		err = kubectl.CiliumInstall(ciliumDaemonSetPatchFile, helpers.CiliumConfigMapPatch)
		ExpectWithOffset(1, err).To(BeNil(), "Unable to install Cilium")

		ExpectCiliumReady(kubectl)
		ExpectETCDOperatorReady(kubectl)

		err = kubectl.WaitforPods(helpers.DefaultNamespace, "", helpers.HelperTimeout)
		ExpectWithOffset(1, err).Should(BeNil(), "Pods are not ready after timeout")

		_, err = kubectl.CiliumNodesWait()
		ExpectWithOffset(1, err).Should(BeNil(), "Failure while waiting for k8s nodes to be annotated by Cilium")

		By("Making sure all endpoints are in ready state")
		err = kubectl.CiliumEndpointWaitReady()
		ExpectWithOffset(1, err).To(BeNil(), "Failure while waiting for all cilium endpoints to reach ready state")
	}

	Context("Encapsulation", func() {
		validateBPFTunnelMap := func() {
			By("Checking that BPF tunnels are in place")
			ciliumPod, err := kubectl.GetCiliumPodOnNode(helpers.KubeSystemNamespace, helpers.K8s1)
			ExpectWithOffset(1, err).Should(BeNil(), "Unable to determine cilium pod on node %s", helpers.K8s1)
			status := kubectl.CiliumExec(ciliumPod, "cilium bpf tunnel list | wc -l")
			status.ExpectSuccess()
			Expect(status.IntOutput()).Should(Equal(3), "Did not find expected number of entries in BPF tunnel map")
		}

		It("Check connectivity with transparent encryption and VXLAN encapsulation", func() {
			SkipIfFlannel()
			deployCilium("cilium-ds-patch-vxlan-ipsec.yaml")
			validateBPFTunnelMap()
			Expect(testPodConnectivityAcrossNodes(kubectl)).Should(BeTrue(), "Connectivity test with IPsec between nodes failed")
			cleanService()
		}, 600)

		It("Check connectivity with VXLAN encapsulation", func() {
			SkipIfFlannel()

			deployCilium("cilium-ds-patch-vxlan.yaml")
			validateBPFTunnelMap()
			Expect(testPodConnectivityAcrossNodes(kubectl)).Should(BeTrue(), "Connectivity test between nodes failed")
			cleanService()
		}, 600)

		It("Check connectivity with Geneve encapsulation", func() {
			SkipIfFlannel()

			deployCilium("cilium-ds-patch-geneve.yaml")
			validateBPFTunnelMap()
			Expect(testPodConnectivityAcrossNodes(kubectl)).Should(BeTrue(), "Connectivity test between nodes failed")
			cleanService()
		})
	})

	Context("DirectRouting", func() {
		It("Check connectivity with automatic direct nodes routes", func() {
			SkipIfFlannel()

			deployCilium("cilium-ds-patch-auto-node-routes.yaml")
			Expect(testPodConnectivityAcrossNodes(kubectl)).Should(BeTrue(), "Connectivity test between nodes failed")
			cleanService()
		})
	})

	Context("Transparent encryption with IPv4Only", func() {
		It("Check connectivity with transparent encryption enabled and IPv6 disabled", func() {
			SkipIfFlannel()
			deployCilium("cilium-ds-patch-ipv4-only-ipsec.yaml")
			Expect(testPodConnectivityAcrossNodes(kubectl)).Should(BeTrue(), "Connectivity test between nodes failed")
			cleanService()
		})
	})

	Context("IPv4Only", func() {
		It("Check connectivity with IPv6 disabled", func() {
			deployCilium("cilium-ds-patch-ipv4-only.yaml")
			Expect(testPodConnectivityAcrossNodes(kubectl)).Should(BeTrue(), "Connectivity test between nodes failed")
			cleanService()
		})
	})
})

func testPodConnectivityAcrossNodes(kubectl *helpers.Kubectl) bool {
	By("Checking pod connectivity between nodes")

	filter := "zgroup=testDS"

	err := kubectl.WaitforPods(helpers.DefaultNamespace, fmt.Sprintf("-l %s", filter), helpers.HelperTimeout)
	ExpectWithOffset(1, err).Should(BeNil(), "Failure while waiting for connectivity test pods to start")
	pods, err := kubectl.GetPodNames(helpers.DefaultNamespace, filter)
	Expect(err).Should(BeNil(), "Failure while retrieving pod name for %s", filter)
	podIP, err := kubectl.Get(
		helpers.DefaultNamespace,
		fmt.Sprintf("pod %s -o json", pods[1])).Filter("{.status.podIP}")
	Expect(err).Should(BeNil(), "Failure to retrieve IP of pod %s", pods[1])
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

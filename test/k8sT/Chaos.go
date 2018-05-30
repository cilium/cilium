// Copyright 2017-2018 Authors of Cilium
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

	. "github.com/cilium/cilium/test/ginkgo-ext"
	"github.com/cilium/cilium/test/helpers"

	. "github.com/onsi/gomega"
	"github.com/sirupsen/logrus"
)

var _ = Describe("K8sValidatedChaosTest", func() {

	var (
		kubectl       *helpers.Kubectl
		logger        = log.WithFields(logrus.Fields{"testName": "K8sChaosTest"})
		demoDSPath    = helpers.ManifestGet("demo_ds.yaml")
		testDSService = "testds-service.default.svc.cluster.local"
	)

	BeforeAll(func() {
		logger.Info("Starting")
		kubectl = helpers.CreateKubectl(helpers.K8s1VMName(), logger)

		err := kubectl.CiliumInstall(helpers.CiliumDSPath)
		Expect(err).To(BeNil(), "Cilium cannot be installed")

		ExpectCiliumReady(kubectl)
		ExpectKubeDNSReady(kubectl)
	})

	BeforeEach(func() {
		kubectl.Apply(demoDSPath).ExpectSuccess("DS deployment cannot be applied")

		err := kubectl.WaitforPods(
			helpers.DefaultNamespace, fmt.Sprintf("-l zgroup=testDS"), 300)
		Expect(err).Should(BeNil(), "Pods are not ready after timeout")
	})

	AfterFailed(func() {
		kubectl.CiliumReport(helpers.KubeSystemNamespace,
			"cilium service list",
			"cilium endpoint list")
	})

	JustAfterEach(func() {
		kubectl.ValidateNoErrorsOnLogs(CurrentGinkgoTestDescription().Duration)
	})

	AfterEach(func() {
		kubectl.Delete(demoDSPath).ExpectSuccess(
			"%s deployment cannot be deleted", demoDSPath)
		ExpectAllPodsTerminated(kubectl)

	})

	PingService := func() {
		pods, err := kubectl.GetPodNames(helpers.DefaultNamespace, "zgroup=testDSClient")
		Expect(err).To(BeNil(), "Cannot get pods names")
		Expect(len(pods)).To(BeNumerically(">", 0), "No pods available to test connectivity")

		dsPods, err := kubectl.GetPodsIPs(helpers.DefaultNamespace, "zgroup=testDS")
		Expect(err).To(BeNil(), "Cannot get daemonset pods IPS")
		Expect(len(pods)).To(BeNumerically(">", 0), "No pods available to test connectivity")

		for _, pod := range pods {
			for _, ip := range dsPods {
				res := kubectl.ExecPodCmd(
					helpers.DefaultNamespace, pod, helpers.Ping(ip))
				log.Debugf("Pod %s ping %v", pod, ip)
				ExpectWithOffset(1, res).To(helpers.CMDSuccess(),
					"Cannot ping from %q to %q", pod, ip)

				err = kubectl.WaitForKubeDNSEntry(testDSService)
				ExpectWithOffset(1, err).To(BeNil(), "DNS entry is not ready after timeout")

				res = kubectl.ExecPodCmd(
					helpers.DefaultNamespace, pod, helpers.CurlFail("http://%s:80/", testDSService))
				ExpectWithOffset(1, res).To(helpers.CMDSuccess(),
					"Cannot curl from %q to testds-service", pod)
			}
		}
	}

	It("Endpoint can still connect while Cilium is not running", func() {
		err := kubectl.WaitforPods(
			helpers.DefaultNamespace,
			fmt.Sprintf("-l zgroup=testDSClient"), 300)
		Expect(err).Should(BeNil(), "Pods are not ready after timeout")

		PingService()

		By("Deleting cilium pods")
		res := kubectl.Exec(fmt.Sprintf("%s -n %s delete pods -l k8s-app=cilium",
			helpers.KubectlCmd, helpers.KubeSystemNamespace))
		res.ExpectSuccess()

		ExpectCiliumReady(kubectl)

		PingService()

		By("Uninstall cilium pods")

		res = kubectl.DeleteResource(
			"ds", fmt.Sprintf("-n %s cilium", helpers.KubeSystemNamespace))
		res.ExpectSuccess("Cilium DS cannot be deleted")

		ExpectAllPodsTerminated(kubectl)

		PingService()

		By("Install cilium pods")

		err = kubectl.CiliumInstall(helpers.CiliumDSPath)
		Expect(err).To(BeNil(), "Cilium cannot be installed")

		ExpectCiliumReady(kubectl)

		PingService()
	})
})

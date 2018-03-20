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
	"sync"

	"github.com/cilium/cilium/test/helpers"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	"github.com/sirupsen/logrus"
)

var _ = Describe("K8sValidatedChaosTest", func() {

	var kubectl *helpers.Kubectl
	var logger *logrus.Entry
	var once sync.Once
	var demoDSPath string
	var ciliumPath string

	initialize := func() {
		logger = log.WithFields(logrus.Fields{"testName": "K8sChaosTest"})
		logger.Info("Starting")

		kubectl = helpers.CreateKubectl(helpers.K8s1VMName(), logger)

		ciliumPath = kubectl.ManifestGet("cilium_ds.yaml")
		kubectl.Apply(ciliumPath)

		_, err := kubectl.WaitforPods(helpers.KubeSystemNamespace, "-l k8s-app=cilium", 600)
		Expect(err).Should(BeNil())

		err = kubectl.WaitKubeDNS()
		Expect(err).Should(BeNil())

		demoDSPath = kubectl.ManifestGet("demo_ds.yaml")
	}

	BeforeEach(func() {
		once.Do(initialize)
		kubectl.Apply(demoDSPath).ExpectSuccess("DS deployment cannot be applied")

		_, err := kubectl.WaitforPods(
			helpers.DefaultNamespace, fmt.Sprintf("-l zgroup=testDS"), 300)
		Expect(err).Should(BeNil(), "Pods are not ready after timeout")
	})

	AfterEach(func() {
		kubectl.ValidateNoErrorsOnLogs(CurrentGinkgoTestDescription().Duration)
		if CurrentGinkgoTestDescription().Failed {
			ciliumPod, _ := kubectl.GetCiliumPodOnNode(
				helpers.KubeSystemNamespace, helpers.K8s1VMName())
			kubectl.CiliumReport("kube-system", ciliumPod, []string{
				"cilium service list",
				"cilium endpoint list"})
		}

		kubectl.Delete(demoDSPath).ExpectSuccess(
			"%s deployment cannot be deleted", demoDSPath)
		err := kubectl.WaitCleanAllTerminatingPods()
		Expect(err).To(BeNil(), "Terminating containers are not deleted after timeout")

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
				ExpectWithOffset(1, res.WasSuccessful()).To(BeTrue(),
					"Cannot ping from %q to %q", pod, ip)

				res = kubectl.ExecPodCmd(
					helpers.DefaultNamespace, pod, helpers.CurlFail("http://testds-service:80/"))
				ExpectWithOffset(1, res.WasSuccessful()).To(BeTrue(),
					"Cannot curl from %q to testds-service", pod)
			}
		}
	}

	It("Endpoint can still connect while Cilium is not running", func() {
		_, err := kubectl.WaitforPods(
			helpers.DefaultNamespace,
			fmt.Sprintf("-l zgroup=testDSClient"), 300)
		Expect(err).Should(BeNil(), "Pods are not ready after timeout")

		PingService()

		By("Deleting cilium pods")
		res := kubectl.Exec(fmt.Sprintf("%s -n %s delete pods -l k8s-app=cilium",
			helpers.KubectlCmd, helpers.KubeSystemNamespace))
		res.ExpectSuccess()

		_, err = kubectl.WaitforPods(helpers.KubeSystemNamespace, "-l k8s-app=cilium", 600)
		Expect(err).Should(BeNil(), "Cilium is not ready after deleting some pods")

		PingService()

		By("Uninstall cilium pods")
		res = kubectl.Delete(ciliumPath)
		res.ExpectSuccess(res.GetDebugMessage())

		err = kubectl.WaitCleanAllTerminatingPods()
		Expect(err).To(BeNil(), "Terminating containers are not deleted after timeout")

		PingService()

		By("Install cilium pods")
		res = kubectl.Apply(ciliumPath)
		res.ExpectSuccess(res.GetDebugMessage())

		_, err = kubectl.WaitforPods(helpers.KubeSystemNamespace, "-l k8s-app=cilium", 600)
		Expect(err).Should(BeNil(), "Cilium is not ready after deleting some pods")

		PingService()
	})
})

// Copyright 2020 Authors of Cilium
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
	"context"
	"fmt"

	. "github.com/cilium/cilium/test/ginkgo-ext"
	"github.com/cilium/cilium/test/helpers"

	. "github.com/onsi/gomega"
)

var _ = Describe("K8sBandwidthTest", func() {
	const (
		testDS10   = "run=netperf-10"
		testDS25   = "run=netperf-25"
		testDS50   = "run=netperf-50"
		testDSInf  = "run=netperf-inf"
		testClient = "run=netperf-client"
	)

	var (
		kubectl        *helpers.Kubectl
		ciliumFilename string

		backgroundCancel       context.CancelFunc = func() {}
		backgroundError        error
		enableBackgroundReport = true
	)

	BeforeAll(func() {
		kubectl = helpers.CreateKubectl(helpers.K8s1VMName(), logger)

		ciliumFilename = helpers.TimestampFilename("cilium.yaml")
		DeployCiliumAndDNS(kubectl, ciliumFilename)
	})

	AfterFailed(func() {
		kubectl.CiliumReport(helpers.CiliumNamespace,
			"cilium bpf bandwidth list",
			"cilium endpoint list")
	})

	JustBeforeEach(func() {
		if enableBackgroundReport {
			backgroundCancel, backgroundError = kubectl.BackgroundReport("uptime")
			Expect(backgroundError).To(BeNil(), "Cannot start background report process")
		}
	})

	JustAfterEach(func() {
		kubectl.ValidateNoErrorsInLogs(CurrentGinkgoTestDescription().Duration)
		backgroundCancel()
	})

	AfterEach(func() {
		ExpectAllPodsTerminated(kubectl)
	})

	AfterAll(func() {
		kubectl.CloseSSHClient()
	})

	Context("Checks Bandwidth Rate-Limiting", func() {
		var demoYAML string

		BeforeAll(func() {
			demoYAML = helpers.ManifestGet(kubectl.BasePath(), "demo_bw.yaml")

			res := kubectl.ApplyDefault(demoYAML)
			res.ExpectSuccess("unable to apply %s", demoYAML)

			podLabels := []string{
				testDS10,
				testDS25,
				testDS50,
				testDSInf,
				testClient,
			}
			for _, label := range podLabels {
				err := kubectl.WaitforPods(helpers.DefaultNamespace,
					fmt.Sprintf("-l %s", label), helpers.HelperTimeout)
				Expect(err).Should(BeNil())
			}
		})

		AfterAll(func() {
			_ = kubectl.Delete(demoYAML)
		})

		testNetperfFromPods := func(clientPodLabel, targetIP string) {
			pods, err := kubectl.GetPodNames(helpers.DefaultNamespace, clientPodLabel)
			ExpectWithOffset(1, err).Should(BeNil(), "cannot retrieve pod names by filter %q",
				clientPodLabel)
			cmd := helpers.Netperf(targetIP, helpers.TCP_MAERTS, "-l 30 -I 99,5")
			for _, pod := range pods {
				By("Making netperf request from %s pod to pod with IP %s", pod, targetIP)
				res := kubectl.ExecPodCmd(helpers.DefaultNamespace, pod, cmd)
				ExpectWithOffset(1, res).Should(helpers.CMDSuccess(),
					"Request from %s pod to pod with IP %s failed", pod, targetIP)
			}
		}

		SkipItIf(helpers.RunsWithKubeProxy, "Checks Pod to Pod bandwidth", func() {
			podLabels := []string{
				testDS10,
				testDS25,
				testDS50,
				testDSInf,
			}
			for _, label := range podLabels {
				podIPs, err := kubectl.GetPodsIPs(helpers.DefaultNamespace, label)
				ExpectWithOffset(1, err).Should(BeNil(), "Cannot retrieve pod IPs for %s",
					label)
				Expect(len(podIPs)).To(Equal(int(1)), "Expected pod IPs mismatch")
				for _, podIP := range podIPs {
					testNetperfFromPods(testClient, podIP)
				}
			}
		})
	})
})

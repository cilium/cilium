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
	var (
		kubectl        *helpers.Kubectl
		ciliumFilename string
		demoYAML       string
	)

	BeforeAll(func() {
		kubectl = helpers.CreateKubectl(helpers.K8s1VMName(), logger)

		ciliumFilename = helpers.TimestampFilename("cilium.yaml")

		demoYAML = helpers.ManifestGet(kubectl.BasePath(), "demo_bw.yaml")
		res := kubectl.ApplyDefault(demoYAML)
		res.ExpectSuccess("Unable to apply %s", demoYAML)
	})

	AfterAll(func() {
		_ = kubectl.Delete(demoYAML)
		ExpectAllPodsTerminated(kubectl)
		kubectl.CloseSSHClient()
	})

	SkipContextIf(helpers.DoesNotRunOnNetNextKernel, "Checks Bandwidth Rate-Limiting", func() {
		const (
			testDS10       = "run=netperf-10"
			testDS25       = "run=netperf-25"
			testClientPod  = "run=netperf-client-pod"
			testClientHost = "run=netperf-client-host"

			maxRateDeviation = 5
			minBandwidth     = 1
		)

		var (
			backgroundCancel       context.CancelFunc = func() {}
			backgroundError        error
			enableBackgroundReport = true

			podLabels = []string{
				testDS10,
				testDS25,
			}
		)

		AfterFailed(func() {
			kubectl.CiliumReport("cilium bpf bandwidth list", "cilium endpoint list")
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

		AfterAll(func() {
			UninstallCiliumFromManifest(kubectl, ciliumFilename)
		})

		waitForTestPods := func() {
			podLabels := []string{
				testDS10,
				testDS25,
				testClientPod,
				testClientHost,
			}
			for _, label := range podLabels {
				err := kubectl.WaitforPods(helpers.DefaultNamespace,
					fmt.Sprintf("-l %s", label), helpers.HelperTimeout)
				Expect(err).Should(BeNil())
			}
		}

		testNetperfFromPods := func(clientPodLabel, targetIP string, maxSessions, rate int) {
			pods, err := kubectl.GetPodNames(helpers.DefaultNamespace, clientPodLabel)
			ExpectWithOffset(1, err).Should(BeNil(), "cannot retrieve pod names by filter %q",
				clientPodLabel)
			for i := 1; i <= maxSessions; i++ {
				cmd := helpers.SuperNetperf(i, targetIP, helpers.TCP_MAERTS, "")
				for _, pod := range pods {
					By("Running %d netperf session from %s pod to pod with IP %s (expected rate: %d)",
						i, pod, targetIP, rate)
					res := kubectl.ExecPodCmd(helpers.DefaultNamespace, pod, cmd)
					ExpectWithOffset(1, res).Should(helpers.CMDSuccess(),
						"Request from %s pod to pod with IP %s failed", pod, targetIP)
					By("Session test completed, netperf result raw: %s", res.SingleOut())
					if rate > 0 {
						ExpectWithOffset(1, res.InRange(minBandwidth, rate+maxRateDeviation)).To(BeNil(),
							"Rate mismatch")
					}
				}
			}
		}

		testNetperf := func(podLabels []string, fromLabel string) {
			for _, label := range podLabels {
				podIPs, err := kubectl.GetPodsIPs(helpers.DefaultNamespace, label)
				ExpectWithOffset(1, err).Should(BeNil(), "Cannot retrieve pod IPs for %s", label)
				ExpectWithOffset(1, len(podIPs)).To(Equal(int(1)), "Expected pod IPs mismatch")
				rate := 0
				fmt.Sscanf(label, "run=netperf-%d", &rate)
				for _, podIP := range podIPs {
					testNetperfFromPods(fromLabel, podIP, 1, rate)
				}
			}
		}

		It("Checks Pod to Pod bandwidth, vxlan tunneling", func() {
			DeployCiliumOptionsAndDNS(kubectl, ciliumFilename, map[string]string{
				"bandwidthManager": "true",
				"tunnel":           "vxlan",
			})
			waitForTestPods()
			testNetperf(podLabels, testClientPod)
			testNetperf(podLabels, testClientHost)
		})
		It("Checks Pod to Pod bandwidth, geneve tunneling", func() {
			DeployCiliumOptionsAndDNS(kubectl, ciliumFilename, map[string]string{
				"bandwidthManager": "true",
				"tunnel":           "geneve",
			})
			waitForTestPods()
			testNetperf(podLabels, testClientPod)
			testNetperf(podLabels, testClientHost)
		})
		It("Checks Pod to Pod bandwidth, direct routing", func() {
			DeployCiliumOptionsAndDNS(kubectl, ciliumFilename, map[string]string{
				"bandwidthManager":     "true",
				"tunnel":               "disabled",
				"autoDirectNodeRoutes": "true",
			})
			waitForTestPods()
			testNetperf(podLabels, testClientPod)
			testNetperf(podLabels, testClientHost)
		})
	})
})

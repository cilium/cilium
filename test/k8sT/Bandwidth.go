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

		maxRateDeviation = 10
	)

	var (
		kubectl        *helpers.Kubectl
		ciliumFilename string
		k8s2NodeName   string

		backgroundCancel       context.CancelFunc = func() {}
		backgroundError        error
		enableBackgroundReport = true

		podLabels = []string{
			testDS10,
			testDS25,
		}
	)

	BeforeAll(func() {
		kubectl = helpers.CreateKubectl(helpers.K8s1VMName(), logger)
		k8s2NodeName, _ = kubectl.GetNodeInfo(helpers.K8s2)

		ciliumFilename = helpers.TimestampFilename("cilium.yaml")
		DeployCiliumAndDNS(kubectl, ciliumFilename)

		ExpectWithOffset(1, "xxxx").To(Equal("yyyy"))
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
		UninstallCiliumFromManifest(kubectl, ciliumFilename)
		kubectl.CloseSSHClient()
	})

	SkipContextIf(func() bool {
		return !helpers.RunsOnNetNextKernel()
	}, "Checks Bandwidth Rate-Limiting", func() {
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
						ExpectWithOffset(1, res.InRange(rate, maxRateDeviation)).To(BeNil(),
							"Rate mismatch")
					}
				}
			}
		}

		testNetperfFromHost := func(nodeName, targetIP string, maxSessions, rate int) {
			for i := 1; i <= maxSessions; i++ {
				cmd := helpers.SuperNetperf(i, targetIP, helpers.TCP_MAERTS, "")
				By("Running %d netperf session from %s host to pod with IP %s (expected rate: %d)",
					i, nodeName, targetIP, rate)
				res := kubectl.ExecInHostNetNS(context.TODO(), nodeName, cmd)
				ExpectWithOffset(1, res).Should(helpers.CMDSuccess(),
					"Request from %s host to pod with IP %s failed", nodeName, targetIP)
				By("Session test completed, netperf result raw: %s", res.SingleOut())
				if rate > 0 {
					ExpectWithOffset(1, res.InRange(rate, maxRateDeviation)).To(BeNil(),
						"Rate mismatch")
				}
			}
		}

		testNetperf := func(podLabels []string, fromHost bool) {
			for _, label := range podLabels {
				podIPs, err := kubectl.GetPodsIPs(helpers.DefaultNamespace, label)
				ExpectWithOffset(1, err).Should(BeNil(), "Cannot retrieve pod IPs for %s", label)
				ExpectWithOffset(1, len(podIPs)).To(Equal(int(1)), "Expected pod IPs mismatch")
				rate := 0
				fmt.Sscanf(label, "run=netperf-%d", &rate)
				for _, podIP := range podIPs {
					if fromHost {
						testNetperfFromHost(k8s2NodeName, podIP, 1, rate)
					} else {
						testNetperfFromPods(testClient, podIP, 1, rate)
					}
				}
			}
		}

		It("Checks Pod to Pod bandwidth, vxlan tunneling", func() {
			DeployCiliumOptionsAndDNS(kubectl, ciliumFilename, map[string]string{
				"global.tunnel": "vxlan",
			})
			// TODO: super_netperf from host ns
			testNetperf(podLabels, false)
		})
		It("Checks Pod to Pod bandwidth, geneve tunneling", func() {
			DeployCiliumOptionsAndDNS(kubectl, ciliumFilename, map[string]string{
				"global.tunnel": "geneve",
			})
			testNetperf(podLabels, false)
		})
		It("Checks Pod to Pod bandwidth, direct routing", func() {
			DeployCiliumOptionsAndDNS(kubectl, ciliumFilename, map[string]string{
				"global.tunnel":               "disabled",
				"global.autoDirectNodeRoutes": "true",
			})
			testNetperf(podLabels, false)
		})
	})
})

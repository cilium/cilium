// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package k8sTest

import (
	"fmt"

	. "github.com/onsi/gomega"

	. "github.com/cilium/cilium/test/ginkgo-ext"
	"github.com/cilium/cilium/test/helpers"
)

var _ = SkipDescribeIf(helpers.DoesNotRunOnNetNextKernel, "K8sDatapathBandwidthTest", func() {
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
		kubectl.Delete(demoYAML)
		ExpectAllPodsTerminated(kubectl)

		UninstallCiliumFromManifest(kubectl, ciliumFilename)
		ExpectAllPodsTerminated(kubectl)

		kubectl.CloseSSHClient()
	})

	Context("Checks Bandwidth Rate-Limiting", func() {
		const (
			testDS10       = "run=netperf-10"
			testDS25       = "run=netperf-25"
			testClientPod  = "run=netperf-client-pod"
			testClientHost = "run=netperf-client-host"

			maxRateDeviation = 5
			minBandwidth     = 1
		)

		var (
			podLabels = []string{
				testDS10,
				testDS25,
			}
		)

		AfterFailed(func() {
			kubectl.CiliumReport("cilium bpf bandwidth list", "cilium endpoint list")
		})

		JustAfterEach(func() {
			kubectl.ValidateNoErrorsInLogs(CurrentGinkgoTestDescription().Duration)
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
				"bandwidthManager.enabled": "true",
				"tunnelProtocol":           "vxlan",
			})
			waitForTestPods()
			testNetperf(podLabels, testClientPod)
			testNetperf(podLabels, testClientHost)
		})
		It("Checks Pod to Pod bandwidth, geneve tunneling", func() {
			DeployCiliumOptionsAndDNS(kubectl, ciliumFilename, map[string]string{
				"bandwidthManager.enabled": "true",
				"tunnelProtocol":           "geneve",
			})
			waitForTestPods()
			testNetperf(podLabels, testClientPod)
			testNetperf(podLabels, testClientHost)
		})
		It("Checks Pod to Pod bandwidth, direct routing", func() {
			DeployCiliumOptionsAndDNS(kubectl, ciliumFilename, map[string]string{
				"bandwidthManager.enabled": "true",
				"routingMode":              "native",
				"autoDirectNodeRoutes":     "true",
			})
			waitForTestPods()
			testNetperf(podLabels, testClientPod)
			testNetperf(podLabels, testClientHost)
		})
	})
})

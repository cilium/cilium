// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package k8sTest

import (
	"fmt"
	. "github.com/onsi/gomega"

	. "github.com/cilium/cilium/test/ginkgo-ext"
	"github.com/cilium/cilium/test/helpers"
)

var _ = SkipDescribeIf(helpers.DoesNotRunOnNetNextKernel, "K8sDatapathQosTest", func() {
	var (
		kubectl        *helpers.Kubectl
		ciliumFilename string
		demoYAML       string
	)

	BeforeAll(func() {
		kubectl = helpers.CreateKubectl(helpers.K8s1VMName(), logger)

		ciliumFilename = helpers.TimestampFilename("cilium.yaml")

		demoYAML = helpers.ManifestGet(kubectl.BasePath(), "demo_qos.yaml")
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

	Context("Checks Bandwidth QoS Classes", func() {
		const (
			testNetperfServer         = "run=netperf-server"
			testNetperfHighPrioClient = "run=netperf-high-prio-client"
			testNetperfLowPrioClient  = "run=netperf-low-prio-client"
		)
		var bwPrioResultsMap = map[string]float64{}

		AfterFailed(func() {
			kubectl.CiliumReport("cilium-dbg statedb bandwidth-edts", "cilium-dbg endpoint list")
		})

		JustAfterEach(func() {
			kubectl.ValidateNoErrorsInLogs(CurrentGinkgoTestDescription().Duration)
		})

		waitForTestPods := func() {
			podLabels := []string{
				testNetperfServer,
				testNetperfHighPrioClient,
				testNetperfLowPrioClient,
			}
			for _, label := range podLabels {
				err := kubectl.WaitforPods(helpers.DefaultNamespace,
					fmt.Sprintf("-l %s", label), helpers.HelperTimeout)
				Expect(err).Should(BeNil())
			}
		}

		testNetperf := func(serverLabel string, fromLabel string) {
			serverIPs, err := kubectl.GetPodsIPs(helpers.DefaultNamespace, serverLabel)
			ExpectWithOffset(1, err).Should(BeNil(), "Cannot retrieve pod IPs for %s", serverLabel)
			ExpectWithOffset(1, len(serverIPs)).To(Equal(int(1)), "Expected pod IPs mismatch")
			for _, serverIP := range serverIPs {
				pods, err := kubectl.GetPodNames(helpers.DefaultNamespace, fromLabel)
				ExpectWithOffset(1, err).Should(BeNil(), "cannot retrieve pod names by filter %q",
					fromLabel)
				maxSessions := 100
				cmd := helpers.SuperNetperf(maxSessions, serverIP, helpers.TCP_STREAM, "-l 120 -P 8 -- -m 1500000 -R 1")
				By("Running %d netperf sessions from %s pod to pod with IP %s",
					maxSessions, pods[0], serverIP)
				res := kubectl.ExecPodCmd(helpers.DefaultNamespace, pods[0], cmd)
				ExpectWithOffset(1, res).Should(helpers.CMDSuccess(),
					"Request from %s pod to pod with IP %s failed", pods[0], serverIP)
				By("Session test completed, netperf result raw: %s", res.SingleOut())
				observedRate, err := res.FloatOutput()
				Expect(err).Should(BeNil())
				bwPrioResultsMap[fromLabel] = observedRate
			}
		}

		It("High to Low Ratio", func() {
			DeployCiliumOptionsAndDNS(kubectl, ciliumFilename, map[string]string{
				"bandwidthManager.enabled": "true",
			})
			waitForTestPods()
			go testNetperf(testNetperfServer, testNetperfLowPrioClient)
			go testNetperf(testNetperfServer, testNetperfHighPrioClient)
			// wait until bwPrioResultsMap has both high and low prio results
			Eventually(func() bool {
				return len(bwPrioResultsMap) == 2
			}, "5m", "10s").Should(BeTrue())
			// check if the ratio of high and low priority tput is around 1:9
			Expect(bwPrioResultsMap[testNetperfHighPrioClient] / bwPrioResultsMap[testNetperfLowPrioClient]).
				To(BeNumerically("~", 8, 10))
		})
	})
})

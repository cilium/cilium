// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package k8sTest

import (
	"fmt"
	"sync"

	. "github.com/onsi/gomega"

	. "github.com/cilium/cilium/test/ginkgo-ext"
	"github.com/cilium/cilium/test/helpers"
)

var _ = Describe("K8sDatapathHostFirewall", func() {
	Context("Host firewall", func() {
		var (
			kubectl    *helpers.Kubectl
		)

		BeforeAll(func() {
			kubectl = helpers.CreateKubectl(helpers.K8s1VMName(), logger)
			deploymentManager.SetKubectl(kubectl)

			kubectl.Exec("kubectl label nodes --all status=lockdown")
		})

		AfterAll(func() {
			deploymentManager.DeleteAll()
			ExpectAllPodsTerminated(kubectl)

			kubectl.Exec("kubectl label nodes --all status-")

			kubectl.ScaleDownDNS()
			ExpectAllPodsTerminated(kubectl)
			deploymentManager.DeleteCilium()
			kubectl.ScaleUpDNS()
			kubectl.CloseSSHClient()
		})

		AfterFailed(func() {
			kubectl.CiliumReport("cilium status", "cilium endpoint list")
		})

		JustAfterEach(func() {
			kubectl.ValidateNoErrorsInLogs(CurrentGinkgoTestDescription().Duration)
		})

		testHostFirewallWithPath := func(kubectl *helpers.Kubectl, randomNs, client, server string, crossNodes bool) {
			srcPod, srcPodJSON := fetchPodsWithOffset(kubectl, randomNs, "client", client, "", crossNodes, 3)
			srcHost, err := srcPodJSON.Filter("{.status.hostIP}")
			ExpectWithOffset(2, err).Should(BeNil(), "Failure to retrieve host of pod %s", srcPod)

			dstPod, dstPodJSON := fetchPodsWithOffset(kubectl, randomNs, "server", server, srcHost.String(), crossNodes, 3)
			podIP, err := dstPodJSON.Filter("{.status.podIP}")
			ExpectWithOffset(2, err).Should(BeNil(), "Failure to retrieve IP of pod %s", dstPod)
			targetIP := podIP.String()

			res := kubectl.ExecPodCmd(randomNs, srcPod, helpers.CurlFail("http://%s:80/", targetIP))
			ExpectWithOffset(2, res).Should(helpers.CMDSuccess(),
				"Failed to reach %s:80 from %s", targetIP, srcPod)

			res = kubectl.ExecPodCmd(randomNs, srcPod, helpers.CurlFail("tftp://%s:69/hello", targetIP))
			ExpectWithOffset(2, res).ShouldNot(helpers.CMDSuccess(),
				"Managed to reach %s:69 from %s", targetIP, srcPod)
		}

		testHostFirewall := func(kubectl *helpers.Kubectl) {
			randomNs := deploymentManager.DeployRandomNamespaceShared(DemoHostFirewall)
			deploymentManager.WaitUntilReady()

			demoHostPolicies := helpers.ManifestGet(kubectl.BasePath(), "host-policies.yaml")
			By(fmt.Sprintf("Applying policies %s", demoHostPolicies))
			_, err := kubectl.CiliumClusterwidePolicyAction(demoHostPolicies, helpers.KubectlApply, helpers.HelperTimeout)
			ExpectWithOffset(1, err).Should(BeNil(), fmt.Sprintf("Error creating resource %s: %s", demoHostPolicies, err))
			defer func() {
				_, err := kubectl.CiliumClusterwidePolicyAction(demoHostPolicies, helpers.KubectlDelete, helpers.HelperTimeout)
				ExpectWithOffset(1, err).Should(BeNil(), fmt.Sprintf("Error deleting resource %s: %s", demoHostPolicies, err))
			}()

			var wg sync.WaitGroup
			wg.Add(1)
			go func() {
				defer GinkgoRecover()
				defer wg.Done()
				By("Checking host policies on ingress from local pod")
				testHostFirewallWithPath(kubectl, randomNs, "zgroup=testClient", "zgroup=testServerHost", false)
			}()
			wg.Add(1)
			go func() {
				defer GinkgoRecover()
				defer wg.Done()
				By("Checking host policies on ingress from remote pod")
				testHostFirewallWithPath(kubectl, randomNs, "zgroup=testClient", "zgroup=testServerHost", true)
			}()
			wg.Add(1)
			go func() {
				defer GinkgoRecover()
				defer wg.Done()
				By("Checking host policies on egress to local pod")
				testHostFirewallWithPath(kubectl, randomNs, "zgroup=testClientHost", "zgroup=testServer", false)
			}()
			wg.Add(1)
			go func() {
				defer GinkgoRecover()
				defer wg.Done()
				By("Checking host policies on egress to remote pod")
				testHostFirewallWithPath(kubectl, randomNs, "zgroup=testClientHost", "zgroup=testServer", true)
			}()
			wg.Add(1)
			go func() {
				defer GinkgoRecover()
				defer wg.Done()
				By("Checking host policies on ingress from remote node")
				testHostFirewallWithPath(kubectl, randomNs, "zgroup=testServerHost", "zgroup=testClientHost", true)
			}()
			wg.Add(1)
			go func() {
				defer GinkgoRecover()
				defer wg.Done()
				By("Checking host policies on egress to remote node")
				testHostFirewallWithPath(kubectl, randomNs, "zgroup=testClientHost", "zgroup=testServerHost", true)
			}()
			wg.Wait()
		}

		SkipItIf(helpers.RunsOnAKS, "With VXLAN", func() {
			options := map[string]string{
				"hostFirewall.enabled": "true",
			}
			if helpers.RunsOnGKE() {
				options["gke.enabled"] = "false"
				options["tunnelProtocol"] = "vxlan"
			}
			deploymentManager.DeployCilium(options, DeployCiliumOptionsAndDNS)
			testHostFirewall(kubectl)
		})

		SkipItIf(func() bool {
			return helpers.RunsOnAKS()
		}, "With VXLAN and endpoint routes", func() {
			options := map[string]string{
				"hostFirewall.enabled":   "true",
				"endpointRoutes.enabled": "true",
			}
			if helpers.RunsOnGKE() {
				options["gke.enabled"] = "false"
				options["tunnelProtocol"] = "vxlan"
			}
			deploymentManager.DeployCilium(options, DeployCiliumOptionsAndDNS)
			testHostFirewall(kubectl)
		})

		It("With native routing", func() {
			options := map[string]string{
				"hostFirewall.enabled": "true",
				"routingMode":          "native",
			}
			// We don't want to run with per-endpoint routes (enabled by
			// gke.enabled) for this test.
			if helpers.RunsOnGKE() {
				options["gke.enabled"] = "false"
			} else {
				options["autoDirectNodeRoutes"] = "true"
			}
			deploymentManager.DeployCilium(options, DeployCiliumOptionsAndDNS)
			testHostFirewall(kubectl)
		})

		It("With native routing and endpoint routes", func() {
			options := map[string]string{
				"hostFirewall.enabled":   "true",
				"routingMode":            "native",
				"endpointRoutes.enabled": "true",
			}
			if !helpers.RunsOnGKE() {
				options["autoDirectNodeRoutes"] = "true"
			}
			deploymentManager.DeployCilium(options, DeployCiliumOptionsAndDNS)
			testHostFirewall(kubectl)
		})
	})
})

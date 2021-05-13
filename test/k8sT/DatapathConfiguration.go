// Copyright 2017-2021 Authors of Cilium
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
	"net"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/cilium/cilium/test/config"
	. "github.com/cilium/cilium/test/ginkgo-ext"
	"github.com/cilium/cilium/test/helpers"

	. "github.com/onsi/gomega"
)

var _ = Describe("K8sDatapathConfig", func() {

	var (
		kubectl    *helpers.Kubectl
		monitorLog = "monitor-aggregation.log"
	)

	BeforeAll(func() {
		kubectl = helpers.CreateKubectl(helpers.K8s1VMName(), logger)
		deploymentManager.SetKubectl(kubectl)
	})

	AfterEach(func() {
		deploymentManager.DeleteAll()
	})

	AfterFailed(func() {
		kubectl.CiliumReport("cilium status", "cilium endpoint list")
	})

	AfterAll(func() {
		deploymentManager.DeleteCilium()
		kubectl.CloseSSHClient()
	})

	JustAfterEach(func() {
		kubectl.ValidateNoErrorsInLogs(CurrentGinkgoTestDescription().Duration)
	})

	deployNetperf := func() string {
		randomNamespace := deploymentManager.DeployRandomNamespace(DemoDaemonSet)
		deploymentManager.Deploy(randomNamespace, NetperfPods)
		deploymentManager.WaitUntilReady()

		_, err := kubectl.GetPodsIPs(randomNamespace, NetperfPods.LabelSelector)
		Expect(err).To(BeNil(), "Cannot get pods ips")

		_, _, err = kubectl.GetServiceHostPort(randomNamespace, "netperf-service")
		Expect(err).To(BeNil(), "cannot get service netperf ip")

		return randomNamespace
	}

	deployHTTPclientAndServer := func() string {
		randomNamespace := deploymentManager.DeployRandomNamespace(HttpServer)
		deploymentManager.Deploy(randomNamespace, HttpClients)
		deploymentManager.WaitUntilReady()

		_, err := kubectl.GetPodsIPs(randomNamespace, HttpClients.LabelSelector)
		Expect(err).To(BeNil(), "Cannot get pods ips")

		_, err = kubectl.GetPodsIPs(randomNamespace, HttpServer.LabelSelector)
		Expect(err).To(BeNil(), "Cannot get pods ips")

		return randomNamespace
	}

	Context("MonitorAggregation", func() {
		It("Checks that monitor aggregation restricts notifications", func() {
			deploymentManager.DeployCilium(map[string]string{
				"bpf.monitorAggregation": "medium",
				"bpf.monitorInterval":    "60s",
				"bpf.monitorFlags":       "syn",
				// Need to disable the host firewall for now due to complexity issue.
				// See #14552 for details.
				"hostFirewall": "false",
			}, DeployCiliumOptionsAndDNS)

			monitorRes, monitorCancel, targetIP := monitorConnectivityAcrossNodes(kubectl)
			defer monitorCancel()

			var monitorOutput []byte
			searchMonitorLog := func(expr *regexp.Regexp) bool {
				monitorOutput = monitorRes.CombineOutput().Bytes()
				egressMatches := expr.FindAllIndex(monitorOutput, -1)
				return len(egressMatches) > 0
			}

			By("Checking that ICMP notifications in egress direction were observed")
			expEgress := fmt.Sprintf("ICMPv4.*DstIP=%s", targetIP)
			expEgressRegex := regexp.MustCompile(expEgress)
			Eventually(func() bool {
				return searchMonitorLog(expEgressRegex)
			}, helpers.HelperTimeout, time.Second).Should(BeTrue(), "Egress ICMPv4 flow (%q) not found in monitor log\n%s", expEgress, monitorOutput)

			By("Checking that ICMP notifications in ingress direction were observed")
			expIngress := fmt.Sprintf("ICMPv4.*SrcIP=%s", targetIP)
			expIngressRegex := regexp.MustCompile(expIngress)
			Eventually(func() bool {
				return searchMonitorLog(expIngressRegex)
			}, helpers.HelperTimeout, time.Second).Should(BeTrue(), "Ingress ICMPv4 flow (%q) not found in monitor log\n%s", expIngress, monitorOutput)

			By("Checking the set of TCP notifications received matches expectations")
			// | TCP Flags | Direction | Report? | Why?
			// +===========+===========+=========+=====
			// | SYN       |    ->     |    Y    | monitorFlags=SYN
			// | SYN / ACK |    <-     |    Y    | monitorFlags=SYN
			// | ACK       |    ->     |    N    | monitorFlags=(!ACK)
			// | ACK       |    ...    |    N    | monitorFlags=(!ACK)
			// | ACK       |    <-     |    N    | monitorFlags=(!ACK)
			// | FIN       |    ->     |    Y    | monitorAggregation=medium
			// | FIN / ACK |    <-     |    Y    | monitorAggregation=medium
			// | ACK       |    ->     |    Y    | monitorAggregation=medium
			egressPktCount := 3
			ingressPktCount := 2
			Eventually(func() bool {
				monitorOutput = monitorRes.CombineOutput().Bytes()
				return checkMonitorOutput(monitorOutput, egressPktCount, ingressPktCount)
			}, helpers.HelperTimeout, time.Second).Should(BeTrue(), "Monitor log did not contain %d ingress and %d egress TCP notifications\n%s",
				ingressPktCount, egressPktCount, monitorOutput)

			helpers.WriteToReportFile(monitorOutput, monitorLog)
		})

		It("Checks that monitor aggregation flags send notifications", func() {
			deploymentManager.DeployCilium(map[string]string{
				"bpf.monitorAggregation": "medium",
				"bpf.monitorInterval":    "60s",
				"bpf.monitorFlags":       "psh",
			}, DeployCiliumOptionsAndDNS)
			monitorRes, monitorCancel, _ := monitorConnectivityAcrossNodes(kubectl)
			defer monitorCancel()

			var monitorOutput []byte
			By("Checking the set of TCP notifications received matches expectations")
			// | TCP Flags | Direction | Report? | Why?
			// +===========+===========+=========+=====
			// | SYN       |    ->     |    Y    | monitorAggregation=medium
			// | SYN / ACK |    <-     |    Y    | monitorAggregation=medium
			// | ACK       |    ->     |    N    | monitorFlags=(!ACK)
			// | ACK       |    ...    |    N    | monitorFlags=(!ACK)
			// | PSH       |    ->     |    Y    | monitorFlags=(PSH)
			// | PSH       |    <-     |    Y    | monitorFlags=(PSH)
			// | FIN       |    ->     |    Y    | monitorAggregation=medium
			// | FIN / ACK |    <-     |    Y    | monitorAggregation=medium
			// | ACK       |    ->     |    Y    | monitorAggregation=medium
			egressPktCount := 4
			ingressPktCount := 3
			Eventually(func() bool {
				monitorOutput = monitorRes.CombineOutput().Bytes()
				return checkMonitorOutput(monitorOutput, egressPktCount, ingressPktCount)
			}, helpers.HelperTimeout, time.Second).Should(BeTrue(), "monitor aggregation did not result in correct number of TCP notifications\n%s", monitorOutput)
			helpers.WriteToReportFile(monitorOutput, monitorLog)
		})
	})

	Context("Encapsulation", func() {
		BeforeEach(func() {
			SkipIfIntegration(helpers.CIIntegrationGKE)
		})

		validateBPFTunnelMap := func() {
			By("Checking that BPF tunnels are in place")
			ciliumPod, err := kubectl.GetCiliumPodOnNode(helpers.K8s1)
			ExpectWithOffset(1, err).Should(BeNil(), "Unable to determine cilium pod on node %s", helpers.K8s1)
			status := kubectl.CiliumExecMustSucceed(context.TODO(), ciliumPod, "cilium bpf tunnel list | wc -l")

			// ipv4+ipv6: 2 entries for each remote node + 1 header row
			numEntries := (kubectl.GetNumCiliumNodes()-1)*2 + 1
			if value := helpers.HelmOverride("ipv6.enabled"); value == "false" {
				// ipv4 only: 1 entry for each remote node + 1 header row
				numEntries = (kubectl.GetNumCiliumNodes() - 1) + 1
			}

			Expect(status.IntOutput()).Should(Equal(numEntries), "Did not find expected number of entries in BPF tunnel map")
		}

		SkipItIf(helpers.RunsWithoutKubeProxy, "Check connectivity with transparent encryption and VXLAN encapsulation", func() {
			// FIXME(brb) Currently, the test is broken with CI 4.19 setup. Run it on 4.19
			//			  once we have kube-proxy disabled there.
			if !helpers.RunsOnNetNextKernel() {
				Skip("Skipping test because it is not running with the net-next kernel")
				return
			}

			deploymentManager.Deploy(helpers.CiliumNamespace, IPSecSecret)
			deploymentManager.DeployCilium(map[string]string{
				"kubeProxyReplacement": "disabled",
				"encryption.enabled":   "true",
			}, DeployCiliumOptionsAndDNS)
			validateBPFTunnelMap()
			Expect(testPodConnectivityAcrossNodes(kubectl)).Should(BeTrue(), "Connectivity test with IPsec between nodes failed")
		}, 600)

		It("Check connectivity with sockops and VXLAN encapsulation", func() {
			// Note if run on kernel without sockops feature is ignored
			if !helpers.RunsOn419OrLaterKernel() {
				Skip("Skipping sockops testing before 4.19 kernel")
				return
			}

			deploymentManager.DeployCilium(map[string]string{
				"sockops.enabled": "true",
			}, DeployCiliumOptionsAndDNS)
			validateBPFTunnelMap()
			Expect(testPodConnectivityAcrossNodes(kubectl)).Should(BeTrue(), "Connectivity test between nodes failed")
			Expect(testPodConnectivitySameNodes(kubectl)).Should(BeTrue(), "Connectivity test on same node failed")
		}, 600)

		It("Check connectivity with VXLAN encapsulation", func() {
			deploymentManager.DeployCilium(map[string]string{
				"tunnel": "vxlan",
			}, DeployCiliumOptionsAndDNS)
			validateBPFTunnelMap()
			Expect(testPodConnectivityAcrossNodes(kubectl)).Should(BeTrue(), "Connectivity test between nodes failed")
		}, 600)

		// Geneve is currently not supported on GKE
		SkipItIf(helpers.RunsOnGKE, "Check connectivity with Geneve encapsulation", func() {
			deploymentManager.DeployCilium(map[string]string{
				"tunnel": "geneve",
			}, DeployCiliumOptionsAndDNS)
			validateBPFTunnelMap()
			Expect(testPodConnectivityAcrossNodes(kubectl)).Should(BeTrue(), "Connectivity test between nodes failed")
		})

		It("Check vxlan connectivity with per-endpoint routes", func() {
			deploymentManager.DeployCilium(map[string]string{
				"tunnel":                 "vxlan",
				"endpointRoutes.enabled": "true",
			}, DeployCiliumOptionsAndDNS)
			Expect(testPodConnectivityAcrossNodes(kubectl)).Should(BeTrue(), "Connectivity test between nodes failed")

			if helpers.RunsOn419OrLaterKernel() {
				By("Test BPF masquerade")
				Expect(testPodHTTPToOutside(kubectl, "http://google.com", false, false)).
					Should(BeTrue(), "Connectivity test to http://google.com failed")
			}
		})

		It("Check iptables masquerading with random-fully", func() {
			deploymentManager.DeployCilium(map[string]string{
				"bpf.masquerade":      "false",
				"iptablesRandomFully": "true",
			}, DeployCiliumOptionsAndDNS)
			Expect(testPodConnectivityAcrossNodes(kubectl)).Should(BeTrue(), "Connectivity test between nodes failed")

			By("Test iptables masquerading")
			Expect(testPodHTTPToOutside(kubectl, "http://google.com", false, false)).
				Should(BeTrue(), "Connectivity test to http://google.com failed")
		})

		It("Check iptables masquerading without random-fully", func() {
			deploymentManager.DeployCilium(map[string]string{
				"bpf.masquerade": "false",
			}, DeployCiliumOptionsAndDNS)
			Expect(testPodConnectivityAcrossNodes(kubectl)).Should(BeTrue(), "Connectivity test between nodes failed")

			By("Test iptables masquerading")
			Expect(testPodHTTPToOutside(kubectl, "http://google.com", false, false)).
				Should(BeTrue(), "Connectivity test to http://google.com failed")
		})
	})

	// DirectRouting without AutoDirectNodeRoutes not supported outside of GKE.
	SkipContextIf(helpers.DoesNotRunOnGKE, "DirectRouting", func() {
		It("Check connectivity with direct routing", func() {
			deploymentManager.DeployCilium(map[string]string{
				"tunnel":                 "disabled",
				"k8s.requireIPv4PodCIDR": "true",
				"endpointRoutes.enabled": "false",
			}, DeployCiliumOptionsAndDNS)

			Expect(testPodConnectivityAcrossNodes(kubectl)).Should(BeTrue(), "Connectivity test between nodes failed")
		})

		It("Check connectivity with direct routing and endpointRoutes", func() {
			deploymentManager.DeployCilium(map[string]string{
				"tunnel":                 "disabled",
				"k8s.requireIPv4PodCIDR": "true",
				"endpointRoutes.enabled": "true",
			}, DeployCiliumOptionsAndDNS)

			Expect(testPodConnectivityAcrossNodes(kubectl)).Should(BeTrue(), "Connectivity test between nodes failed")
		})
	})

	Context("AutoDirectNodeRoutes", func() {
		BeforeEach(func() {
			SkipIfIntegration(helpers.CIIntegrationGKE)
		})

		It("Check connectivity with automatic direct nodes routes", func() {
			options := map[string]string{
				"tunnel":               "disabled",
				"autoDirectNodeRoutes": "true",
			}
			// Needed to bypass bug with masquerading when devices are set. See #12141.
			if helpers.DoesNotRunWithKubeProxyReplacement() {
				options["masquerade"] = "false"
				// This test fails if the hostfw is enabled (and devices specified).
				// See #12205 for details.
				options["hostFirewall"] = "false"
			}
			deploymentManager.DeployCilium(options, DeployCiliumOptionsAndDNS)

			Expect(testPodConnectivityAcrossNodes(kubectl)).Should(BeTrue(), "Connectivity test between nodes failed")
			if helpers.RunsOn419OrLaterKernel() {
				By("Test BPF masquerade")
				Expect(testPodHTTPToOutside(kubectl, "http://google.com", false, false)).
					Should(BeTrue(), "Connectivity test to http://google.com failed")
			}
		})

		It("Check direct connectivity with per endpoint routes", func() {
			options := map[string]string{
				"tunnel":                 "disabled",
				"autoDirectNodeRoutes":   "true",
				"endpointRoutes.enabled": "true",
				"ipv6.enabled":           "false",
			}
			// Needed to bypass bug with masquerading when devices are set. See #12141.
			if helpers.DoesNotRunWithKubeProxyReplacement() {
				options["masquerade"] = "false"
			}
			deploymentManager.DeployCilium(options, DeployCiliumOptionsAndDNS)

			Expect(testPodConnectivityAcrossNodes(kubectl)).Should(BeTrue(), "Connectivity test between nodes failed")
		})

		It("Check connectivity with sockops and direct routing", func() {
			// Note if run on kernel without sockops feature is ignored
			if !helpers.RunsOn419OrLaterKernel() {
				Skip("Skipping sockops testing before 4.19 kernel")
				return
			}

			deploymentManager.DeployCilium(map[string]string{
				"sockops.enabled": "true",
			}, DeployCiliumOptionsAndDNS)
			Expect(testPodConnectivityAcrossNodes(kubectl)).Should(BeTrue(), "Connectivity test between nodes failed")
			Expect(testPodConnectivitySameNodes(kubectl)).Should(BeTrue(), "Connectivity test on same node failed")
		}, 600)
	})

	SkipContextIf(func() bool {
		return helpers.DoesNotExistNodeWithoutCilium() || helpers.DoesNotRunOn419OrLaterKernel()
	}, "Check BPF masquerading with ip-masq-agent", func() {
		var (
			tmpEchoPodPath      string
			tmpConfigMapDirPath string
			tmpConfigMapPath    string
			tmpConfigYAMLPath   string
		)

		installConfig := func(cidrsInYaml string) {
			ns := helpers.GetCiliumNamespace(helpers.GetCurrentIntegration())
			kubectl.ExecMiddle(fmt.Sprintf("echo 'nonMasqueradeCIDRs:\n%s' > %s",
				cidrsInYaml, tmpConfigMapPath)).ExpectSuccess()
			kubectl.CreateResource("configmap",
				fmt.Sprintf("ip-masq-agent --from-file=%s --namespace=%s -o yaml --dry-run > %s",
					tmpConfigMapDirPath, ns, tmpConfigYAMLPath)).
				ExpectSuccess("Failed to create ip-masq-agent configmap file")
			kubectl.ApplyDefault(tmpConfigYAMLPath).ExpectSuccess("Failed to apply configmap")
		}

		BeforeAll(func() {
			// Deploy echoserver on the node which does not run Cilium to test
			// BPF masquerading. The pod will run in the host netns, so no CNI
			// is required for the pod on that host.
			echoPodPath := helpers.ManifestGet(kubectl.BasePath(), "echoserver-hostnetns.yaml")
			res := kubectl.ExecMiddle("mktemp")
			res.ExpectSuccess()
			tmpEchoPodPath = strings.Trim(res.Stdout(), "\n")
			kubectl.ExecMiddle(fmt.Sprintf("sed 's/NODE_WITHOUT_CILIUM/%s/' %s > %s",
				helpers.GetNodeWithoutCilium(), echoPodPath, tmpEchoPodPath)).ExpectSuccess()
			kubectl.ApplyDefault(tmpEchoPodPath).ExpectSuccess("Cannot install echoserver application")
			Expect(kubectl.WaitforPods(helpers.DefaultNamespace, "-l name=echoserver-hostnetns",
				helpers.HelperTimeout)).Should(BeNil())

			// Setup ip-masq-agent configmap dir
			res = kubectl.ExecMiddle("mktemp -d")
			res.ExpectSuccess()
			tmpConfigMapDirPath = strings.Trim(res.Stdout(), "\n")
			tmpConfigMapPath = filepath.Join(tmpConfigMapDirPath, "config")
			res = kubectl.ExecMiddle("mktemp")
			res.ExpectSuccess()
			tmpConfigYAMLPath = strings.Trim(res.Stdout(), "\n")

			// Deploy empty ip-masq-agent config to prevent the ipmasq agent from
			// adding the default nonMasq CIDRs which include the echoserver's
			// node IP. This is needed, as the first test case expects the request
			// to be masqueraded.
			installConfig("")
		})

		AfterEach(func() {
			// Don't remove so that the default nonMasq CIDRs are not installed
			installConfig("")
		})

		AfterAll(func() {
			ns := helpers.GetCiliumNamespace(helpers.GetCurrentIntegration())
			kubectl.DeleteResource("configmap", fmt.Sprintf("ip-masq-agent --namespace=%s", ns))

			if tmpEchoPodPath != "" {
				kubectl.Delete(tmpEchoPodPath)
			}

			for _, path := range []string{tmpEchoPodPath, tmpConfigMapPath, tmpConfigMapDirPath, tmpConfigYAMLPath} {
				if path != "" {
					os.Remove(path)
				}
			}
		})

		testIPMasqAgent := func() {
			// Check that requests to the echoserver from client pods are masqueraded.
			nodeIP, err := kubectl.GetNodeIPByLabel(helpers.GetNodeWithoutCilium(), false)
			Expect(err).Should(BeNil())
			Expect(testPodHTTPToOutside(kubectl,
				fmt.Sprintf("http://%s:80", nodeIP), true, false)).Should(BeTrue(),
				"Connectivity test to http://%s failed", nodeIP)

			// Update ip-masq-agent config to prevent masquerading to the node IP
			// which is running the echoserver.
			installConfig(fmt.Sprintf("- %s/32", nodeIP))

			// Wait until the ip-masq-agent config update is handled by the agent
			time.Sleep(90 * time.Second)

			// Check that connections from the client pods are not masqueraded
			Expect(testPodHTTPToOutside(kubectl,
				fmt.Sprintf("http://%s:80", nodeIP), false, true)).Should(BeTrue(),
				"Connectivity test to http://%s failed", nodeIP)
		}

		It("DirectRouting", func() {
			deploymentManager.DeployCilium(map[string]string{
				"ipMasqAgent.enabled":  "true",
				"tunnel":               "disabled",
				"autoDirectNodeRoutes": "true",
			}, DeployCiliumOptionsAndDNS)

			testIPMasqAgent()
		})

		It("VXLAN", func() {
			deploymentManager.DeployCilium(map[string]string{
				"ipMasqAgent.enabled": "true",
				"tunnel":              "vxlan",
			}, DeployCiliumOptionsAndDNS)

			testIPMasqAgent()
		})
	})

	SkipContextIf(helpers.DoesNotRunOnNetNextKernel, "Wireguard encryption", func() {
		testWireguard := func(interNodeDev string) {
			randomNamespace := deploymentManager.DeployRandomNamespaceShared(DemoDaemonSet)
			deploymentManager.WaitUntilReady()

			k8s1NodeName, k8s1IP := kubectl.GetNodeInfo(helpers.K8s1)
			k8s2NodeName, k8s2IP := kubectl.GetNodeInfo(helpers.K8s2)

			// Fetch srcPod (testDSClient@k8s1)
			srcPod, srcPodJSON := fetchPodsWithOffset(kubectl, randomNamespace, "client", "zgroup=testDSClient", k8s2IP, true, 0)
			srcPodIP, err := srcPodJSON.Filter("{.status.podIP}")
			ExpectWithOffset(1, err).Should(BeNil(), "Failure to retrieve pod IP %s", srcPod)
			srcHost, err := srcPodJSON.Filter("{.status.hostIP}")
			ExpectWithOffset(1, err).Should(BeNil(), "Failure to retrieve host of pod %s", srcPod)
			// Sanity check
			ExpectWithOffset(1, srcHost.String()).Should(Equal(k8s1IP))
			// Fetch srcPod IPv6
			ciliumPodK8s1, err := kubectl.GetCiliumPodOnNode(helpers.K8s1)
			ExpectWithOffset(1, err).Should(BeNil(), "Unable to fetch cilium pod on k8s1")
			endpointIPs := kubectl.CiliumEndpointIPv6(ciliumPodK8s1, "-l k8s:zgroup=testDSClient")
			// Sanity check
			ExpectWithOffset(1, len(endpointIPs)).Should(Equal(1), "BUG: more than one DS client on %s", ciliumPodK8s1)
			var srcPodIPv6 string
			for _, ip := range endpointIPs {
				srcPodIPv6 = ip
				break
			}

			// Fetch dstPod (testDS@k8s2)
			dstPod, dstPodJSON := fetchPodsWithOffset(kubectl, randomNamespace, "server", "zgroup=testDS", k8s1IP, true, 0)
			dstPodIP, err := dstPodJSON.Filter("{.status.podIP}")
			ExpectWithOffset(1, err).Should(BeNil(), "Failure to retrieve IP of pod %s", dstPod)
			dstHost, err := dstPodJSON.Filter("{.status.hostIP}")
			ExpectWithOffset(1, err).Should(BeNil(), "Failure to retrieve host of pod %s", dstPod)
			// Sanity check
			ExpectWithOffset(1, dstHost.String()).Should(Equal(k8s2IP))
			// Fetch dstPod IPv6
			ciliumPodK8s2, err := kubectl.GetCiliumPodOnNode(helpers.K8s2)
			ExpectWithOffset(1, err).Should(BeNil(), "Unable to fetch cilium pod on k8s2")
			endpointIPs = kubectl.CiliumEndpointIPv6(ciliumPodK8s2, "-l k8s:zgroup=testDS")
			// Sanity check
			ExpectWithOffset(1, len(endpointIPs)).Should(Equal(1), "BUG: more than one DS server on %s", ciliumPodK8s2)
			var dstPodIPv6 string
			for _, ip := range endpointIPs {
				dstPodIPv6 = ip
				break
			}

			// Due to IPCache update delays, it can take up to a few seconds
			// before both nodes have added the new pod IPs to their allowedIPs
			// list, which can cause flakes in CI. Therefore wait for the
			// IPs to be present on both nodes before performing the test
			waitForAllowedIP := func(ciliumPod, ip string) {
				jsonpath := fmt.Sprintf(`{.encryption.wireguard.interfaces[*].peers[*].allowed-ips[?(@=='%s')]}`, ip)
				ciliumCmd := fmt.Sprintf(`cilium debuginfo --output jsonpath="%s"`, jsonpath)
				expected := fmt.Sprintf("jsonpath=%s", ip)
				err := kubectl.CiliumExecUntilMatch(ciliumPod, ciliumCmd, expected)
				Expect(err).To(BeNil(), "ip %q not in allowedIPs of pod %q", ip, ciliumPod)
			}

			waitForAllowedIP(ciliumPodK8s1, fmt.Sprintf("%s/32", dstPodIP))
			waitForAllowedIP(ciliumPodK8s1, fmt.Sprintf("%s/128", dstPodIPv6))

			waitForAllowedIP(ciliumPodK8s2, fmt.Sprintf("%s/32", srcPodIP))
			waitForAllowedIP(ciliumPodK8s2, fmt.Sprintf("%s/128", srcPodIPv6))

			checkNoLeak := func(srcPod, srcIP, dstIP string) {
				cmd := fmt.Sprintf("tcpdump -i %s --immediate-mode -n 'host %s and host %s' -c 1", interNodeDev, srcIP, dstIP)
				res1, cancel1, err := kubectl.ExecInHostNetNSInBackground(context.TODO(), k8s1NodeName, cmd)
				ExpectWithOffset(2, err).Should(BeNil(), "Cannot exec tcpdump in bg")
				res2, cancel2, err := kubectl.ExecInHostNetNSInBackground(context.TODO(), k8s2NodeName, cmd)
				ExpectWithOffset(2, err).Should(BeNil(), "Cannot exec tcpdump in bg")

				// HTTP connectivity test (pod2pod)
				kubectl.ExecPodCmd(randomNamespace, srcPod,
					helpers.CurlFail("http://%s/", net.JoinHostPort(dstIP, "80"))).ExpectSuccess("Failed to curl dst pod")

				// Check that no unencrypted pod2pod traffic was captured on the direct routing device
				cancel1()
				cancel2()
				ExpectWithOffset(2, res1.CombineOutput().String()).Should(Not(ContainSubstring("1 packet captured")))
				ExpectWithOffset(2, res2.CombineOutput().String()).Should(Not(ContainSubstring("1 packet captured")))
			}

			checkNoLeak(srcPod, srcPodIP.String(), dstPodIP.String())
			checkNoLeak(srcPod, srcPodIPv6, dstPodIPv6)

			// Check that the src pod can reach the remote host
			kubectl.ExecPodCmd(randomNamespace, srcPod, helpers.Ping(k8s2IP)).
				ExpectSuccess("Failed to ping k8s2 host from src pod")

			// Check that the remote host can reach the dst pod
			kubectl.ExecInHostNetNS(context.TODO(), k8s1NodeName,
				helpers.CurlFail("http://%s:80/", dstPodIP)).ExpectSuccess("Failed to curl dst pod from k8s1")
		}

		It("Pod2pod is encrypted in direct-routing mode", func() {
			deploymentManager.DeployCilium(map[string]string{
				"tunnel":               "disabled",
				"autoDirectNodeRoutes": "true",
				"encryption.enabled":   "true",
				"encryption.type":      "wireguard",
				"l7Proxy":              "false",
			}, DeployCiliumOptionsAndDNS)

			privateIface, err := kubectl.GetPrivateIface()
			Expect(err).Should(BeNil(), "Cannot determine private iface")
			testWireguard(privateIface)
		})

		It("Pod2pod is encrypted in tunneling mode", func() {
			deploymentManager.DeployCilium(map[string]string{
				"tunnel":             "vxlan",
				"encryption.enabled": "true",
				"encryption.type":    "wireguard",
				"l7Proxy":            "false",
			}, DeployCiliumOptionsAndDNS)

			testWireguard("cilium_vxlan")
		})

		It("Pod2pod is encrypted in tunneling mode with per-endpoint routes", func() {
			deploymentManager.DeployCilium(map[string]string{
				"tunnel":                 "vxlan",
				"endpointRoutes.enabled": "true",
				"encryption.enabled":     "true",
				"encryption.type":        "wireguard",
				"l7Proxy":                "false",
			}, DeployCiliumOptionsAndDNS)

			testWireguard("cilium_vxlan")
		})

	})

	Context("Sockops performance", func() {
		directRoutingOptions := map[string]string{
			"tunnel":               "disabled",
			"autoDirectNodeRoutes": "true",
		}

		sockopsEnabledOptions := map[string]string{}
		for k, v := range directRoutingOptions {
			sockopsEnabledOptions[k] = v
		}

		sockopsEnabledOptions["sockops.enabled"] = "true"

		BeforeEach(func() {
			SkipIfBenchmark()
			SkipIfIntegration(helpers.CIIntegrationGKE)
		})

		It("Check baseline performance with direct routing TCP_CRR", func() {
			Skip("Skipping TCP_CRR until fix reaches upstream")
			deploymentManager.DeployCilium(directRoutingOptions, DeployCiliumOptionsAndDNS)
			namespace := deployNetperf()
			Expect(testPodNetperfSameNodes(kubectl, namespace, helpers.TCP_CRR)).Should(BeTrue(), "Connectivity test TCP_CRR on same node failed")
		}, 600)

		It("Check baseline performance with direct routing TCP_RR", func() {
			deploymentManager.DeployCilium(directRoutingOptions, DeployCiliumOptionsAndDNS)
			namespace := deployNetperf()
			Expect(testPodNetperfSameNodes(kubectl, namespace, helpers.TCP_RR)).Should(BeTrue(), "Connectivity test TCP_RR on same node failed")
		}, 600)

		It("Check baseline performance with direct routing TCP_STREAM", func() {
			deploymentManager.DeployCilium(directRoutingOptions, DeployCiliumOptionsAndDNS)
			namespace := deployNetperf()
			Expect(testPodNetperfSameNodes(kubectl, namespace, helpers.TCP_STREAM)).Should(BeTrue(), "Connectivity test TCP_STREAM on same node failed")
		}, 600)

		It("Check performance with sockops and direct routing", func() {
			Skip("Skipping TCP_CRR until fix reaches upstream")
			deploymentManager.DeployCilium(sockopsEnabledOptions, DeployCiliumOptionsAndDNS)
			namespace := deployNetperf()
			Expect(testPodNetperfSameNodes(kubectl, namespace, helpers.TCP_CRR)).Should(BeTrue(), "Connectivity test TCP_CRR on same node failed")
		}, 600)

		It("Check performance with sockops and direct routing", func() {
			deploymentManager.DeployCilium(sockopsEnabledOptions, DeployCiliumOptionsAndDNS)
			namespace := deployNetperf()
			Expect(testPodNetperfSameNodes(kubectl, namespace, helpers.TCP_RR)).Should(BeTrue(), "Connectivity test TCP_RR on same node failed")
		}, 600)

		It("Check performance with sockops and direct routing", func() {
			deploymentManager.DeployCilium(sockopsEnabledOptions, DeployCiliumOptionsAndDNS)
			namespace := deployNetperf()
			Expect(testPodNetperfSameNodes(kubectl, namespace, helpers.TCP_STREAM)).Should(BeTrue(), "Connectivity test TCP_STREAM on same node failed")
		}, 600)

		It("Check baseline http performance with sockops and direct routing", func() {
			deploymentManager.DeployCilium(directRoutingOptions, DeployCiliumOptionsAndDNS)
			namespace := deployHTTPclientAndServer()
			Expect(testPodHTTPSameNodes(kubectl, namespace)).Should(BeTrue(), "HTTP test on same node failed ")
		}, 600)

		It("Check http performance with sockops and direct routing", func() {
			deploymentManager.DeployCilium(sockopsEnabledOptions, DeployCiliumOptionsAndDNS)
			namespace := deployHTTPclientAndServer()
			Expect(testPodHTTPSameNodes(kubectl, namespace)).Should(BeTrue(), "HTTP test on same node failed ")
		}, 600)
	})

	Context("Transparent encryption DirectRouting", func() {
		SkipItIf(helpers.RunsWithoutKubeProxy, "Check connectivity with transparent encryption and direct routing", func() {
			SkipIfIntegration(helpers.CIIntegrationGKE)

			privateIface, err := kubectl.GetPrivateIface()
			Expect(err).Should(BeNil(), "Unable to determine private iface")

			deploymentManager.Deploy(helpers.CiliumNamespace, IPSecSecret)
			deploymentManager.DeployCilium(map[string]string{
				"tunnel":                     "disabled",
				"autoDirectNodeRoutes":       "true",
				"encryption.enabled":         "true",
				"encryption.ipsec.interface": privateIface,
				"devices":                    "",
				"hostFirewall":               "false",
				"kubeProxyReplacement":       "disabled",
			}, DeployCiliumOptionsAndDNS)
			Expect(testPodConnectivityAcrossNodes(kubectl)).Should(BeTrue(), "Connectivity test between nodes failed")
		})

		// This test is broken because of #12205. In short, when bpf_host is
		// loading on the native device, the source identity of packet on the
		// destination node is resolved to WORLD and policy enforcement fails.
		XIt("Check connectivity with transparent encryption and direct routing with bpf_host", func() {
			SkipIfIntegration(helpers.CIIntegrationGKE)

			privateIface, err := kubectl.GetPrivateIface()
			Expect(err).Should(BeNil(), "Unable to determine the private interface")
			defaultIface, err := kubectl.GetDefaultIface()
			Expect(err).Should(BeNil(), "Unable to determine the default interface")
			devices := fmt.Sprintf(`'{%s,%s}'`, privateIface, defaultIface)

			deploymentManager.Deploy(helpers.CiliumNamespace, IPSecSecret)
			deploymentManager.DeployCilium(map[string]string{
				"tunnel":                     "disabled",
				"autoDirectNodeRoutes":       "true",
				"encryption.enabled":         "true",
				"encryption.ipsec.interface": privateIface,
				"devices":                    devices,
				"hostFirewall":               "false",
			}, DeployCiliumOptionsAndDNS)
			Expect(testPodConnectivityAcrossNodes(kubectl)).Should(BeTrue(), "Connectivity test between nodes failed")
		})
	})

	Context("IPv4Only", func() {
		It("Check connectivity with IPv6 disabled", func() {
			deploymentManager.DeployCilium(map[string]string{
				"ipv4.enabled": "true",
				"ipv6.enabled": "false",
			}, DeployCiliumOptionsAndDNS)
			Expect(testPodConnectivityAcrossNodes(kubectl)).Should(BeTrue(), "Connectivity test between nodes failed")
		})
	})

	Context("Etcd", func() {
		It("Check connectivity", func() {
			deploymentManager.Deploy(helpers.CiliumNamespace, StatelessEtcd)
			deploymentManager.WaitUntilReady()

			host, port, err := kubectl.GetServiceHostPort(helpers.CiliumNamespace, "stateless-etcd")
			Expect(err).Should(BeNil(), "Unable to retrieve ClusterIP and port for stateless-etcd service")

			etcdService := fmt.Sprintf("http://%s:%d", host, port)
			opts := map[string]string{
				"etcd.enabled":           "true",
				"etcd.endpoints[0]":      etcdService,
				"identityAllocationMode": "kvstore",
			}
			if helpers.ExistNodeWithoutCilium() {
				opts["synchronizeK8sNodes"] = "false"
			}
			deploymentManager.DeployCilium(opts, DeployCiliumOptionsAndDNS)
			Expect(testPodConnectivityAcrossNodes(kubectl)).Should(BeTrue(), "Connectivity test between nodes failed")
		})
	})

	Context("Host firewall", func() {
		BeforeAll(func() {
			kubectl.Exec("kubectl label nodes --all status=lockdown")
		})

		AfterAll(func() {
			kubectl.Exec("kubectl label nodes --all status-")
		})

		AfterEach(func() {
			kubectl.Exec(fmt.Sprintf("%s delete --all ccnp", helpers.KubectlCmd))
		})

		SkipItIf(func() bool {
			return !helpers.IsIntegration(helpers.CIIntegrationGKE)
		}, "Check connectivity with IPv6 disabled", func() {
			deploymentManager.DeployCilium(map[string]string{
				"ipv4.enabled": "true",
				"ipv6.enabled": "false",
				"hostFirewall": "true",
			}, DeployCiliumOptionsAndDNS)
			Expect(testPodConnectivityAcrossNodes(kubectl)).Should(BeTrue(), "Connectivity test between nodes failed")
		})

		It("With VXLAN", func() {
			options := map[string]string{
				"hostFirewall": "true",
			}
			if helpers.RunsOnGKE() {
				options["gke.enabled"] = "false"
				options["tunnel"] = "vxlan"
			}
			deploymentManager.DeployCilium(options, DeployCiliumOptionsAndDNS)
			testHostFirewall(kubectl)
		})

		It("With VXLAN and endpoint routes", func() {
			options := map[string]string{
				"hostFirewall":           "true",
				"endpointRoutes.enabled": "true",
			}
			if helpers.RunsOnGKE() {
				options["gke.enabled"] = "false"
				options["tunnel"] = "vxlan"
			}
			deploymentManager.DeployCilium(options, DeployCiliumOptionsAndDNS)
			testHostFirewall(kubectl)
		})

		It("With native routing", func() {
			options := map[string]string{
				"hostFirewall": "true",
				"tunnel":       "disabled",
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
				"hostFirewall":           "true",
				"tunnel":                 "disabled",
				"endpointRoutes.enabled": "true",
			}
			if !helpers.RunsOnGKE() {
				options["autoDirectNodeRoutes"] = "true"
			}
			deploymentManager.DeployCilium(options, DeployCiliumOptionsAndDNS)
			testHostFirewall(kubectl)
		})
	})

	Context("Iptables", func() {
		SkipItIf(func() bool {
			return helpers.IsIntegration(helpers.CIIntegrationGKE) || helpers.DoesNotRunWithKubeProxyReplacement()
		}, "Skip conntrack for pod traffic", func() {
			deploymentManager.DeployCilium(map[string]string{
				"tunnel":                          "disabled",
				"autoDirectNodeRoutes":            "true",
				"installNoConntrackIptablesRules": "true",
			}, DeployCiliumOptionsAndDNS)

			ciliumPod, err := kubectl.GetCiliumPodOnNode(helpers.K8s1)
			ExpectWithOffset(1, err).Should(BeNil(), "Unable to determine cilium pod on node %s", helpers.K8s1)

			res := kubectl.ExecPodCmd(helpers.CiliumNamespace, ciliumPod, "sh -c 'apt update && apt install -y conntrack && conntrack -F'")
			Expect(res.WasSuccessful()).Should(BeTrue(), "Cannot flush conntrack table")

			Expect(testPodConnectivityAcrossNodes(kubectl)).Should(BeTrue(), "Connectivity test between nodes failed")

			cmd := fmt.Sprintf("iptables -t raw -C CILIUM_PRE_raw -s %s -m comment --comment 'cilium: NOTRACK for pod traffic' -j NOTRACK", helpers.NativeRoutingCIDR)
			res = kubectl.ExecPodCmd(helpers.CiliumNamespace, ciliumPod, cmd)
			Expect(res.WasSuccessful()).Should(BeTrue(), "Missing -j NOTRACK iptables rule")

			cmd = fmt.Sprintf("iptables -t raw -C CILIUM_PRE_raw -d %s -m comment --comment 'cilium: NOTRACK for pod traffic' -j NOTRACK", helpers.NativeRoutingCIDR)
			res = kubectl.ExecPodCmd(helpers.CiliumNamespace, ciliumPod, cmd)
			Expect(res.WasSuccessful()).Should(BeTrue(), "Missing -j NOTRACK iptables rule")

			cmd = fmt.Sprintf("iptables -t raw -C CILIUM_OUTPUT_raw -s %s -m comment --comment 'cilium: NOTRACK for pod traffic' -j NOTRACK", helpers.NativeRoutingCIDR)
			res = kubectl.ExecPodCmd(helpers.CiliumNamespace, ciliumPod, cmd)
			Expect(res.WasSuccessful()).Should(BeTrue(), "Missing -j NOTRACK iptables rule")

			cmd = fmt.Sprintf("iptables -t raw -C CILIUM_OUTPUT_raw -d %s -m comment --comment 'cilium: NOTRACK for pod traffic' -j NOTRACK", helpers.NativeRoutingCIDR)
			res = kubectl.ExecPodCmd(helpers.CiliumNamespace, ciliumPod, cmd)
			Expect(res.WasSuccessful()).Should(BeTrue(), "Missing -j NOTRACK iptables rule")

			cmd = fmt.Sprintf("conntrack -L -s %s -d %s | wc -l", helpers.NativeRoutingCIDR, helpers.NativeRoutingCIDR)
			res = kubectl.ExecPodCmd(helpers.CiliumNamespace, ciliumPod, cmd)
			Expect(res.WasSuccessful()).Should(BeTrue(), "Cannot list conntrack entries")
			Expect(strings.TrimSpace(res.Stdout())).To(Equal("0"), "Unexpected conntrack entries")
		})
	})
})

func testHostFirewall(kubectl *helpers.Kubectl) {
	randomNs := deploymentManager.DeployRandomNamespaceShared(DemoHostFirewall)
	deploymentManager.WaitUntilReady()

	demoHostPolicies := helpers.ManifestGet(kubectl.BasePath(), "host-policies.yaml")
	By(fmt.Sprintf("Applying policies %s", demoHostPolicies))
	_, err := kubectl.CiliumPolicyAction(randomNs, demoHostPolicies, helpers.KubectlApply, helpers.HelperTimeout)
	ExpectWithOffset(1, err).Should(BeNil(), fmt.Sprintf("Error creating resource %s: %s", demoHostPolicies, err))

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

func testHostFirewallWithPath(kubectl *helpers.Kubectl, randomNs, client, server string, crossNodes bool) {
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

func testPodConnectivityAcrossNodes(kubectl *helpers.Kubectl) bool {
	result, _ := testPodConnectivityAndReturnIP(kubectl, true, 1)
	return result
}

func testPodConnectivitySameNodes(kubectl *helpers.Kubectl) bool {
	result, _ := testPodConnectivityAndReturnIP(kubectl, false, 1)
	return result
}

func testPodNetperfSameNodes(kubectl *helpers.Kubectl, namespace string, test helpers.PerfTest) bool {
	result, _ := testPodNetperf(kubectl, namespace, false, 1, test)
	return result
}

func fetchPodsWithOffset(kubectl *helpers.Kubectl, namespace, name, filter, hostIPAntiAffinity string, requireMultiNode bool, callOffset int) (targetPod string, targetPodJSON *helpers.CmdRes) {
	callOffset++

	// Fetch pod (names) with the specified filter
	err := kubectl.WaitforPods(namespace, fmt.Sprintf("-l %s", filter), helpers.HelperTimeout)
	ExpectWithOffset(callOffset, err).Should(BeNil(), "Failure while waiting for connectivity test pods to start")
	pods, err := kubectl.GetPodNames(namespace, filter)
	ExpectWithOffset(callOffset, err).Should(BeNil(), "Failure while retrieving pod name for %s", filter)
	if requireMultiNode {
		if config.CiliumTestConfig.Multinode {
			ExpectWithOffset(callOffset, len(pods)).Should(BeNumerically(">", 1),
				fmt.Sprintf("This test requires at least two %s instances, but only one was found", name))
		} else {
			By("Ignoring the requirement for clients on multiple nodes")
			requireMultiNode = false
		}
	}

	// Fetch the json description of one of the pods
	targetPod = pods[0]
	targetPodJSON = kubectl.Get(
		namespace,
		fmt.Sprintf("pod %s -o json", targetPod))

	// If multinode / antiaffinity is required, ensure that the target is
	// not on the same node as "hostIPAntiAffinity".
	if requireMultiNode && hostIPAntiAffinity != "" {
		targetHost, err := targetPodJSON.Filter("{.status.hostIP}")
		ExpectWithOffset(callOffset, err).Should(BeNil(), "Failure to retrieve host of pod %s", targetPod)

		if targetHost.String() == hostIPAntiAffinity {
			targetPod = pods[1]
			targetPodJSON = kubectl.Get(
				namespace,
				fmt.Sprintf("pod %s -o json", targetPod))
		}
	} else if !requireMultiNode && hostIPAntiAffinity != "" {
		targetHost, err := targetPodJSON.Filter("{.status.hostIP}")
		ExpectWithOffset(callOffset, err).Should(BeNil(), "Failure to retrieve host of pod %s", targetPod)

		if targetHost.String() != hostIPAntiAffinity {
			targetPod = pods[1]
			targetPodJSON = kubectl.Get(
				namespace,
				fmt.Sprintf("pod %s -o json", targetPod))
		}
	}
	return targetPod, targetPodJSON
}

func applyL3Policy(kubectl *helpers.Kubectl, ns string) {
	demoPolicyL3 := helpers.ManifestGet(kubectl.BasePath(), "l3-policy-demo.yaml")
	By(fmt.Sprintf("Applying policy %s", demoPolicyL3))
	_, err := kubectl.CiliumPolicyAction(ns, demoPolicyL3, helpers.KubectlApply, helpers.HelperTimeout)
	ExpectWithOffset(1, err).Should(BeNil(), fmt.Sprintf("Error creating resource %s: %s", demoPolicyL3, err))
}

func testPodConnectivityAndReturnIP(kubectl *helpers.Kubectl, requireMultiNode bool, callOffset int) (bool, string) {
	callOffset++

	randomNamespace := deploymentManager.DeployRandomNamespaceShared(DemoDaemonSet)
	applyL3Policy(kubectl, randomNamespace)
	deploymentManager.WaitUntilReady()

	By("Checking pod connectivity between nodes")
	srcPod, srcPodJSON := fetchPodsWithOffset(kubectl, randomNamespace, "client", "zgroup=testDSClient", "", requireMultiNode, callOffset)
	srcHost, err := srcPodJSON.Filter("{.status.hostIP}")
	ExpectWithOffset(callOffset, err).Should(BeNil(), "Failure to retrieve host of pod %s", srcPod)

	dstPod, dstPodJSON := fetchPodsWithOffset(kubectl, randomNamespace, "server", "zgroup=testDS", srcHost.String(), requireMultiNode, callOffset)
	podIP, err := dstPodJSON.Filter("{.status.podIP}")
	ExpectWithOffset(callOffset, err).Should(BeNil(), "Failure to retrieve IP of pod %s", dstPod)
	targetIP := podIP.String()

	// ICMP connectivity test
	res := kubectl.ExecPodCmd(randomNamespace, srcPod, helpers.Ping(targetIP))
	if !res.WasSuccessful() {
		return false, targetIP
	}

	// HTTP connectivity test
	res = kubectl.ExecPodCmd(randomNamespace, srcPod,
		helpers.CurlFail("http://%s:80/", targetIP))
	return res.WasSuccessful(), targetIP
}

func testPodHTTPSameNodes(kubectl *helpers.Kubectl, namespace string) bool {
	result, _ := testPodHTTP(kubectl, namespace, false, 1)
	return result
}

func testPodHTTP(kubectl *helpers.Kubectl, namespace string, requireMultiNode bool, callOffset int) (bool, string) {
	callOffset++

	By("Checking pod http")
	dstPod, dstPodJSON := fetchPodsWithOffset(kubectl, namespace, "client", "zgroup=http-server", "", requireMultiNode, callOffset)
	dstHost, err := dstPodJSON.Filter("{.status.hostIP}")
	ExpectWithOffset(callOffset, err).Should(BeNil(), "Failure to retrieve host of pod %s", dstPod)

	podIP, err := dstPodJSON.Filter("{.status.podIP}")
	targetIP := podIP.String()

	srcPod, _ := fetchPodsWithOffset(kubectl, namespace, "server", "zgroup=http-client", dstHost.String(), requireMultiNode, callOffset)
	ExpectWithOffset(callOffset, err).Should(BeNil(), "Failure to retrieve IP of pod %s", srcPod)

	// Netperf benchmark test
	res := kubectl.ExecPodCmd(namespace, srcPod, helpers.Wrk(targetIP))
	res.ExpectContains("Requests/sec", "wrk failed")
	return true, targetIP

}

func testPodHTTPToOutside(kubectl *helpers.Kubectl, outsideURL string, expectNodeIP, expectPodIP bool) bool {
	var hostIPs map[string]string
	var podIPs map[string]string

	namespace := deploymentManager.DeployRandomNamespaceShared(DemoDaemonSet)
	applyL3Policy(kubectl, namespace)
	deploymentManager.WaitUntilReady()

	label := "zgroup=testDSClient"
	pods, err := kubectl.GetPodNames(namespace, label)
	ExpectWithOffset(1, err).Should(BeNil(), "Cannot retrieve pod names by label %s", label)

	cmd := helpers.CurlWithRetries(outsideURL, 10, true)
	if expectNodeIP || expectPodIP {
		cmd += " | grep client_address="
		hostIPs, err = kubectl.GetPodsHostIPs(namespace, label)
		ExpectWithOffset(1, err).Should(BeNil(), "Cannot retrieve pod host IPs")
		if expectPodIP {
			podIPs, err = kubectl.GetPodsIPs(namespace, label)
			ExpectWithOffset(1, err).Should(BeNil(), "Cannot retrieve pod IPs")
		}
	}

	for _, pod := range pods {
		By("Making ten curl requests from %q to %q", pod, outsideURL)

		hostIP := hostIPs[pod]
		podIP := podIPs[pod]

		if expectPodIP {
			// Make pods reachable from the host which doesn't run Cilium
			kubectl.AddIPRoute(helpers.GetNodeWithoutCilium(), podIP, hostIP, false).
				ExpectSuccess("Failed to add ip route")
			defer func() {
				kubectl.DelIPRoute(helpers.GetNodeWithoutCilium(), podIP, hostIP).
					ExpectSuccess("Failed to del ip route")
			}()
		}

		for i := 1; i <= 10; i++ {
			res := kubectl.ExecPodCmd(namespace, pod, cmd)
			ExpectWithOffset(1, res).Should(helpers.CMDSuccess(),
				"Pod %q can not connect to %q", pod, outsideURL)

			if expectNodeIP || expectPodIP {
				// Parse the IPs to avoid issues with 4-in-6 formats
				sourceIP := net.ParseIP(strings.TrimSpace(
					strings.Split(res.Stdout(), "=")[1])).String()
				if expectNodeIP {
					Expect(sourceIP).To(Equal(hostIP), "Expected node IP")
				}
				if expectPodIP {
					Expect(sourceIP).To(Equal(podIP), "Expected pod IP")
				}
			}
		}
	}

	return true
}

func testPodNetperf(kubectl *helpers.Kubectl, namespace string, requireMultiNode bool, callOffset int, test helpers.PerfTest) (bool, string) {
	netperfOptions := "-l 30 -I 99,99"
	callOffset++

	By("Checking pod netperf")

	dstPod, dstPodJSON := fetchPodsWithOffset(kubectl, namespace, "client", NetperfPods.LabelSelector, "", requireMultiNode, callOffset)
	dstHost, err := dstPodJSON.Filter("{.status.hostIP}")
	ExpectWithOffset(callOffset, err).Should(BeNil(), "Failure to retrieve host of pod %s", dstPod)

	podIP, err := dstPodJSON.Filter("{.status.podIP}")
	targetIP := podIP.String()

	srcPod, _ := fetchPodsWithOffset(kubectl, namespace, "server", "zgroup=testDSClient", dstHost.String(), requireMultiNode, callOffset)
	ExpectWithOffset(callOffset, err).Should(BeNil(), "Failure to retrieve IP of pod %s", srcPod)

	// Netperf benchmark test
	res := kubectl.ExecPodCmd(namespace, srcPod, helpers.Netperf(targetIP, test, netperfOptions))
	return res.WasSuccessful(), targetIP
}

func monitorConnectivityAcrossNodes(kubectl *helpers.Kubectl) (monitorRes *helpers.CmdRes, monitorCancel func(), targetIP string) {
	requireMultinode := config.CiliumTestConfig.Multinode
	if !config.CiliumTestConfig.Multinode {
		By("Performing multinode connectivity check within a single node")
	}

	ciliumPodK8s1, err := kubectl.GetCiliumPodOnNode(helpers.K8s1)
	ExpectWithOffset(1, err).Should(BeNil(), "Cannot get cilium pod on k8s1")

	By(fmt.Sprintf("Launching cilium monitor on %q", ciliumPodK8s1))
	monitorRes, monitorCancel = kubectl.MonitorStart(ciliumPodK8s1)
	result, targetIP := testPodConnectivityAndReturnIP(kubectl, requireMultinode, 2)
	ExpectWithOffset(1, result).Should(BeTrue(), "Connectivity test between nodes failed")

	return monitorRes, monitorCancel, targetIP
}

func checkMonitorOutput(monitorOutput []byte, egressPktCount, ingressPktCount int) bool {
	// Multiple connection attempts may be made, we need to
	// narrow down to the last connection close, then match
	// the ephemeral port + flags to ensure that the
	// notifications match the table above.
	egressTCPExpr := `TCP.*DstPort=80.*FIN=true`
	egressTCPRegex := regexp.MustCompile(egressTCPExpr)
	egressTCPMatches := egressTCPRegex.FindAll(monitorOutput, -1)
	if len(egressTCPMatches) <= 0 {
		GinkgoPrint("Could not locate final FIN notification in monitor log: egressTCPMatches %+v", egressTCPMatches)
		return false
	}
	finalMatch := egressTCPMatches[len(egressTCPMatches)-1]
	portRegex := regexp.MustCompile(`SrcPort=([0-9]*)`)
	// FindSubmatch should return ["SrcPort=12345" "12345"]
	portBytes := portRegex.FindSubmatch(finalMatch)[1]

	By("Looking for TCP notifications using the ephemeral port %q", portBytes)
	port, err := strconv.Atoi(string(portBytes))
	if err != nil {
		GinkgoPrint("ephemeral port %q could not be converted to integer: %s", string(portBytes), err)
		return false
	}

	expEgress := fmt.Sprintf("SrcPort=%d", port)
	expEgressRegex := regexp.MustCompile(expEgress)
	egressMatches := expEgressRegex.FindAllIndex(monitorOutput, -1)
	if len(egressMatches) != egressPktCount {
		GinkgoPrint("Could not locate final FIN notification in monitor log: egressTCPMatches %+v", egressTCPMatches)
		return false
	}

	expIngress := fmt.Sprintf("DstPort=%d", port)
	expIngressRegex := regexp.MustCompile(expIngress)
	ingressMatches := expIngressRegex.FindAllIndex(monitorOutput, -1)
	if len(ingressMatches) != ingressPktCount {
		GinkgoPrint("Monitor log contained unexpected number of ingress notifications matching %q", expIngress)
		return false
	}

	return true
}

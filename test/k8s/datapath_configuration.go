// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package k8sTest

import (
	"context"
	"fmt"
	"net"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	. "github.com/onsi/gomega"

	"github.com/cilium/cilium/pkg/defaults"
	"github.com/cilium/cilium/test/config"
	. "github.com/cilium/cilium/test/ginkgo-ext"
	"github.com/cilium/cilium/test/helpers"
)

var _ = Describe("K8sDatapathConfig", func() {
	const (
		bpffsDir string = defaults.BPFFSRoot + "/" + defaults.TCGlobalsPath + "/"
	)

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
		ExpectAllPodsTerminated(kubectl)
	})

	AfterFailed(func() {
		kubectl.CiliumReport("cilium-dbg status", "cilium-dbg endpoint list")
	})

	AfterAll(func() {
		kubectl.ScaleDownDNS()
		ExpectAllPodsTerminated(kubectl)
		deploymentManager.DeleteCilium()
		kubectl.ScaleUpDNS()
		kubectl.CloseSSHClient()
	})

	JustAfterEach(func() {
		kubectl.ValidateNoErrorsInLogs(CurrentGinkgoTestDescription().Duration)
	})

	Context("MonitorAggregation", func() {
		It("Checks that monitor aggregation restricts notifications", func() {
			deploymentManager.DeployCilium(map[string]string{
				"bpf.monitorAggregation": "medium",
				"bpf.monitorInterval":    "60s",
				"bpf.monitorFlags":       "syn",
				// Need to disable the host firewall for now due to complexity issue.
				// See #14552 for details.
				"hostFirewall.enabled": "false",
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
			Eventually(func() error {
				monitorOutput = monitorRes.CombineOutput().Bytes()
				return checkMonitorOutput(monitorOutput, egressPktCount, ingressPktCount)
			}, helpers.HelperTimeout, time.Second).Should(BeNil(), "Monitor log did not contain %d ingress and %d egress TCP notifications\n%s",
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
			Eventually(func() error {
				monitorOutput = monitorRes.CombineOutput().Bytes()
				return checkMonitorOutput(monitorOutput, egressPktCount, ingressPktCount)
			}, helpers.HelperTimeout, time.Second).Should(BeNil(), "monitor aggregation did not result in correct number of TCP notifications\n%s", monitorOutput)
			helpers.WriteToReportFile(monitorOutput, monitorLog)
		})
	})

	Context("Encapsulation", func() {
		var (
			tmpEchoPodPath    string
			outside, outside6 string
		)

		BeforeAll(func() {
			if helpers.ExistNodeWithoutCilium() && !helpers.SupportIPv6ToOutside() {
				// Deploy echoserver on the node which does not run Cilium to test
				// IPv6 connectivity to the outside world. The pod will run in
				// the host netns, so no CNI is required for the pod on that host.
				echoPodPath := helpers.ManifestGet(kubectl.BasePath(), "echoserver-hostnetns.yaml")
				res := kubectl.ExecMiddle("mktemp")
				res.ExpectSuccess()
				tmpEchoPodPath = strings.Trim(res.Stdout(), "\n")
				kubectl.ExecMiddle(fmt.Sprintf("sed 's/NODE_WITHOUT_CILIUM/%s/' %s > %s",
					helpers.GetFirstNodeWithoutCilium(), echoPodPath, tmpEchoPodPath)).ExpectSuccess()
				kubectl.ApplyDefault(tmpEchoPodPath).ExpectSuccess("Cannot install echoserver application")
				Expect(kubectl.WaitforPods(helpers.DefaultNamespace, "-l name=echoserver-hostnetns",
					helpers.HelperTimeout)).Should(BeNil())
				var err error
				outside, err = kubectl.GetNodeIPByLabel(kubectl.GetFirstNodeWithoutCiliumLabel(), false)
				Expect(err).Should(BeNil())
				outside6, err = kubectl.GetNodeIPv6ByLabel(kubectl.GetFirstNodeWithoutCiliumLabel(), false)
				Expect(err).Should(BeNil())
				outside6 = net.JoinHostPort(outside6, "80")
			} else {
				outside = "http://google.com"
				outside6 = "http://google.com"
			}
		})

		AfterAll(func() {
			if tmpEchoPodPath != "" {
				kubectl.Delete(tmpEchoPodPath)
			}
		})

		enableVXLANTunneling := func(options map[string]string) {
			options["tunnelProtocol"] = "vxlan"
			if helpers.RunsOnGKE() {
				// We need to disable gke.enabled as it disables tunneling.
				options["gke.enabled"] = "false"
				options["endpointRoutes.enabled"] = "true"
			}
		}

		It("Check iptables masquerading with random-fully", func() {
			options := map[string]string{
				"bpf.masquerade":       "false",
				"enableIPv6Masquerade": "true",
				"iptablesRandomFully":  "true",
			}
			enableVXLANTunneling(options)
			deploymentManager.DeployCilium(options, DeployCiliumOptionsAndDNS)
			Expect(testPodConnectivityAcrossNodes(kubectl)).Should(BeTrue(), "Connectivity test between nodes failed")

			By("Test iptables masquerading")
			Expect(testPodHTTPToOutside(kubectl, outside, false, false, false)).
				Should(BeTrue(), "IPv4 connectivity test to %s", outside)
			if helpers.ExistNodeWithoutCilium() || helpers.SupportIPv6ToOutside() {
				Expect(testPodHTTPToOutside(kubectl, outside6, false, false, true)).
					Should(BeTrue(), "IPv6 connectivity test to %s failed", outside6)
			}
		})
	})

	SkipContextIf(func() bool {
		return helpers.RunsWithKubeProxyReplacement() || helpers.GetCurrentIntegration() != ""
	}, "IPv6 masquerading", func() {
		var (
			k8s1EndpointIPs map[string]string
			testDSK8s1IPv6  string = "fd03::310"

			demoYAML string
		)

		BeforeAll(func() {
			deploymentManager.DeployCilium(map[string]string{
				"routingMode":           "native",
				"autoDirectNodeRoutes":  "true",
				"ipv6NativeRoutingCIDR": helpers.IPv6NativeRoutingCIDR,
			}, DeployCiliumOptionsAndDNS)

			demoYAML = helpers.ManifestGet(kubectl.BasePath(), "demo_ds.yaml")
			res := kubectl.ApplyDefault(demoYAML)
			Expect(res).Should(helpers.CMDSuccess(), "Unable to apply %s", demoYAML)
			waitPodsDs(kubectl, []string{testDS, testDSClient, testDSK8s2})

			pod, err := kubectl.GetCiliumPodOnNode(helpers.K8s1)
			Expect(err).Should(BeNil(), "Cannot get cilium pod on node %s", helpers.K8s1)
			k8s1EndpointIPs = kubectl.CiliumEndpointIPv6(pod, "-l k8s:zgroup=testDS,k8s:io.kubernetes.pod.namespace=default")

			k8s1Backends := []string{}
			for _, epIP := range k8s1EndpointIPs {
				k8s1Backends = append(k8s1Backends, net.JoinHostPort(epIP, "80"))
			}

			ciliumAddService(kubectl, 31080, net.JoinHostPort(testDSK8s1IPv6, "80"), k8s1Backends, "ClusterIP", "Cluster")
		})

		It("across K8s nodes, skipped due to native routing CIDR", func() {
			// Because a native routing CIDR is set, the
			// IPv6 for packets routed to another node are
			// _not_ masqueraded. Retrieve the address for
			// the client, and make sure the echo server
			// receives it unchanged.
			pod, err := kubectl.GetCiliumPodOnNode(helpers.K8s2)
			Expect(err).Should(BeNil(), "Cannot get cilium pod on node %s", helpers.K8s2)
			k8s2EndpointIPs := kubectl.CiliumEndpointIPv6(pod, fmt.Sprintf("-l k8s:%s,k8s:io.kubernetes.pod.namespace=default", testDSK8s2))
			k8s2ClientIPv6 := ""
			for _, epIP := range k8s2EndpointIPs {
				k8s2ClientIPv6 = epIP
				break
			}
			Expect(k8s2ClientIPv6).ShouldNot(BeEmpty(), "Cannot get client IPv6")

			url := fmt.Sprintf(`"http://[%s]:80/"`, testDSK8s1IPv6)
			testCurlFromPodWithSourceIPCheck(kubectl, testDSK8s2, url, 5, k8s2ClientIPv6)

			for _, epIP := range k8s1EndpointIPs {
				url = fmt.Sprintf(`"http://[%s]:80/"`, epIP)
				testCurlFromPodWithSourceIPCheck(kubectl, testDSK8s2, url, 5, k8s2ClientIPv6)
			}
		})

		// Note: At the time we add the test below, it does not
		// run on the CI because the only job which is running
		// with a 3rd, non-K8s node (net-next) also has KPR,
		// and skips the context we're in. Run locally.
		// TODO: uncomment once the above has changed
		//SkipItIf(helpers.DoesNotExistNodeWithoutCilium, "for external traffic", func() {
		//	// A native routing CIDR is set, but it does
		//	// not prevent masquerading for packets going
		//	// outside of the K8s cluster. Check that the
		//	// echo server sees the IPv6 address of the
		//	// client's node.
		//	url := fmt.Sprintf(`"http://[%s]:80/"`, ni.outsideIPv6)
		//	testCurlFromPodWithSourceIPCheck(kubectl, testDSK8s2, url, 5, ni.primaryK8s2IPv6)

		//	for _, epIP := range k8s1EndpointIPs {
		//		url = fmt.Sprintf(`"http://[%s]:80/"`, epIP)
		//		testCurlFromPodWithSourceIPCheck(kubectl, testDSK8s2, url, 5, ni.primaryK8s2IPv6)
		//	}
		//})

		AfterAll(func() {
			ciliumDelService(kubectl, 31080)
			_ = kubectl.Delete(demoYAML)
		})
	})

	SkipContextIf(func() bool {
		return helpers.DoesNotExistNodeWithoutCilium() || helpers.DoesNotRunOn419OrLaterKernel()
	}, "Check BPF masquerading with ip-masq-agent", func() {
		var (
			tmpEchoPodPath string
			nodeIP         string
		)

		BeforeAll(func() {
			// Deploy echoserver on the node which does not run Cilium to test
			// BPF masquerading. The pod will run in the host netns, so no CNI
			// is required for the pod on that host.
			echoPodPath := helpers.ManifestGet(kubectl.BasePath(), "echoserver-hostnetns.yaml")
			res := kubectl.ExecMiddle("mktemp")
			res.ExpectSuccess()
			tmpEchoPodPath = strings.Trim(res.Stdout(), "\n")
			kubectl.ExecMiddle(fmt.Sprintf("sed 's/NODE_WITHOUT_CILIUM/%s/' %s > %s",
				helpers.GetFirstNodeWithoutCilium(), echoPodPath, tmpEchoPodPath)).ExpectSuccess()
			kubectl.ApplyDefault(tmpEchoPodPath).ExpectSuccess("Cannot install echoserver application")
			Expect(kubectl.WaitforPods(helpers.DefaultNamespace, "-l name=echoserver-hostnetns",
				helpers.HelperTimeout)).Should(BeNil())
			var err error
			nodeIP, err = kubectl.GetNodeIPByLabel(kubectl.GetFirstNodeWithoutCiliumLabel(), false)
			Expect(err).Should(BeNil())
		})

		AfterAll(func() {
			if tmpEchoPodPath != "" {
				kubectl.Delete(tmpEchoPodPath)
			}
		})

		testIPMasqAgent := func() {
			Expect(testPodHTTPToOutside(kubectl,
				fmt.Sprintf("http://%s:80", nodeIP), false, true, false)).Should(BeTrue(),
				"IPv4 Connectivity test to http://%s failed", nodeIP)

			// remove nonMasqueradeCIDRs from the ConfigMap
			kubectl.Patch(helpers.CiliumNamespace, "configMap", "ip-masq-agent", `{"data":{"config":"{\"nonMasqueradeCIDRs\":[]}"}}`)
			// Wait until the ip-masq-agent config update is handled by the agent
			time.Sleep(90 * time.Second)

			// Check that requests to the echoserver from client pods are masqueraded.
			Expect(testPodHTTPToOutside(kubectl,
				fmt.Sprintf("http://%s:80", nodeIP), true, false, false)).Should(BeTrue(),
				"IPv4 Connectivity test to http://%s failed", nodeIP)

			Expect(testPodHTTPToOutside(kubectl,
				fmt.Sprintf("http://%s:80", nodeIP), true, false, true)).Should(BeTrue(),
				"IPv6 Connectivity test to http://%s failed", nodeIP)
		}

		It("DirectRouting", func() {
			deploymentManager.DeployCilium(map[string]string{
				"ipMasqAgent.enabled":                   "true",
				"routingMode":                           "native",
				"autoDirectNodeRoutes":                  "true",
				"ipMasqAgent.config.nonMasqueradeCIDRs": fmt.Sprintf("{%s/32}", nodeIP),
			}, DeployCiliumOptionsAndDNS)

			testIPMasqAgent()
		})

		It("DirectRouting, IPv4 only", func() {
			deploymentManager.DeployCilium(map[string]string{
				"ipMasqAgent.enabled":                   "true",
				"routingMode":                           "native",
				"autoDirectNodeRoutes":                  "true",
				"ipMasqAgent.config.nonMasqueradeCIDRs": fmt.Sprintf("{%s/32}", nodeIP),
				"ipv6.enabled":                          "false",
			}, DeployCiliumOptionsAndDNS)

			testIPMasqAgent()
		})

		It("VXLAN", func() {
			deploymentManager.DeployCilium(map[string]string{
				"ipMasqAgent.enabled":                   "true",
				"tunnelProtocol":                        "vxlan",
				"ipMasqAgent.config.nonMasqueradeCIDRs": fmt.Sprintf("{%s/32}", nodeIP),
			}, DeployCiliumOptionsAndDNS)

			testIPMasqAgent()
		})
	})

	SkipContextIf(helpers.DoesNotRunOnNetNextKernel, "WireGuard encryption strict mode", func() {
		BeforeAll(func() {
			kubectl.DeleteResource("ciliumnode", "--all --wait")
		})
		AfterEach(func() {
			kubectl.DeleteResource("ciliumnode", "--all --wait")
		})

		testStrictWireguard := func(interNodeDev string) {
			// Disable the Cilium operator
			// In combination with the used CES option, this will stop any
			// endpoint propagation to other nodes.
			kubectl.SetCiliumOperatorReplicas(0)
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

			// Fetch svc IP
			dsSvcJSON := kubectl.Get(randomNamespace, "svc testds-service -o json")
			dsSvcIP, err := dsSvcJSON.Filter("{.spec.clusterIP}")
			ExpectWithOffset(1, err).Should(BeNil(), "Failure to retrieve IP of service testds-service")

			checkNoLeakP2P := func(srcPod, srcIP, dstIP string, shouldBeSuccessful bool) {
				cmd := fmt.Sprintf("tcpdump -vv -i %s --immediate-mode -n 'host %s and host %s' -c 1", interNodeDev, srcIP, dstIP)
				res1, cancel1, err := kubectl.ExecInHostNetNSInBackground(context.TODO(), k8s1NodeName, cmd)
				ExpectWithOffset(2, err).Should(BeNil(), "Cannot exec tcpdump in bg")
				res2, cancel2, err := kubectl.ExecInHostNetNSInBackground(context.TODO(), k8s2NodeName, cmd)
				ExpectWithOffset(2, err).Should(BeNil(), "Cannot exec tcpdump in bg")

				// HTTP connectivity test (pod2pod)

				cmdRes := kubectl.ExecPodCmd(randomNamespace, srcPod, helpers.CurlFail("http://%s/", net.JoinHostPort(dstIP, "80")))
				if shouldBeSuccessful {
					cmdRes.ExpectSuccess("Failed to curl dst pod")
				} else {
					cmdRes.ExpectFail("Should not be able to curl dst pod")
				}

				// Check that no unencrypted pod2pod traffic was captured on the direct routing device
				cancel1()
				cancel2()
				ExpectWithOffset(2, res1.CombineOutput().String()).Should(Not(ContainSubstring("1 packet captured")))
				ExpectWithOffset(2, res2.CombineOutput().String()).Should(Not(ContainSubstring("1 packet captured")))
			}

			checkNoLeakP2RemoteService := func(srcPod, dstPod, srcIP, dstService string, shouldBeSuccessful bool) {
				cmd := fmt.Sprintf("tcpdump -vv -i %s --immediate-mode -n 'src %s or dst %s' -c 1", interNodeDev, srcIP, srcIP)
				res1, cancel1, err := kubectl.ExecInHostNetNSInBackground(context.TODO(), k8s1NodeName, cmd)
				ExpectWithOffset(2, err).Should(BeNil(), "Cannot exec tcpdump in bg")
				res2, cancel2, err := kubectl.ExecInHostNetNSInBackground(context.TODO(), k8s2NodeName, cmd)
				ExpectWithOffset(2, err).Should(BeNil(), "Cannot exec tcpdump in bg")

				// HTTP connectivity test (pod2pod)

				cmdRes, err := kubectl.ExecUntilMatch(randomNamespace, srcPod, helpers.CurlTimeout("http://%s/", time.Second, net.JoinHostPort(dstService, "80")), dstPod)
				if shouldBeSuccessful {
					cmdRes.ExpectSuccess("Failed to curl svc on dst pod")
					ExpectWithOffset(2, err).Should(BeNil(), "Failed to curl svc on dst pod")
				} else {
					ExpectWithOffset(2, err).ShouldNot(BeNil(), "Should not be able to curl svc on dst pod")
				}

				// Check that no unencrypted pod2pod traffic was captured on the direct routing device
				cancel1()
				cancel2()
				ExpectWithOffset(2, res1.CombineOutput().String()).Should(Not(ContainSubstring("1 packet captured")))
				ExpectWithOffset(2, res2.CombineOutput().String()).Should(Not(ContainSubstring("1 packet captured")))
			}

			checkNoLeakP2P(srcPod, srcPodIP.String(), dstPodIP.String(), false)
			checkNoLeakP2RemoteService(srcPod, dstPod, srcPodIP.String(), dsSvcIP.String(), false)

			// Check that the src pod can reach the remote host
			kubectl.ExecPodCmd(randomNamespace, srcPod, helpers.Ping(k8s2IP)).
				ExpectSuccess("Failed to ping k8s2 host from src pod")

			// Check that the remote host can reach the dst pod
			kubectl.ExecInHostNetNS(context.TODO(), k8s1NodeName,
				helpers.CurlFail("http://%s:80/", dstPodIP)).ExpectSuccess("Failed to curl dst pod from k8s1")

			// Re-enable operator so that all endpoints are eventually updated
			kubectl.SetCiliumOperatorReplicas(2)

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
			waitForAllowedIP(ciliumPodK8s2, fmt.Sprintf("%s/32", srcPodIP))

			checkNoLeakP2P(srcPod, srcPodIP.String(), dstPodIP.String(), true)

			checkNoLeakP2RemoteService(srcPod, dstPod, srcPodIP.String(), dsSvcIP.String(), true)
		}

		It("Pod-to-pod traffic is encrypted in native routing mode with per-endpoint routes", func() {
			deploymentManager.DeployCilium(map[string]string{
				"tunnel":                 "disabled",
				"autoDirectNodeRoutes":   "true",
				"ipv4NativeRoutingCIDR":  "10.244.0.0/16",
				"ipv6.enabled":           "false",
				"endpointRoutes.enabled": "true",
				"encryption.enabled":     "true",
				"encryption.type":        "wireguard",
				"l7Proxy":                "false",
				"ipam.operator.clusterPoolIPv4PodCIDRList": "10.244.0.0/16",
				"encryption.strictMode.enabled":            "true",
				"encryption.strictMode.cidr":               "10.244.0.0/16",
			}, DeployCiliumOptionsAndDNS)

			privateIface, err := kubectl.GetPrivateIface(helpers.K8s1)
			Expect(err).Should(BeNil(), "Cannot determine private iface")
			testStrictWireguard(privateIface)
		})
		It("Pod-to-pod traffic is encrypted in native routing mode with per-endpoint routes and overlapping node and pod CIDRs", func() {
			deploymentManager.DeployCilium(map[string]string{
				"tunnel":                 "disabled",
				"autoDirectNodeRoutes":   "true",
				"ipv4NativeRoutingCIDR":  "192.168.56.0/24",
				"ipv6.enabled":           "false",
				"endpointRoutes.enabled": "true",
				"encryption.enabled":     "true",
				"encryption.type":        "wireguard",
				"l7Proxy":                "false",
				"ipam.operator.clusterPoolIPv4PodCIDRList":        "192.168.56.128/25",
				"ipam.operator.clusterPoolIPv4MaskSize":           "26",
				"encryption.strictMode.enabled":                   "true",
				"encryption.strictMode.cidr":                      "192.168.56.0/24",
				"encryption.strictMode.allowRemoteNodeIdentities": "true",
			}, DeployCiliumOptionsAndDNS)

			privateIface, err := kubectl.GetPrivateIface(helpers.K8s1)
			Expect(err).Should(BeNil(), "Cannot determine private iface")
			testStrictWireguard(privateIface)
		})
	})

	SkipContextIf(func() bool {
		return helpers.RunsOnGKE() || helpers.RunsWithoutKubeProxy() || helpers.RunsOnAKS()
	}, "Transparent encryption DirectRouting", func() {
		var privateIface string
		BeforeAll(func() {
			Eventually(func() (string, error) {
				iface, err := kubectl.GetPrivateIface(helpers.K8s1)
				privateIface = iface
				return iface, err
			}, helpers.MidCommandTimeout, time.Second).ShouldNot(BeEmpty(),
				"Unable to determine private iface")
		})
		SkipItIf(helpers.RunsWithoutKubeProxy, "Check connectivity with transparent encryption and direct routing with bpf_host", func() {
			defaultIface, err := kubectl.GetDefaultIface(false)
			Expect(err).Should(BeNil(), "Unable to determine the default interface")
			devices := fmt.Sprintf(`'{%s,%s}'`, privateIface, defaultIface)

			deploymentManager.Deploy(helpers.CiliumNamespace, IPSecSecret)
			deploymentManager.DeployCilium(map[string]string{
				"routingMode":                "native",
				"autoDirectNodeRoutes":       "true",
				"encryption.enabled":         "true",
				"encryption.ipsec.interface": privateIface,
				"devices":                    devices,
				"hostFirewall.enabled":       "false",
				"kubeProxyReplacement":       "disabled",
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

			// Need to install Cilium w/ host fw prior to the host policy preparation
			// step.
			options := map[string]string{
				"hostFirewall.enabled": "true",
			}
			if helpers.RunsWithKubeProxyReplacement() {
				// BPF IPv6 masquerade not currently supported with host firewall - GH-26074
				options["enableIPv6Masquerade"] = "false"
			}
			deploymentManager.DeployCilium(options, DeployCiliumOptionsAndDNS)

			hostPolicy := helpers.ManifestGet(kubectl.BasePath(), "host-policies.yaml")
			prepareHostPolicyEnforcement(kubectl, hostPolicy)
		})

		AfterAll(func() {
			kubectl.Exec("kubectl label nodes --all status-")
		})

		SkipItIf(func() bool {
			return !helpers.IsIntegration(helpers.CIIntegrationGKE)
		}, "Check connectivity with IPv6 disabled", func() {
			deploymentManager.DeployCilium(map[string]string{
				"ipv4.enabled":         "true",
				"ipv6.enabled":         "false",
				"hostFirewall.enabled": "true",
			}, DeployCiliumOptionsAndDNS)
			Expect(testPodConnectivityAcrossNodes(kubectl)).Should(BeTrue(), "Connectivity test between nodes failed")
		})

		SkipItIf(helpers.RunsOnAKS, "With VXLAN", func() {
			options := map[string]string{
				"hostFirewall.enabled": "true",
			}
			if helpers.RunsOnGKE() {
				options["gke.enabled"] = "false"
				options["tunnelProtocol"] = "vxlan"
			}
			if helpers.RunsWithKubeProxyReplacement() {
				// BPF IPv6 masquerade not currently supported with host firewall - GH-26074
				options["enableIPv6Masquerade"] = "false"
			}
			deploymentManager.DeployCilium(options, DeployCiliumOptionsAndDNS)
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
			if helpers.RunsWithKubeProxyReplacement() {
				// BPF IPv6 masquerade not currently supported with host firewall - GH-26074
				options["enableIPv6Masquerade"] = "false"
			}
			deploymentManager.DeployCilium(options, DeployCiliumOptionsAndDNS)
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
			if helpers.RunsWithKubeProxyReplacement() {
				// BPF IPv6 masquerade not currently supported with host firewall - GH-26074
				options["enableIPv6Masquerade"] = "false"
			}
			deploymentManager.DeployCilium(options, DeployCiliumOptionsAndDNS)
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
			if helpers.RunsWithKubeProxyReplacement() {
				// BPF IPv6 masquerade not currently supported with host firewall - GH-26074
				options["enableIPv6Masquerade"] = "false"
			}
			deploymentManager.DeployCilium(options, DeployCiliumOptionsAndDNS)
			deploymentManager.DeployCilium(options, DeployCiliumOptionsAndDNS)
			testHostFirewall(kubectl)
		})
	})

	SkipContextIf(func() bool {
		return helpers.SkipQuarantined() || helpers.DoesNotRunOnNetNextKernel()
	}, "High-scale IPcache", func() {
		const hsIPcacheFile = "high-scale-ipcache.yaml"

		AfterEach(func() {
			hsIPcacheYAML := helpers.ManifestGet(kubectl.BasePath(), hsIPcacheFile)
			_ = kubectl.Delete(hsIPcacheYAML)
		})

		testHighScaleIPcache := func(tunnelProto string, epRoutesConfig string) {
			options := map[string]string{
				"highScaleIPcache.enabled":    "true",
				"routingMode":                 "native",
				"bpf.monitorAggregation":      "none",
				"ipv6.enabled":                "false",
				"wellKnownIdentities.enabled": "true",
				"tunnelProtocol":              tunnelProto,
				"endpointRoutes.enabled":      epRoutesConfig,
			}
			if !helpers.RunsOnGKE() {
				options["autoDirectNodeRoutes"] = "true"
			}
			if helpers.RunsWithKubeProxy() {
				options["kubeProxyReplacement"] = "disabled"
			}
			deploymentManager.DeployCilium(options, DeployCiliumOptionsAndDNS)

			cmd := fmt.Sprintf("bpftool map update pinned %scilium_world_cidrs4 key 0 0 0 0 0 0 0 0 value 1", bpffsDir)
			kubectl.CiliumExecMustSucceedOnAll(context.TODO(), cmd)

			hsIPcacheYAML := helpers.ManifestGet(kubectl.BasePath(), hsIPcacheFile)
			kubectl.Create(hsIPcacheYAML).ExpectSuccess("Unable to create resource %q", hsIPcacheYAML)

			// We need a longer timeout here because of the larger number of
			// pods that need to be deployed.
			err := kubectl.WaitforPods(helpers.DefaultNamespace, "-l type=client", 2*helpers.HelperTimeout)
			Expect(err).ToNot(HaveOccurred(), "Client pods not ready after timeout")
		}

		It("Test ingress policy enforcement with VXLAN and no endpoint routes", func() {
			testHighScaleIPcache("vxlan", "false")
		})

		It("Test ingress policy enforcement with GENEVE and endpoint routes", func() {
			testHighScaleIPcache("geneve", "true")
		})
	})

	Context("Iptables", func() {
		SkipItIf(func() bool {
			return helpers.IsIntegration(helpers.CIIntegrationGKE) || helpers.DoesNotRunWithKubeProxyReplacement()
		}, "Skip conntrack for pod traffic", func() {
			deploymentManager.DeployCilium(map[string]string{
				"routingMode":                     "native",
				"autoDirectNodeRoutes":            "true",
				"installNoConntrackIptablesRules": "true",
			}, DeployCiliumOptionsAndDNS)

			ciliumPod, err := kubectl.GetCiliumPodOnNode(helpers.K8s1)
			ExpectWithOffset(1, err).Should(BeNil(), "Unable to determine cilium pod on node %s", helpers.K8s1)

			_, err = kubectl.ExecInHostNetNSByLabel(context.TODO(), helpers.K8s1, "conntrack -F")
			if err != nil {
				ExpectWithOffset(1, err).Should(BeNil(), "Cannot flush conntrack table")
			}

			Expect(testPodConnectivityAcrossNodes(kubectl)).Should(BeTrue(), "Connectivity test between nodes failed")

			cmd := fmt.Sprintf("iptables -w 60 -t raw -C CILIUM_PRE_raw -s %s -m comment --comment 'cilium: NOTRACK for pod traffic' -j CT --notrack", helpers.IPv4NativeRoutingCIDR)
			res := kubectl.ExecPodCmd(helpers.CiliumNamespace, ciliumPod, cmd)
			res.ExpectSuccess("Missing '-j CT --notrack' iptables rule")

			cmd = fmt.Sprintf("iptables -w 60 -t raw -C CILIUM_PRE_raw -d %s -m comment --comment 'cilium: NOTRACK for pod traffic' -j CT --notrack", helpers.IPv4NativeRoutingCIDR)
			res = kubectl.ExecPodCmd(helpers.CiliumNamespace, ciliumPod, cmd)
			res.ExpectSuccess("Missing '-j CT --notrack' iptables rule")

			cmd = fmt.Sprintf("iptables -w 60 -t raw -C CILIUM_OUTPUT_raw -s %s -m comment --comment 'cilium: NOTRACK for pod traffic' -j CT --notrack", helpers.IPv4NativeRoutingCIDR)
			res = kubectl.ExecPodCmd(helpers.CiliumNamespace, ciliumPod, cmd)
			res.ExpectSuccess("Missing '-j CT --notrack' iptables rule")

			cmd = fmt.Sprintf("iptables -w 60 -t raw -C CILIUM_OUTPUT_raw -d %s -m comment --comment 'cilium: NOTRACK for pod traffic' -j CT --notrack", helpers.IPv4NativeRoutingCIDR)
			res = kubectl.ExecPodCmd(helpers.CiliumNamespace, ciliumPod, cmd)
			res.ExpectSuccess("Missing '-j CT --notrack' iptables rule")

			cmd = fmt.Sprintf("conntrack -L -s %s -d %s | wc -l", helpers.IPv4NativeRoutingCIDR, helpers.IPv4NativeRoutingCIDR)
			resStr, err := kubectl.ExecInHostNetNSByLabel(context.TODO(), helpers.K8s1, cmd)
			if err != nil {
				ExpectWithOffset(1, err).Should(BeNil(), "Cannot list conntrack entries")
			}
			Expect(strings.TrimSpace(resStr)).To(Equal("0"), "Unexpected conntrack entries")
		})
	})
})

// To avoid flakes, we need to perform some prep work before we enable host
// policy enforcement.
//
// When we first enable the host firewall, Cilium will for the first time track
// all hostns connections on all nodes. Because those connections are already
// established, the first packet we see from them may be a reply packet. For
// that reason, it's possible for Cilium to create conntrack entries in the
// wrong direction. As a consequence, once host policies are enforced, we will
// allow the forward path through and enforce policies on replies.
// For example, consider a connection to the kube-apiserver, a:52483 -> b:6443.
// If the first packet we track is the SYN+ACK, we will create a conntrack
// entry TCP OUT b:6443 -> a:52483. All traffic a:52483 -> b:6443 will be
// considered reply traffic and we will enforce policies on b:6443 -> a:52483.
// If there are any L4 policy rules, this 52483 destination port is unlikely to
// be allowed through.
//
// That situation unfortunately doesn't resolve on its own because Linux will
// consider the connections to be in LAST-ACK state on the server side and will
// keep them around indefinitely.
//
// To fix that, we need to force the termination of those connections. One way
// to do that is to enforce policies just long enough that all such connections
// will end up in a closing state (LAST-ACK or TIME-WAIT). Once that is the
// case, we remove the policies to allow everything through and enable proper
// termination of those connections.
// This function implements that process.
func prepareHostPolicyEnforcement(kubectl *helpers.Kubectl, policy string) {
	By(fmt.Sprintf("Applying policies %s for 1min", policy))
	_, err := kubectl.CiliumClusterwidePolicyAction(policy, helpers.KubectlApply, helpers.HelperTimeout)
	ExpectWithOffset(1, err).Should(BeNil(), fmt.Sprintf("Error creating resource %s: %s", policy, err))

	time.Sleep(1 * time.Minute)

	_, err = kubectl.CiliumClusterwidePolicyAction(policy, helpers.KubectlDelete, helpers.HelperTimeout)
	ExpectWithOffset(1, err).Should(BeNil(), fmt.Sprintf("Error deleting resource %s: %s", policy, err))

	By("Deleted the policies, waiting for connection terminations")
	time.Sleep(30 * time.Second)
}

func testHostFirewall(kubectl *helpers.Kubectl) {
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

func applyL3Policy(kubectl *helpers.Kubectl, ns string) (withdrawPolicy func()) {
	demoPolicyL3 := helpers.ManifestGet(kubectl.BasePath(), "l3-policy-demo.yaml")
	By(fmt.Sprintf("Applying policy %s", demoPolicyL3))
	_, err := kubectl.CiliumPolicyAction(ns, demoPolicyL3, helpers.KubectlApply, helpers.HelperTimeout)
	ExpectWithOffset(1, err).Should(BeNil(), fmt.Sprintf("Error creating resource %s: %s", demoPolicyL3, err))

	return func() {
		_, err := kubectl.CiliumPolicyAction(ns, demoPolicyL3, helpers.KubectlDelete, helpers.HelperTimeout)
		ExpectWithOffset(1, err).Should(BeNil(), fmt.Sprintf("Error deleting resource %s: %s", demoPolicyL3, err))
	}
}

func testPodConnectivityAndReturnIP(kubectl *helpers.Kubectl, requireMultiNode bool, callOffset int) (bool, string) {
	callOffset++

	randomNamespace := deploymentManager.DeployRandomNamespaceShared(DemoDaemonSet)
	withdrawPolicy := applyL3Policy(kubectl, randomNamespace)
	defer withdrawPolicy()
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

func testPodHTTPToOutside(kubectl *helpers.Kubectl, outsideURL string, expectNodeIP, expectPodIP, ipv6 bool) bool {
	var hostIPs map[string]string
	var podIPs map[string]string

	// IPv6 is not supported when the source IP should be checked. It could be
	// supported with more work, but it doesn't make sense as in those cases,
	// we can simply pass the IPv6 target address as outsideURL.
	if ipv6 && expectPodIP {
		panic("IPv6 not supported with source IP checking.")
	}

	namespace := deploymentManager.DeployRandomNamespaceShared(DemoDaemonSet)
	withdrawPolicy := applyL3Policy(kubectl, namespace)
	defer withdrawPolicy()
	deploymentManager.WaitUntilReady()

	label := "zgroup=testDSClient"
	pods, err := kubectl.GetPodNames(namespace, label)
	ExpectWithOffset(1, err).Should(BeNil(), "Cannot retrieve pod names by label %s", label)

	cmd := outsideURL
	if ipv6 {
		cmd = fmt.Sprintf("-6 %s", cmd)
	}
	cmd = helpers.CurlWithRetries(cmd, 10, true)

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
			kubectl.AddIPRoute(helpers.GetFirstNodeWithoutCilium(), podIP, hostIP, false).
				ExpectSuccess("Failed to add ip route")
			defer func() {
				kubectl.DelIPRoute(helpers.GetFirstNodeWithoutCilium(), podIP, hostIP).
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

func monitorConnectivityAcrossNodes(kubectl *helpers.Kubectl) (monitorRes *helpers.CmdRes, monitorCancel func(), targetIP string) {
	requireMultinode := config.CiliumTestConfig.Multinode
	if !config.CiliumTestConfig.Multinode {
		By("Performing multinode connectivity check within a single node")
	}

	ciliumPodK8s1, err := kubectl.GetCiliumPodOnNode(helpers.K8s1)
	ExpectWithOffset(1, err).Should(BeNil(), "Cannot get cilium pod on k8s1")

	By(fmt.Sprintf("Launching cilium-dbg monitor on %q", ciliumPodK8s1))
	monitorRes, monitorCancel = kubectl.MonitorStart(ciliumPodK8s1)
	result, targetIP := testPodConnectivityAndReturnIP(kubectl, requireMultinode, 2)
	ExpectWithOffset(1, result).Should(BeTrue(), "Connectivity test between nodes failed")

	return monitorRes, monitorCancel, targetIP
}

func checkMonitorOutput(monitorOutput []byte, egressPktCount, ingressPktCount int) error {
	// Multiple connection attempts may be made, we need to
	// narrow down to the last connection close, then match
	// the ephemeral port + flags to ensure that the
	// notifications match the table above.
	egressTCPExpr := `TCP.*DstPort=80.*FIN=true`
	egressTCPRegex := regexp.MustCompile(egressTCPExpr)
	egressTCPMatches := egressTCPRegex.FindAll(monitorOutput, -1)
	if len(egressTCPMatches) == 0 {
		return fmt.Errorf("could not locate TCP FIN in monitor log")
	}
	finalMatch := egressTCPMatches[len(egressTCPMatches)-1]
	portRegex := regexp.MustCompile(`SrcPort=([0-9]*)`)
	// FindSubmatch should return ["SrcPort=12345" "12345"]
	portBytes := portRegex.FindSubmatch(finalMatch)[1]

	By("Looking for TCP notifications using the ephemeral port %q", portBytes)
	port, err := strconv.Atoi(string(portBytes))
	if err != nil {
		return fmt.Errorf("ephemeral port %q could not be converted to integer: %s",
			string(portBytes), err)
	}

	expEgress := fmt.Sprintf("SrcPort=%d", port)
	expEgressRegex := regexp.MustCompile(expEgress)
	egressMatches := expEgressRegex.FindAllIndex(monitorOutput, -1)
	if len(egressMatches) != egressPktCount {
		return fmt.Errorf("monitor logs contained unexpected number (%d) of egress notifications matching %q",
			len(egressMatches), expEgress)
	}

	expIngress := fmt.Sprintf("DstPort=%d", port)
	expIngressRegex := regexp.MustCompile(expIngress)
	ingressMatches := expIngressRegex.FindAllIndex(monitorOutput, -1)
	if len(ingressMatches) != ingressPktCount {
		return fmt.Errorf("monitor log contained unexpected number (%d) of ingress notifications matching %q",
			len(ingressMatches), expIngress)
	}

	return nil
}

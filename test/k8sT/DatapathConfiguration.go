// Copyright 2017-2019 Authors of Cilium
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
	"io/ioutil"
	"regexp"
	"strconv"

	"github.com/cilium/cilium/test/config"
	. "github.com/cilium/cilium/test/ginkgo-ext"
	"github.com/cilium/cilium/test/helpers"

	. "github.com/onsi/gomega"
)

var _ = Describe("K8sDatapathConfig", func() {

	var kubectl *helpers.Kubectl
	var demoDSPath string
	var ipsecDSPath string
	var monitorLog = "monitor-aggregation.log"
	var ciliumFilename string

	BeforeAll(func() {
		kubectl = helpers.CreateKubectl(helpers.K8s1VMName(), logger)
		demoDSPath = helpers.ManifestGet(kubectl.BasePath(), "demo_ds.yaml")
		ipsecDSPath = helpers.ManifestGet(kubectl.BasePath(), "ipsec_ds.yaml")
		ciliumFilename = helpers.TimestampFilename("cilium.yaml")
	})

	BeforeEach(func() {
		kubectl.ApplyDefault(demoDSPath).ExpectSuccess("cannot install Demo application")
		kubectl.Apply(helpers.ApplyOptions{FilePath: ipsecDSPath, Namespace: helpers.CiliumNamespace}).ExpectSuccess("cannot install IPsec keys")
		kubectl.NodeCleanMetadata()
	})

	AfterEach(func() {
		kubectl.Delete(demoDSPath)
		kubectl.Delete(ipsecDSPath)
		kubectl.DeleteCiliumDS()
		ExpectAllPodsTerminated(kubectl)
	})

	AfterFailed(func() {
		kubectl.CiliumReport(helpers.CiliumNamespace,
			"cilium bpf tunnel list",
			"cilium endpoint list")
	})

	AfterAll(func() {
		DeployCiliumAndDNS(kubectl, ciliumFilename)
		kubectl.CloseSSHClient()
	})

	JustAfterEach(func() {
		if !(config.CiliumTestConfig.HoldEnvironment && TestFailed()) {
			// To avoid hitting GH-4384
			kubectl.DeleteResource("service", "test-nodeport testds-service").ExpectSuccess(
				"Service is deleted")
		}

		kubectl.ValidateNoErrorsInLogs(CurrentGinkgoTestDescription().Duration)
	})

	deployNetperf := func() {
		netperfServiceName := "netperf-service"

		netperfManifest := helpers.ManifestGet(kubectl.BasePath(), "netperf-deployment.yaml")
		kubectl.ApplyDefault(netperfManifest).ExpectSuccess("Netperf cannot be deployed")

		err := kubectl.WaitforPods(
			helpers.DefaultNamespace,
			fmt.Sprintf("-l zgroup=testapp"), helpers.HelperTimeout)
		Expect(err).Should(BeNil(), "Pods are not ready after timeout")

		_, err = kubectl.GetPodsIPs(helpers.DefaultNamespace, "zgroup=testapp")
		Expect(err).To(BeNil(), "Cannot get pods ips")

		_, _, err = kubectl.GetServiceHostPort(helpers.DefaultNamespace, netperfServiceName)
		Expect(err).To(BeNil(), "cannot get service netperf ip")
	}

	deployHTTPd := func() {
		httpManifest := helpers.ManifestGet(kubectl.BasePath(), "http-deployment.yaml")
		kubectl.ApplyDefault(httpManifest).ExpectSuccess("HTTP cannot be deployed")

		err := kubectl.WaitforPods(
			helpers.DefaultNamespace,
			fmt.Sprintf("-l zgroup=http-server"), helpers.HelperTimeout)
		Expect(err).Should(BeNil(), "Pods are not ready after timeout")

		_, err = kubectl.GetPodsIPs(helpers.DefaultNamespace, "zgroup=http-server")
		Expect(err).To(BeNil(), "Cannot get pods ips")
	}

	deployHTTPclients := func() {
		httpManifest := helpers.ManifestGet(kubectl.BasePath(), "http-clients.yaml")
		kubectl.ApplyDefault(httpManifest).ExpectSuccess("HTTP clients cannot be deployed")

		err := kubectl.WaitforPods(
			helpers.DefaultNamespace,
			fmt.Sprintf("-l zgroup=http-clients"), helpers.HelperTimeout)
		Expect(err).Should(BeNil(), "Pods are not ready after timeout")

		_, err = kubectl.GetPodsIPs(helpers.DefaultNamespace, "zgroup=http-clients")
		Expect(err).To(BeNil(), "Cannot get pods ips")
	}

	deployCilium := func(options map[string]string) {
		DeployCiliumOptionsAndDNS(kubectl, ciliumFilename, options)

		err := kubectl.WaitforPods(helpers.DefaultNamespace, "", helpers.HelperTimeout)
		ExpectWithOffset(1, err).Should(BeNil(), "Pods are not ready after timeout")

		_, err = kubectl.CiliumNodesWait()
		ExpectWithOffset(1, err).Should(BeNil(), "Failure while waiting for k8s nodes to be annotated by Cilium")

		By("Making sure all endpoints are in ready state")
		err = kubectl.CiliumEndpointWaitReady()
		ExpectWithOffset(1, err).To(BeNil(), "Failure while waiting for all cilium endpoints to reach ready state")
	}

	Context("MonitorAggregation", func() {
		It("Checks that monitor aggregation restricts notifications", func() {
			deployCilium(map[string]string{
				"global.bpf.monitorAggregation": "medium",
				"global.bpf.monitorInterval":    "60s",
				"global.bpf.monitorFlags":       "syn",
				"global.debug.enabled":          "false",
			})
			monitorOutput, targetIP := monitorConnectivityAcrossNodes(kubectl, monitorLog)

			By("Checking that exactly one ICMP notification in each direction was observed")
			expEgress := fmt.Sprintf("ICMPv4.*DstIP=%s", targetIP)
			expEgressRegex := regexp.MustCompile(expEgress)
			egressMatches := expEgressRegex.FindAllIndex(monitorOutput, -1)
			Expect(len(egressMatches)).To(Equal(1), "Monitor log contained unexpected number of egress notifications matching %q", expEgress)

			expIngress := fmt.Sprintf("ICMPv4.*SrcIP=%s", targetIP)
			expIngressRegex := regexp.MustCompile(expIngress)
			ingressMatches := expIngressRegex.FindAllIndex(monitorOutput, -1)
			Expect(len(ingressMatches)).To(Equal(1), "Monitor log contained unexpected number of ingress notifications matching %q", expIngress)

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
			checkMonitorOutput(monitorOutput, egressPktCount, ingressPktCount)
		})

		It("Checks that monitor aggregation flags send notifications", func() {
			deployCilium(map[string]string{
				"global.bpf.monitorAggregation": "medium",
				"global.bpf.monitorInterval":    "60s",
				"global.bpf.monitorFlags":       "psh",
				"global.debug.enabled":          "false",
			})
			monitorOutput, _ := monitorConnectivityAcrossNodes(kubectl, monitorLog)

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
			checkMonitorOutput(monitorOutput, egressPktCount, ingressPktCount)
		})
	})

	Context("Encapsulation", func() {
		BeforeEach(func() {
			SkipIfIntegration(helpers.CIIntegrationFlannel)
		})

		validateBPFTunnelMap := func() {
			By("Checking that BPF tunnels are in place")
			ciliumPod, err := kubectl.GetCiliumPodOnNodeWithLabel(helpers.CiliumNamespace, helpers.K8s1)
			ExpectWithOffset(1, err).Should(BeNil(), "Unable to determine cilium pod on node %s", helpers.K8s1)
			status := kubectl.CiliumExec(ciliumPod, "cilium bpf tunnel list | wc -l")
			status.ExpectSuccess()

			// ipv4+ipv6: 2 entries for each remote node + 1 header row
			numEntries := (kubectl.GetNumCiliumNodes()-1)*2 + 1
			if value := helpers.HelmOverride("global.ipv6.enabled"); value == "false" {
				// ipv4 only: 1 entry for each remote node + 1 header row
				numEntries = (kubectl.GetNumCiliumNodes() - 1) + 1
			}

			Expect(status.IntOutput()).Should(Equal(numEntries), "Did not find expected number of entries in BPF tunnel map")
		}

		It("Check connectivity with transparent encryption and VXLAN encapsulation", func() {
			if !helpers.RunsOnNetNext() {
				Skip("Skipping test because it is not running with the net-next kernel")
				return
			}
			SkipItIfNoKubeProxy()

			deployCilium(map[string]string{
				"global.encryption.enabled": "true",
			})
			validateBPFTunnelMap()
			Expect(testPodConnectivityAcrossNodes(kubectl)).Should(BeTrue(), "Connectivity test with IPsec between nodes failed")
		}, 600)

		It("Check connectivity with sockops and VXLAN encapsulation", func() {
			// Note if run on kernel without sockops feature is ignored
			deployCilium(map[string]string{
				"global.sockops.enabled": "true",
			})
			validateBPFTunnelMap()
			Expect(testPodConnectivityAcrossNodes(kubectl)).Should(BeTrue(), "Connectivity test between nodes failed")
			Expect(testPodConnectivitySameNodes(kubectl)).Should(BeTrue(), "Connectivity test on same node failed")
		}, 600)

		It("Check connectivity with VXLAN encapsulation", func() {
			deployCilium(map[string]string{
				"global.tunnel": "vxlan",
			})
			validateBPFTunnelMap()
			Expect(testPodConnectivityAcrossNodes(kubectl)).Should(BeTrue(), "Connectivity test between nodes failed")
		}, 600)

		It("Check connectivity with Geneve encapsulation", func() {
			deployCilium(map[string]string{
				"global.tunnel": "geneve",
			})
			validateBPFTunnelMap()
			Expect(testPodConnectivityAcrossNodes(kubectl)).Should(BeTrue(), "Connectivity test between nodes failed")
		})

		It("Check vxlan connectivity with per endpoint routes", func() {
			Skip("Encapsulation mode is not supported with per-endpoint routes")

			deployCilium(map[string]string{
				"global.autoDirectNodeRoutes": "true",
			})
			Expect(testPodConnectivityAcrossNodes(kubectl)).Should(BeTrue(), "Connectivity test between nodes failed")
		})

	})

	Context("DirectRouting", func() {
		BeforeEach(func() {
			SkipIfIntegration(helpers.CIIntegrationFlannel)
			SkipIfIntegration(helpers.CIIntegrationGKE)
		})

		directRoutingOptions := map[string]string{
			"global.tunnel":               "disabled",
			"global.autoDirectNodeRoutes": "true",
		}

		It("Check connectivity with automatic direct nodes routes", func() {
			deployCilium(directRoutingOptions)
			Expect(testPodConnectivityAcrossNodes(kubectl)).Should(BeTrue(), "Connectivity test between nodes failed")
		})

		It("Check direct connectivity with per endpoint routes", func() {
			directRoutingOptions["global.endpointRoutes.enabled"] = "true"
			directRoutingOptions["global.ipv6.enabled"] = "false"
			deployCilium(directRoutingOptions)
			Expect(testPodConnectivityAcrossNodes(kubectl)).Should(BeTrue(), "Connectivity test between nodes failed")
		})

		It("Check connectivity with sockops and direct routing", func() {
			// Note if run on kernel without sockops feature is ignored
			deployCilium(map[string]string{
				"global.sockops.enabled": "true",
			})
			Expect(testPodConnectivityAcrossNodes(kubectl)).Should(BeTrue(), "Connectivity test between nodes failed")
			Expect(testPodConnectivitySameNodes(kubectl)).Should(BeTrue(), "Connectivity test on same node failed")
		}, 600)

	})

	Context("Sockops performance", func() {
		directRoutingOptions := map[string]string{
			"global.tunnel":               "disabled",
			"global.autoDirectNodeRoutes": "true",
		}

		sockopsEnabledOptions := map[string]string{}
		for k, v := range directRoutingOptions {
			sockopsEnabledOptions[k] = v
		}

		sockopsEnabledOptions["global.sockops.enabled"] = "true"

		BeforeEach(func() {
			SkipIfBenchmark()
			SkipIfIntegration(helpers.CIIntegrationGKE)
		})

		AfterEach(func() {
			httpClients := helpers.ManifestGet(kubectl.BasePath(), "http-clients.yaml")
			httpServers := helpers.ManifestGet(kubectl.BasePath(), "http-deployment.yaml")
			netperfClients := helpers.ManifestGet(kubectl.BasePath(), "netperf-deployment.yaml")

			kubectl.Delete(netperfClients)
			kubectl.Delete(httpClients)
			kubectl.Delete(httpServers)

			ExpectAllPodsTerminated(kubectl)
		})

		It("Check baseline performance with direct routing TCP_CRR", func() {
			Skip("Skipping TCP_CRR until fix reaches upstream")
			deployCilium(directRoutingOptions)
			deployNetperf()
			Expect(testPodNetperfSameNodes(kubectl, helpers.TCP_CRR)).Should(BeTrue(), "Connectivity test TCP_CRR on same node failed")
		}, 600)

		It("Check baseline performance with direct routing TCP_RR", func() {
			deployCilium(directRoutingOptions)
			deployNetperf()
			Expect(testPodNetperfSameNodes(kubectl, helpers.TCP_RR)).Should(BeTrue(), "Connectivity test TCP_RR on same node failed")
		}, 600)

		It("Check baseline performance with direct routing TCP_STREAM", func() {
			deployCilium(directRoutingOptions)
			deployNetperf()
			Expect(testPodNetperfSameNodes(kubectl, helpers.TCP_STREAM)).Should(BeTrue(), "Connectivity test TCP_STREAM on same node failed")
		}, 600)

		It("Check performance with sockops and direct routing", func() {
			Skip("Skipping TCP_CRR until fix reaches upstream")
			deployCilium(sockopsEnabledOptions)
			deployNetperf()
			Expect(testPodNetperfSameNodes(kubectl, helpers.TCP_CRR)).Should(BeTrue(), "Connectivity test TCP_CRR on same node failed")
		}, 600)

		It("Check performance with sockops and direct routing", func() {
			deployCilium(sockopsEnabledOptions)
			deployNetperf()
			Expect(testPodNetperfSameNodes(kubectl, helpers.TCP_RR)).Should(BeTrue(), "Connectivity test TCP_RR on same node failed")
		}, 600)

		It("Check performance with sockops and direct routing", func() {
			deployCilium(sockopsEnabledOptions)
			deployNetperf()
			Expect(testPodNetperfSameNodes(kubectl, helpers.TCP_STREAM)).Should(BeTrue(), "Connectivity test TCP_STREAM on same node failed")
		}, 600)

		It("Check baseline http performance with sockops and direct routing", func() {
			deployCilium(directRoutingOptions)
			deployHTTPclients()
			deployHTTPd()
			Expect(testPodHTTPSameNodes(kubectl)).Should(BeTrue(), "HTTP test on same node failed ")
		}, 600)

		It("Check http performance with sockops and direct routing", func() {
			deployCilium(sockopsEnabledOptions)
			deployHTTPclients()
			deployHTTPd()
			Expect(testPodHTTPSameNodes(kubectl)).Should(BeTrue(), "HTTP test on same node failed ")
		}, 600)
	})

	Context("Transparent encryption DirectRouting", func() {
		It("Check connectivity with transparent encryption and direct routing", func() {
			SkipIfIntegration(helpers.CIIntegrationFlannel)
			SkipIfIntegration(helpers.CIIntegrationGKE)
			SkipItIfNoKubeProxy()

			privateIface, err := kubectl.GetPrivateIface()
			Expect(err).Should(BeNil(), "Unable to determine private iface")

			deployCilium(map[string]string{
				"global.tunnel":               "disabled",
				"global.autoDirectNodeRoutes": "true",
				"global.encryption.enabled":   "true",
				"global.encryption.interface": privateIface,
			})
			Expect(testPodConnectivityAcrossNodes(kubectl)).Should(BeTrue(), "Connectivity test between nodes failed")
		})
	})

	Context("IPv4Only", func() {
		It("Check connectivity with IPv6 disabled", func() {
			// Flannel always disables IPv6, this test is a no-op in that case.
			SkipIfIntegration(helpers.CIIntegrationFlannel)

			deployCilium(map[string]string{
				"global.ipv4.enabled": "true",
				"global.ipv6.enabled": "false",
			})
			Expect(testPodConnectivityAcrossNodes(kubectl)).Should(BeTrue(), "Connectivity test between nodes failed")
		})
	})

	Context("ManagedEtcd", func() {
		AfterAll(func() {
			deleteETCDOperator(kubectl)
		})
		It("Check connectivity with managed etcd", func() {
			opts := map[string]string{
				"global.etcd.enabled": "true",
				"global.etcd.managed": "true",
			}
			if helpers.ExistNodeWithoutCilium() {
				opts["operator.synchronizeK8sNodes"] = "false"
			}
			deployCilium(opts)
			Expect(testPodConnectivityAcrossNodes(kubectl)).Should(BeTrue(), "Connectivity test between nodes failed")
		})
	})
})

func testPodConnectivityAcrossNodes(kubectl *helpers.Kubectl) bool {
	result, _ := testPodConnectivityAndReturnIP(kubectl, true, 1)
	return result
}

func testPodConnectivitySameNodes(kubectl *helpers.Kubectl) bool {
	result, _ := testPodConnectivityAndReturnIP(kubectl, false, 1)
	return result
}

func testPodNetperfSameNodes(kubectl *helpers.Kubectl, test helpers.PerfTest) bool {
	result, _ := testPodNetperf(kubectl, false, 1, test)
	return result
}

func fetchPodsWithOffset(kubectl *helpers.Kubectl, name, filter, hostIPAntiAffinity string, requireMultiNode bool, callOffset int) (targetPod string, targetPodJSON *helpers.CmdRes) {
	callOffset++

	// Fetch pod (names) with the specified filter
	err := kubectl.WaitforPods(helpers.DefaultNamespace, fmt.Sprintf("-l %s", filter), helpers.HelperTimeout)
	ExpectWithOffset(callOffset, err).Should(BeNil(), "Failure while waiting for connectivity test pods to start")
	pods, err := kubectl.GetPodNames(helpers.DefaultNamespace, filter)
	ExpectWithOffset(callOffset, err).Should(BeNil(), "Failure while retrieving pod name for %s", filter)
	if requireMultiNode {
		ExpectWithOffset(callOffset, len(pods)).Should(BeNumerically(">", 1),
			fmt.Sprintf("This test requires at least two %s instances, but only one was found", name))
	}

	// Fetch the json description of one of the pods
	targetPod = pods[0]
	targetPodJSON = kubectl.Get(
		helpers.DefaultNamespace,
		fmt.Sprintf("pod %s -o json", targetPod))

	// If multinode / antiaffinity is required, ensure that the target is
	// not on the same node as "hostIPAntiAffinity".
	if requireMultiNode && hostIPAntiAffinity != "" {
		targetHost, err := targetPodJSON.Filter("{.status.hostIP}")
		ExpectWithOffset(callOffset, err).Should(BeNil(), "Failure to retrieve host of pod %s", targetPod)

		if targetHost.String() == hostIPAntiAffinity {
			targetPod = pods[1]
			targetPodJSON = kubectl.Get(
				helpers.DefaultNamespace,
				fmt.Sprintf("pod %s -o json", targetPod))
		}
	} else if !requireMultiNode && hostIPAntiAffinity != "" {
		targetHost, err := targetPodJSON.Filter("{.status.hostIP}")
		ExpectWithOffset(callOffset, err).Should(BeNil(), "Failure to retrieve host of pod %s", targetPod)

		if targetHost.String() != hostIPAntiAffinity {
			targetPod = pods[1]
			targetPodJSON = kubectl.Get(
				helpers.DefaultNamespace,
				fmt.Sprintf("pod %s -o json", targetPod))
		}
	}
	return targetPod, targetPodJSON
}

func testPodConnectivityAndReturnIP(kubectl *helpers.Kubectl, requireMultiNode bool, callOffset int) (bool, string) {
	callOffset++

	By("Checking pod connectivity between nodes")

	srcPod, srcPodJSON := fetchPodsWithOffset(kubectl, "client", "zgroup=testDSClient", "", requireMultiNode, callOffset)
	srcHost, err := srcPodJSON.Filter("{.status.hostIP}")
	ExpectWithOffset(callOffset, err).Should(BeNil(), "Failure to retrieve host of pod %s", srcPod)

	dstPod, dstPodJSON := fetchPodsWithOffset(kubectl, "server", "zgroup=testDS", srcHost.String(), requireMultiNode, callOffset)
	podIP, err := dstPodJSON.Filter("{.status.podIP}")
	ExpectWithOffset(callOffset, err).Should(BeNil(), "Failure to retrieve IP of pod %s", dstPod)
	targetIP := podIP.String()

	// ICMP connectivity test
	res := kubectl.ExecPodCmd(helpers.DefaultNamespace, srcPod, helpers.Ping(targetIP))
	if !res.WasSuccessful() {
		return false, targetIP
	}

	// HTTP connectivity test
	res = kubectl.ExecPodCmd(helpers.DefaultNamespace, srcPod,
		helpers.CurlFail("http://%s:80/", targetIP))
	return res.WasSuccessful(), targetIP
}

func testPodHTTPAcrossNodes(kubectl *helpers.Kubectl) bool {
	result, _ := testPodHTTP(kubectl, true, 1)
	return result
}

func testPodHTTPSameNodes(kubectl *helpers.Kubectl) bool {
	result, _ := testPodHTTP(kubectl, false, 1)
	return result
}

func testPodHTTP(kubectl *helpers.Kubectl, requireMultiNode bool, callOffset int) (bool, string) {
	callOffset++

	By("Checking pod http")
	dstPod, dstPodJSON := fetchPodsWithOffset(kubectl, "client", "zgroup=http-server", "", requireMultiNode, callOffset)
	dstHost, err := dstPodJSON.Filter("{.status.hostIP}")
	ExpectWithOffset(callOffset, err).Should(BeNil(), "Failure to retrieve host of pod %s", dstPod)

	podIP, err := dstPodJSON.Filter("{.status.podIP}")
	targetIP := podIP.String()

	srcPod, _ := fetchPodsWithOffset(kubectl, "server", "zgroup=http-client", dstHost.String(), requireMultiNode, callOffset)
	ExpectWithOffset(callOffset, err).Should(BeNil(), "Failure to retrieve IP of pod %s", srcPod)

	// Netperf benchmark test
	res := kubectl.ExecPodCmd(helpers.DefaultNamespace, srcPod, helpers.Wrk(targetIP))
	res.ExpectContains("Requests/sec", "wrk failed")
	return true, targetIP

}

func testPodNetperf(kubectl *helpers.Kubectl, requireMultiNode bool, callOffset int, test helpers.PerfTest) (bool, string) {
	netperfOptions := "-l 30 -I 99,99"
	callOffset++

	By("Checking pod netperf")

	dstPod, dstPodJSON := fetchPodsWithOffset(kubectl, "client", "zgroup=testapp", "", requireMultiNode, callOffset)
	dstHost, err := dstPodJSON.Filter("{.status.hostIP}")
	ExpectWithOffset(callOffset, err).Should(BeNil(), "Failure to retrieve host of pod %s", dstPod)

	podIP, err := dstPodJSON.Filter("{.status.podIP}")
	targetIP := podIP.String()

	srcPod, _ := fetchPodsWithOffset(kubectl, "server", "zgroup=testDSClient", dstHost.String(), requireMultiNode, callOffset)
	ExpectWithOffset(callOffset, err).Should(BeNil(), "Failure to retrieve IP of pod %s", srcPod)

	// Netperf benchmark test
	res := kubectl.ExecPodCmd(helpers.DefaultNamespace, srcPod, helpers.Netperf(targetIP, test, netperfOptions))
	return res.WasSuccessful(), targetIP
}

func monitorConnectivityAcrossNodes(kubectl *helpers.Kubectl, monitorLog string) (monitorOutput []byte, targetIP string) {
	// For local single-node testing, configure requireMultiNode to "false"
	// and add the labels "cilium.io/ci-node: k8s1" to the node.
	requireMultiNode := true

	ciliumPodK8s1, err := kubectl.GetCiliumPodOnNodeWithLabel(helpers.CiliumNamespace, helpers.K8s1)
	ExpectWithOffset(1, err).Should(BeNil(), "Cannot get cilium pod on k8s1")

	By(fmt.Sprintf("Launching cilium monitor on %q", ciliumPodK8s1))
	monitorStop := kubectl.MonitorStart(helpers.CiliumNamespace, ciliumPodK8s1, monitorLog)
	result, targetIP := testPodConnectivityAndReturnIP(kubectl, requireMultiNode, 2)
	monitorStop()
	ExpectWithOffset(1, result).Should(BeTrue(), "Connectivity test between nodes failed")

	monitorPath := fmt.Sprintf("%s/%s", helpers.ReportDirectoryPath(), monitorLog)
	By("Reading the monitor log at %s", monitorPath)
	monitorOutput, err = ioutil.ReadFile(monitorPath)
	ExpectWithOffset(1, err).To(BeNil(), "Could not read monitor log")
	return monitorOutput, targetIP
}

func checkMonitorOutput(monitorOutput []byte, egressPktCount, ingressPktCount int) {
	// Multiple connection attempts may be made, we need to
	// narrow down to the last connection close, then match
	// the ephemeral port + flags to ensure that the
	// notifications match the table above.
	egressTCPExpr := `TCP.*DstPort=80.*FIN=true`
	egressTCPRegex := regexp.MustCompile(egressTCPExpr)
	egressTCPMatches := egressTCPRegex.FindAll(monitorOutput, -1)
	ExpectWithOffset(1, len(egressTCPMatches)).To(BeNumerically(">", 0), "Could not locate final FIN notification in monitor log")
	finalMatch := egressTCPMatches[len(egressTCPMatches)-1]
	portRegex := regexp.MustCompile(`SrcPort=([0-9]*)`)
	// FindSubmatch should return ["SrcPort=12345" "12345"]
	portBytes := portRegex.FindSubmatch(finalMatch)[1]

	By("Looking for TCP notifications using the ephemeral port %q", portBytes)
	port, err := strconv.Atoi(string(portBytes))
	ExpectWithOffset(1, err).To(BeNil(), fmt.Sprintf("ephemeral port %q could not be converted to integer", string(portBytes)))
	expEgress := fmt.Sprintf("SrcPort=%d", port)
	expEgressRegex := regexp.MustCompile(expEgress)
	egressMatches := expEgressRegex.FindAllIndex(monitorOutput, -1)
	ExpectWithOffset(1, len(egressMatches)).To(Equal(egressPktCount), "Monitor log contained unexpected number of egress notifications matching %q", expEgress)
	expIngress := fmt.Sprintf("DstPort=%d", port)
	expIngressRegex := regexp.MustCompile(expIngress)
	ingressMatches := expIngressRegex.FindAllIndex(monitorOutput, -1)
	ExpectWithOffset(1, len(ingressMatches)).To(Equal(ingressPktCount), "Monitor log contained unexpected number of ingress notifications matching %q", expIngress)
}

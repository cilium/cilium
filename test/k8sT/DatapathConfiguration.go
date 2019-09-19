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

	. "github.com/cilium/cilium/test/ginkgo-ext"
	"github.com/cilium/cilium/test/helpers"

	. "github.com/onsi/gomega"
)

var _ = Describe("K8sDatapathConfig", func() {

	var kubectl *helpers.Kubectl
	var demoDSPath string
	var ipsecDSPath string
	var monitorLog = "monitor-aggregation.log"

	BeforeAll(func() {
		kubectl = helpers.CreateKubectl(helpers.K8s1VMName(), logger)
		demoDSPath = helpers.ManifestGet(kubectl.BasePath(), "demo_ds.yaml")
		ipsecDSPath = helpers.ManifestGet(kubectl.BasePath(), "ipsec_ds.yaml")

		deleteCiliumDS(kubectl)
	})

	BeforeEach(func() {
		kubectl.Apply(demoDSPath).ExpectSuccess("cannot install Demo application")
		kubectl.Apply(ipsecDSPath).ExpectSuccess("cannot install IPsec keys")
		kubectl.NodeCleanMetadata()
	})

	AfterEach(func() {
		kubectl.Delete(demoDSPath)
		kubectl.Delete(ipsecDSPath)
		ExpectAllPodsTerminated(kubectl)

		deleteCiliumDS(kubectl)
	})

	AfterFailed(func() {
		kubectl.CiliumReport(helpers.KubeSystemNamespace,
			"cilium bpf tunnel list",
			"cilium endpoint list")
	})

	AfterAll(func() {
		kubectl.CloseSSHClient()
	})

	JustAfterEach(func() {
		kubectl.ValidateNoErrorsInLogs(CurrentGinkgoTestDescription().Duration)
	})

	cleanService := func() {
		// To avoid hit GH-4384
		kubectl.DeleteResource("service", "test-nodeport testds-service").ExpectSuccess(
			"Service is deleted")
	}

	deployCilium := func(options []string) {
		DeployCiliumOptionsAndDNS(kubectl, options)

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
			deployCilium([]string{
				"--set global.bpf.monitorAggregation=medium",
				"--set global.bpf.monitorInterval=60s",
				"--set global.bpf.monitorFlags=syn",
				"--set global.debug.enabled=false",
			})
			nodeName := helpers.K8s1

			var err error
			ciliumPodK8s1, err := kubectl.GetCiliumPodOnNode(helpers.KubeSystemNamespace, nodeName)
			Expect(err).Should(BeNil(), "Cannot get cilium pod on k8s1")

			By(fmt.Sprintf("Launching cilium monitor on %q", ciliumPodK8s1))
			monitorStop := kubectl.MonitorStart(helpers.KubeSystemNamespace, ciliumPodK8s1, monitorLog)
			result, targetIP := testPodConnectivityAcrossNodesAndReturnIP(kubectl, 1)
			monitorStop()
			cleanService()
			Expect(result).Should(BeTrue(), "Connectivity test between nodes failed")

			monitorPath := fmt.Sprintf("%s/%s", helpers.ReportDirectoryPath(), monitorLog)
			By("Reading the monitor log at %s", monitorPath)
			monitorOutput, err := ioutil.ReadFile(monitorPath)
			Expect(err).To(BeNil(), "Could not read monitor log")

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

			// Multiple connection attempts may be made, we need to
			// narrow down to the last connection close, then match
			// the ephemeral port + flags to ensure that the
			// notifications match the table above.
			egressTCPExpr := `TCP.*DstPort=80.*FIN=true`
			egressTCPRegex := regexp.MustCompile(egressTCPExpr)
			egressTCPMatches := egressTCPRegex.FindAll(monitorOutput, -1)
			Expect(len(egressTCPMatches)).To(BeNumerically(">", 0), "Could not locate final FIN notification in monitor log")
			finalMatch := egressTCPMatches[len(egressTCPMatches)-1]
			portRegex := regexp.MustCompile(`SrcPort=([0-9]*)`)
			// FindSubmatch should return ["SrcPort=12345" "12345"]
			portBytes := portRegex.FindSubmatch(finalMatch)[1]

			By("Looking for TCP notifications using the ephemeral port %q", portBytes)
			port, err := strconv.Atoi(string(portBytes))
			Expect(err).To(BeNil(), fmt.Sprintf("ephemeral port %q could not be converted to integer", string(portBytes)))
			expEgress = fmt.Sprintf("SrcPort=%d", port)
			expEgressRegex = regexp.MustCompile(expEgress)
			egressMatches = expEgressRegex.FindAllIndex(monitorOutput, -1)
			Expect(len(egressMatches)).To(Equal(3), "Monitor log contained unexpected number of egress notifications matching %q", expEgress)
			expIngress = fmt.Sprintf("DstPort=%d", port)
			expIngressRegex = regexp.MustCompile(expIngress)
			ingressMatches = expIngressRegex.FindAllIndex(monitorOutput, -1)
			Expect(len(ingressMatches)).To(Equal(2), "Monitor log contained unexpected number of ingress notifications matching %q", expIngress)
		})
	})

	Context("Encapsulation", func() {
		BeforeEach(func() {
			SkipIfFlannel()
		})

		validateBPFTunnelMap := func() {
			By("Checking that BPF tunnels are in place")
			ciliumPod, err := kubectl.GetCiliumPodOnNode(helpers.KubeSystemNamespace, helpers.K8s1)
			ExpectWithOffset(1, err).Should(BeNil(), "Unable to determine cilium pod on node %s", helpers.K8s1)
			status := kubectl.CiliumExec(ciliumPod, "cilium bpf tunnel list | wc -l")
			status.ExpectSuccess()
			Expect(status.IntOutput()).Should(Equal(3), "Did not find expected number of entries in BPF tunnel map")
		}

		It("Check connectivity with transparent encryption and VXLAN encapsulation", func() {
			if !helpers.RunsOnNetNext() {
				Skip("Skipping test because it is not running with the net-next kernel")
				return
			}

			deployCilium([]string{
				"--set global.encryption.enabled=true",
			})
			validateBPFTunnelMap()
			Expect(testPodConnectivityAcrossNodes(kubectl)).Should(BeTrue(), "Connectivity test with IPsec between nodes failed")
			cleanService()
		}, 600)

		It("Check connectivity with sockops and VXLAN encapsulation", func() {
			// Note if run on kernel without sockops feature is ignored
			deployCilium([]string{
				"--set global.sockops.enabled=true",
			})
			validateBPFTunnelMap()
			Expect(testPodConnectivityAcrossNodes(kubectl)).Should(BeTrue(), "Connectivity test between nodes failed")
			cleanService()
		}, 600)

		It("Check connectivity with VXLAN encapsulation", func() {
			deployCilium([]string{
				"--set global.tunnel=vxlan",
			})
			validateBPFTunnelMap()
			Expect(testPodConnectivityAcrossNodes(kubectl)).Should(BeTrue(), "Connectivity test between nodes failed")
			cleanService()
		}, 600)

		It("Check connectivity with Geneve encapsulation", func() {
			deployCilium([]string{
				"--set global.tunnel=geneve",
			})
			validateBPFTunnelMap()
			Expect(testPodConnectivityAcrossNodes(kubectl)).Should(BeTrue(), "Connectivity test between nodes failed")
			cleanService()
		})

		It("Check vxlan connectivity with per endpoint routes", func() {
			Skip("Encapsulation mode is not supported with per-endpoint routes")

			deployCilium([]string{
				"--set global.autoDirectNodeRoutes=true",
			})
			Expect(testPodConnectivityAcrossNodes(kubectl)).Should(BeTrue(), "Connectivity test between nodes failed")
			cleanService()
		})

	})

	Context("DirectRouting", func() {
		directRoutingOptions := []string{
			"--set global.tunnel=disabled",
			"--set global.autoDirectNodeRoutes=true",
		}

		It("Check connectivity with automatic direct nodes routes", func() {
			SkipIfFlannel()

			deployCilium(directRoutingOptions)
			Expect(testPodConnectivityAcrossNodes(kubectl)).Should(BeTrue(), "Connectivity test between nodes failed")
			cleanService()
		})

		It("Check direct connectivity with per endpoint routes", func() {
			SkipIfFlannel()

			deployCilium(append(directRoutingOptions,
				"--set global.endpointRoutes.enabled=true",
			))
			Expect(testPodConnectivityAcrossNodes(kubectl)).Should(BeTrue(), "Connectivity test between nodes failed")
			cleanService()
		})
	})

	Context("Transparent encryption DirectRouting", func() {
		It("Check connectivity with transparent encryption and direct routing", func() {
			SkipIfFlannel()

			deployCilium([]string{
				"--set global.tunnel=disabled",
				"--set global.autoDirectNodeRoutes=true",
				"--set global.encryption.enabled=true",
				"--set global.encryption.interface=enp0s8",
			})
			Expect(testPodConnectivityAcrossNodes(kubectl)).Should(BeTrue(), "Connectivity test between nodes failed")
			cleanService()
		})
	})

	Context("IPv4Only", func() {
		It("Check connectivity with IPv6 disabled", func() {
			// Flannel always disables IPv6, this test is a no-op in that case.
			SkipIfFlannel()

			deployCilium([]string{
				"--set global.ipv4.enabled=true",
				"--set global.ipv6.enabled=false",
			})
			Expect(testPodConnectivityAcrossNodes(kubectl)).Should(BeTrue(), "Connectivity test between nodes failed")
			cleanService()
		})
	})

	Context("ManagedEtcd", func() {
		AfterAll(func() {
			deleteETCDOperator(kubectl)
		})
		It("Check connectivity with managed etcd", func() {
			deployCilium([]string{
				"--set global.etcd.enabled=true",
				"--set global.etcd.managed=true",
			})
			Expect(testPodConnectivityAcrossNodes(kubectl)).Should(BeTrue(), "Connectivity test between nodes failed")
			cleanService()
		})
	})
})

func testPodConnectivityAcrossNodes(kubectl *helpers.Kubectl) bool {
	result, _ := testPodConnectivityAcrossNodesAndReturnIP(kubectl, 1)
	return result
}

func fetchPodsWithOffset(kubectl *helpers.Kubectl, name, filter, hostIPAntiAffinity string, callOffset int) (targetPod string, targetPodJSON *helpers.CmdRes) {
	callOffset++

	// Fetch pod (names) with the specified filter
	err := kubectl.WaitforPods(helpers.DefaultNamespace, fmt.Sprintf("-l %s", filter), helpers.HelperTimeout)
	ExpectWithOffset(callOffset, err).Should(BeNil(), "Failure while waiting for connectivity test pods to start")
	pods, err := kubectl.GetPodNames(helpers.DefaultNamespace, filter)
	ExpectWithOffset(callOffset, err).Should(BeNil(), "Failure while retrieving pod name for %s", filter)

	// Fetch the json description of one of the pods
	targetPod = pods[0]
	targetPodJSON = kubectl.Get(
		helpers.DefaultNamespace,
		fmt.Sprintf("pod %s -o json", targetPod))

	// If multinode / antiaffinity is required, ensure that the target is
	// not on the same node as "hostIPAntiAffinity".
	if hostIPAntiAffinity != "" {
		targetHost, err := targetPodJSON.Filter("{.status.hostIP}")
		ExpectWithOffset(callOffset, err).Should(BeNil(), "Failure to retrieve host of pod %s", targetPod)

		if targetHost.String() == hostIPAntiAffinity {
			targetPod = pods[1]
			targetPodJSON = kubectl.Get(
				helpers.DefaultNamespace,
				fmt.Sprintf("pod %s -o json", targetPod))
		}
	}
	return targetPod, targetPodJSON
}

func testPodConnectivityAcrossNodesAndReturnIP(kubectl *helpers.Kubectl, callOffset int) (bool, string) {
	callOffset++

	By("Checking pod connectivity between nodes")

	srcPod, srcPodJSON := fetchPodsWithOffset(kubectl, "client", "zgroup=testDSClient", "", callOffset)
	srcHost, err := srcPodJSON.Filter("{.status.hostIP}")
	ExpectWithOffset(callOffset, err).Should(BeNil(), "Failure to retrieve host of pod %s", srcPod)

	dstPod, dstPodJSON := fetchPodsWithOffset(kubectl, "server", "zgroup=testDS", srcHost.String(), callOffset)
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

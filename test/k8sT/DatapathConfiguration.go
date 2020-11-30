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
	"context"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
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
				"debug.enabled":          "false",
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
			}, helpers.HelperTimeout).Should(BeTrue(), "Egress ICMPv4 flow (%q) not found in monitor log\n%s", expEgress, monitorOutput)

			By("Checking that ICMP notifications in ingress direction were observed")
			expIngress := fmt.Sprintf("ICMPv4.*SrcIP=%s", targetIP)
			expIngressRegex := regexp.MustCompile(expIngress)
			Eventually(func() bool {
				return searchMonitorLog(expIngressRegex)
			}, helpers.HelperTimeout).Should(BeTrue(), "Ingress ICMPv4 flow (%q) not found in monitor log\n%s", expIngress, monitorOutput)

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
			}, helpers.HelperTimeout).Should(BeTrue(), "Monitor log did not contain %d ingress and %d egress TCP notifications\n%s",
				ingressPktCount, egressPktCount, monitorOutput)

			helpers.WriteToReportFile(monitorOutput, monitorLog)
		})

		It("Checks that monitor aggregation flags send notifications", func() {
			deploymentManager.DeployCilium(map[string]string{
				"bpf.monitorAggregation": "medium",
				"bpf.monitorInterval":    "60s",
				"bpf.monitorFlags":       "psh",
				"debug.enabled":          "false",
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
			}, helpers.HelperTimeout).Should(BeTrue(), "monitor aggregation did not result in correct number of TCP notifications\n%s", monitorOutput)
			helpers.WriteToReportFile(monitorOutput, monitorLog)
		})
	})

	Context("Encapsulation", func() {
		BeforeEach(func() {
			SkipIfIntegration(helpers.CIIntegrationFlannel)
			SkipIfIntegration(helpers.CIIntegrationGKE)
		})

		validateBPFTunnelMap := func() {
			By("Checking that BPF tunnels are in place")
			ciliumPod, err := kubectl.GetCiliumPodOnNodeWithLabel(helpers.K8s1)
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

		It("Check connectivity with transparent encryption and VXLAN encapsulation", func() {
			// FIXME(brb) Currently, the test is broken with CI 4.19 setup. Run it on 4.19
			//			  once we have kube-proxy disabled there.
			if !helpers.RunsOnNetNextKernel() {
				Skip("Skipping test because it is not running with the net-next kernel")
				return
			}
			SkipItIfNoKubeProxy()

			deploymentManager.Deploy(helpers.CiliumNamespace, IPSecSecret)
			deploymentManager.DeployCilium(map[string]string{
				"encryption.enabled": "true",
			}, DeployCiliumOptionsAndDNS)
			validateBPFTunnelMap()
			Expect(testPodConnectivityAcrossNodes(kubectl)).Should(BeTrue(), "Connectivity test with IPsec between nodes failed")
		}, 600)

		It("Check connectivity with sockops and VXLAN encapsulation", func() {
			// Note if run on kernel without sockops feature is ignored
			if !helpers.RunsOnNetNextOr419Kernel() {
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

		SkipItIf(func() bool {
			// Skip K8s versions for which the test is currently flaky.
			return helpers.SkipK8sVersions(">=1.13.0 <1.18.0") && helpers.SkipQuarantined()
		}, "Check vxlan connectivity with per-endpoint routes", func() {
			deploymentManager.DeployCilium(map[string]string{
				"tunnel":                 "vxlan",
				"endpointRoutes.enabled": "true",
				"hostFirewall":           "false",
			}, DeployCiliumOptionsAndDNS)
			Expect(testPodConnectivityAcrossNodes(kubectl)).Should(BeTrue(), "Connectivity test between nodes failed")

			if helpers.RunsOnNetNextOr419Kernel() {
				By("Test BPF masquerade")
				Expect(testPodHTTPToOutside(kubectl, "http://google.com", false, false)).
					Should(BeTrue(), "Connectivity test to http://google.com failed")
			}
		})

		SkipItIf(func() bool {
			// Skip K8s versions for which the test is currently flaky.
			return helpers.SkipK8sVersions(">=1.14.0 <1.20.0") && helpers.SkipQuarantined()
		}, "Check iptables masquerading with random-fully", func() {
			deploymentManager.DeployCilium(map[string]string{
				"bpf.masquerade":      "false",
				"iptablesRandomFully": "true",
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
				"hostFirewall":           "false",
			}, DeployCiliumOptionsAndDNS)

			Expect(testPodConnectivityAcrossNodes(kubectl)).Should(BeTrue(), "Connectivity test between nodes failed")
		})
	})

	Context("AutoDirectNodeRoutes", func() {
		BeforeEach(func() {
			SkipIfIntegration(helpers.CIIntegrationFlannel)
			SkipIfIntegration(helpers.CIIntegrationGKE)
		})

		It("Check connectivity with automatic direct nodes routes", func() {
			options := map[string]string{
				"tunnel":               "disabled",
				"autoDirectNodeRoutes": "true",
			}
			// Needed to bypass bug with masquerading when devices are set. See #12141.
			if helpers.RunsWithKubeProxy() {
				options["masquerade"] = "false"
			}
			deploymentManager.DeployCilium(options, DeployCiliumOptionsAndDNS)

			Expect(testPodConnectivityAcrossNodes(kubectl)).Should(BeTrue(), "Connectivity test between nodes failed")
			if helpers.RunsOnNetNextOr419Kernel() {
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
				"hostFirewall":           "false",
			}
			// Needed to bypass bug with masquerading when devices are set. See #12141.
			if helpers.RunsWithKubeProxy() {
				options["masquerade"] = "false"
			}
			deploymentManager.DeployCilium(options, DeployCiliumOptionsAndDNS)

			Expect(testPodConnectivityAcrossNodes(kubectl)).Should(BeTrue(), "Connectivity test between nodes failed")
		})

		It("Check connectivity with sockops and direct routing", func() {
			// Note if run on kernel without sockops feature is ignored
			if !helpers.RunsOnNetNextOr419Kernel() {
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
		return helpers.DoesNotExistNodeWithoutCilium() || helpers.DoesNotRunOnNetNextOr419Kernel()
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
		It("Check connectivity with transparent encryption and direct routing", func() {
			SkipIfIntegration(helpers.CIIntegrationFlannel)
			SkipIfIntegration(helpers.CIIntegrationGKE)
			SkipItIfNoKubeProxy()

			privateIface, err := kubectl.GetPrivateIface()
			Expect(err).Should(BeNil(), "Unable to determine private iface")

			deploymentManager.Deploy(helpers.CiliumNamespace, IPSecSecret)
			deploymentManager.DeployCilium(map[string]string{
				"tunnel":               "disabled",
				"autoDirectNodeRoutes": "true",
				"encryption.enabled":   "true",
				"encryption.interface": privateIface,
				"devices":              "",
				"hostFirewall":         "false",
			}, DeployCiliumOptionsAndDNS)
			Expect(testPodConnectivityAcrossNodes(kubectl)).Should(BeTrue(), "Connectivity test between nodes failed")
		})
		It("Check connectivity with transparent encryption and direct routing with bpf_host", func() {
			SkipIfIntegration(helpers.CIIntegrationFlannel)
			SkipIfIntegration(helpers.CIIntegrationGKE)
			SkipItIfNoKubeProxy()

			privateIface, err := kubectl.GetPrivateIface()
			Expect(err).Should(BeNil(), "Unable to determine private iface")

			deploymentManager.Deploy(helpers.CiliumNamespace, IPSecSecret)
			deploymentManager.DeployCilium(map[string]string{
				"tunnel":               "disabled",
				"autoDirectNodeRoutes": "true",
				"encryption.enabled":   "true",
				"encryption.interface": privateIface,
				"hostFirewall":         "false",
			}, DeployCiliumOptionsAndDNS)
			Expect(testPodConnectivityAcrossNodes(kubectl)).Should(BeTrue(), "Connectivity test between nodes failed")
		})
	})

	Context("IPv4Only", func() {
		It("Check connectivity with IPv6 disabled", func() {
			// Flannel always disables IPv6, this test is a no-op in that case.
			SkipIfIntegration(helpers.CIIntegrationFlannel)

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
		SkipItIf(func() bool {
			return !helpers.IsIntegration(helpers.CIIntegrationGKE)
		}, "Check connectivity with IPv6 disabled", func() {
			deploymentManager.DeployCilium(map[string]string{
				"ipv4.enabled": "true",
				"ipv6.enabled": "false",
				"hostFirewall": "true",
				// We need the default GKE config. except for per-endpoint
				// routes (incompatible with host firewall for now).
				"gke.enabled": "false",
				"tunnel":      "disabled",
			}, DeployCiliumOptionsAndDNS)
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

func testPodConnectivityAndReturnIP(kubectl *helpers.Kubectl, requireMultiNode bool, callOffset int) (bool, string) {
	callOffset++

	randomNamespace := deploymentManager.DeployRandomNamespaceShared(DemoDaemonSet)
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

	ciliumPodK8s1, err := kubectl.GetCiliumPodOnNodeWithLabel(helpers.K8s1)
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

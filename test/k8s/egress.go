// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package k8sTest

import (
	"context"
	"fmt"
	"net"
	"strconv"
	"strings"

	. "github.com/onsi/gomega"
	v1 "k8s.io/api/core/v1"

	. "github.com/cilium/cilium/test/ginkgo-ext"
	"github.com/cilium/cilium/test/helpers"
)

type egressGatewayTestOpts struct {
	fromGateway    bool
	shouldBeSNATed bool
	shouldFail     bool
}

type egressGatewayConnectivityTestOpts struct {
	fromGateway bool
	ciliumOpts  map[string]string
}

var _ = SkipDescribeIf(func() bool {
	return helpers.RunsOnEKS() || helpers.RunsOnGKE() || helpers.DoesNotRunWithKubeProxyReplacement() || helpers.DoesNotExistNodeWithoutCilium() || helpers.DoesNotRunOn54OrLaterKernel()
}, "K8sDatapathEgressGatewayTest", func() {
	const (
		namespaceSelector = "ns=cilium-test"
		testDS            = "zgroup=testDS"
		testDSClient      = "zgroup=testDSClient"
	)

	var (
		kubectl         *helpers.Kubectl
		ciliumFilename  string
		randomNamespace string

		egressIP    string
		k8s1IP      string
		k8s2IP      string
		outsideIP   string
		k8s1Name    string
		k8s2Name    string
		outsideName string

		assignIPYAML string
		echoPodYAML  string
	)

	runEchoServer := func() {
		// Run echo server on outside node
		originalEchoPodPath := helpers.ManifestGet(kubectl.BasePath(), "echoserver-hostnetns.yaml")
		res := kubectl.ExecMiddle("mktemp")
		res.ExpectSuccess()
		echoPodYAML = strings.Trim(res.Stdout(), "\n")
		kubectl.ExecMiddle(fmt.Sprintf("sed 's/NODE_WITHOUT_CILIUM/%s/' %s > %s",
			helpers.GetFirstNodeWithoutCilium(), originalEchoPodPath, echoPodYAML)).ExpectSuccess()
		kubectl.ApplyDefault(echoPodYAML).ExpectSuccess("Cannot install echoserver application")
		Expect(kubectl.WaitforPods(helpers.DefaultNamespace, "-l name=echoserver-hostnetns",
			helpers.HelperTimeout)).Should(BeNil())
	}

	assignEgressIP := func() {
		// Assign egress IP address to k8s2
		originalAssignIPYAML := helpers.ManifestGet(kubectl.BasePath(), "egress-ip-deployment.yaml")
		res := kubectl.ExecMiddle("mktemp")
		res.ExpectSuccess()
		assignIPYAML = strings.Trim(res.Stdout(), "\n")
		kubectl.ExecMiddle(fmt.Sprintf("sed 's/INPUT_EGRESS_IP/%s/' %s > %s",
			egressIP, originalAssignIPYAML, assignIPYAML)).ExpectSuccess()
		res = kubectl.ApplyDefault(assignIPYAML)
		Expect(res).Should(helpers.CMDSuccess(), "unable to apply %s", assignIPYAML)
		Expect(kubectl.WaitforPods(helpers.DefaultNamespace, "-l name=egress-ip-assign",
			helpers.HelperTimeout)).Should(BeNil())

		// Wait egressIP online
		srcPod, _ := fetchPodsWithOffset(kubectl, helpers.DefaultNamespace, "", "name=egress-ip-assign", "", false, 0)
		res = kubectl.ExecPodCmd(helpers.DefaultNamespace, srcPod, helpers.PingWithCount(egressIP, 5))
		res.ExpectSuccess()
	}

	// ctEntriesOnNode returns the number of CT entries matching destination
	// IP and port on a given node
	ctEntriesOnNode := func(node, dstIP, dstPort string) int {
		ciliumPod, err := kubectl.GetCiliumPodOnNode(node)
		Expect(err).Should(BeNil(), "Unable to determine cilium pod on node %s", node)

		cmd := fmt.Sprintf("cilium bpf ct list global | grep '\\-> %s:%s\\b' | wc -l", dstIP, dstPort)
		res := kubectl.ExecPodCmd(helpers.CiliumNamespace, ciliumPod, cmd)
		res.ExpectSuccess()

		n, err := strconv.Atoi(strings.TrimSpace(res.Stdout()))
		Expect(err).Should(BeNil(), "Cannot parse output of '%s' command", cmd)

		return n
	}

	BeforeAll(func() {
		kubectl = helpers.CreateKubectl(helpers.K8s1VMName(), logger)

		k8s1Name, k8s1IP = kubectl.GetNodeInfo(helpers.K8s1)
		k8s2Name, k8s2IP = kubectl.GetNodeInfo(helpers.K8s2)
		outsideName, outsideIP = kubectl.GetNodeInfo(kubectl.GetFirstNodeWithoutCiliumLabel())

		egressIP = getEgressIP(k8s2IP)

		deploymentManager.SetKubectl(kubectl)

		// We deploy cilium, to run the echo server and assign egress IP, and redeploy with
		// different configurations for the tests.
		ciliumFilename = helpers.TimestampFilename("cilium.yaml")
		DeployCiliumAndDNS(kubectl, ciliumFilename)

		runEchoServer()
		assignEgressIP()
	})

	AfterAll(func() {
		_ = kubectl.Delete(echoPodYAML)
		_ = kubectl.Delete(assignIPYAML)
		ExpectAllPodsTerminated(kubectl)

		UninstallCiliumFromManifest(kubectl, ciliumFilename)
	})

	AfterFailed(func() {
		// Especially check if there are duplicated address allocated on cilium_host
		kubectl.CiliumReport("ip addr")
		kubectl.OutsideNodeReport(outsideName, "ip -d route")
	})

	testEgressGateway := func(testOpts *egressGatewayTestOpts) {
		if testOpts.fromGateway {
			By("Check egress policy from gateway node")
		} else {
			By("Check egress policy from non-gateway node")
		}

		hostIP := k8s1IP
		if testOpts.fromGateway {
			hostIP = k8s2IP
		}

		src, _ := fetchPodsWithOffset(kubectl, randomNamespace, "client", testDSClient, hostIP, false, 1)

		var (
			targetDestinationIP       string
			ctEntriesBeforeConnection int
		)

		if testOpts.shouldBeSNATed {
			By("Testing that a request from pod %s to outside is SNATed with the egressIP %s", src, egressIP)
			targetDestinationIP = egressIP
			ctEntriesBeforeConnection = ctEntriesOnNode(helpers.K8s2, outsideIP, "80")
		} else {
			By("Testing that a request from pod %s to outside is not SNATed with the egressIP %s", src, egressIP)
			targetDestinationIP = hostIP
		}

		res := kubectl.ExecPodCmd(randomNamespace, src, helpers.CurlFail("http://%s:80", outsideIP))

		if !testOpts.shouldFail {
			res.ExpectSuccess()
			res.ExpectMatchesRegexp(fmt.Sprintf("client_address=::ffff:%s\n", targetDestinationIP))
		} else {
			res.ExpectFail()
		}

		if testOpts.shouldBeSNATed {
			ctEntriesAfterConnection := ctEntriesOnNode(helpers.K8s2, outsideIP, "80")
			Expect(ctEntriesAfterConnection - ctEntriesBeforeConnection).Should(Equal(1))
		}
	}

	testConnectivity := func(testOpts *egressGatewayConnectivityTestOpts) {
		if testOpts.fromGateway {
			By("Check connectivity from gateway node")
		} else {
			By("Check connectivity from non-gateway node")
		}
		hostName := k8s1Name
		hostIP := k8s1IP
		if testOpts.fromGateway {
			hostName = k8s2Name
			hostIP = k8s2IP
		}

		src, _ := fetchPodsWithOffset(kubectl, randomNamespace, "client", testDSClient, hostIP, false, 1)

		// Pod-to-node connectivity should work
		By("Testing pod-to-node connectivity from %s to %s", src, k8s1IP)
		res := kubectl.ExecPodCmd(randomNamespace, src, helpers.PingWithCount(k8s1IP, 1))
		res.ExpectSuccess()

		By("Testing pod-to-node connectivity from %s to %s", src, k8s2IP)
		res = kubectl.ExecPodCmd(randomNamespace, src, helpers.PingWithCount(k8s2IP, 1))
		res.ExpectSuccess()

		// DNS query should work (pod-to-pod connectivity)
		By("Testing pod-to-pod connectivity for %s", src)
		res = kubectl.ExecPodCmd(randomNamespace, src, "dig kubernetes +time=2")
		res.ExpectSuccess()

		// When connecting from outside the cluster to a nodeport service whose pods are
		// selected by an egress policy, the reply traffic should not be SNATed with the
		// egress IP
		var extIPsService v1.Service
		err := kubectl.Get(randomNamespace, fmt.Sprintf("service %s", "test-external-ips")).Unmarshal(&extIPsService)
		ExpectWithOffset(1, err).Should(BeNil(), "Can not retrieve service %s", "test-external-ips")

		By("Patching service %s to use externalIP %s", "test-external-ips", hostIP)
		res = kubectl.Patch(randomNamespace, "service", "test-external-ips",
			fmt.Sprintf(`{"spec":{"externalIPs":["%s"],  "externalTrafficPolicy": "Local"}}`, hostIP))
		ExpectWithOffset(1, res).Should(helpers.CMDSuccess(), "Error patching external IP service with node IP")

		By("Waiting for %s to expose service frontend %s", hostName, hostIP)
		err = kubectl.WaitForServiceFrontend(hostName, hostIP)
		ExpectWithOffset(1, err).Should(BeNil(), "Failed waiting for %s frontend entry on %s", hostIP, hostName)

		By("Testing that a service backend's reply to an outside HTTP request is not SNATed with the egressIP")
		res = kubectl.ExecInHostNetNS(context.TODO(), outsideName,
			helpers.CurlFail("http://%s:%d", hostIP, extIPsService.Spec.Ports[0].Port))
		res.ExpectSuccess()
		res.ExpectMatchesRegexp(fmt.Sprintf("client_address=::ffff:%s\n", outsideIP))

		if testOpts.ciliumOpts["routingMode"] == "native" {
			// When connecting from outside the cluster directly to a pod which is
			// selected by an egress policy, the reply traffic should not be SNATed with
			// the egress IP (only connections originating from these pods should go
			// through egress gateway).
			//
			// This test is executed only when Cilium is running in direct routing mode,
			// since we can simply add a route on the node outside the cluster to direct
			// pod's traffic to the node where the pod is running (while in tunneling
			// mode we would need the external node to send the traffic over the tunnel)
			_, targetPodJSON := fetchPodsWithOffset(kubectl, randomNamespace, "server", testDS, hostIP, false, 1)

			_targetPodHostIP, err := targetPodJSON.Filter("{.status.hostIP}")
			Expect(err).Should(BeNil(), "Cannot get target pod host IP")
			targetPodHostIP := _targetPodHostIP.String()

			_targetPodIP, err := targetPodJSON.Filter("{.status.podIP}")
			Expect(err).Should(BeNil(), "Cannot get target pod IP")
			targetPodIP := _targetPodIP.String()

			// Add a route for the target pod's IP on the node running without Cilium to
			// allow reaching it from outside the cluster
			By("Adding a IP route for %s via %s", targetPodIP, targetPodHostIP)
			res = kubectl.AddIPRoute(outsideName, targetPodIP, targetPodHostIP, false)
			Expect(res).Should(helpers.CMDSuccess(),
				"Error adding IP route for %s via %s", targetPodIP, targetPodHostIP)

			By("Testing that a pod's reply to an outside HTTP request is not SNATed with the egressIP")
			res = kubectl.ExecInHostNetNS(context.TODO(), outsideName,
				helpers.CurlFail("http://%s:80", targetPodIP))

			By("Deleting the IP route for %s via %s", targetPodIP, targetPodHostIP)
			res2 := kubectl.DelIPRoute(outsideName, targetPodIP, targetPodHostIP)
			Expect(res2).Should(helpers.CMDSuccess(),
				"Error removing IP route for %s via %s", targetPodIP, targetPodHostIP)

			res.ExpectSuccess()
			res.ExpectMatchesRegexp(fmt.Sprintf("client_address=::ffff:%s\n", outsideIP))
		}
	}

	applyEgressPolicy := func(manifest string) string {
		// Apply egress policy yaml
		originalPolicyYAML := helpers.ManifestGet(kubectl.BasePath(), manifest)
		res := kubectl.ExecMiddle("mktemp")
		res.ExpectSuccess()
		policyYAML := strings.Trim(res.Stdout(), "\n")
		kubectl.ExecMiddle(fmt.Sprintf("sed 's/INPUT_EGRESS_IP/%s/' %s > %s",
			egressIP, originalPolicyYAML, policyYAML)).ExpectSuccess()
		kubectl.ExecMiddle(fmt.Sprintf("sed 's/INPUT_OUTSIDE_NODE_IP/%s/' -i %s",
			outsideIP, policyYAML)).ExpectSuccess()
		res = kubectl.ApplyDefault(policyYAML)
		Expect(res).Should(helpers.CMDSuccess(), "unable to apply %s", policyYAML)

		return policyYAML
	}

	doContext := func(name string, ciliumOpts map[string]string) {
		Context(name, func() {
			BeforeAll(func() {
				DeployCiliumOptionsAndDNS(kubectl, ciliumFilename, ciliumOpts)
				randomNamespace = deploymentManager.DeployRandomNamespaceShared(DemoDaemonSet)
				kubectl.NamespaceLabel(randomNamespace, namespaceSelector)
				deploymentManager.WaitUntilReady()
			})

			AfterAll(func() {
				deploymentManager.DeleteAll()
			})

			Context("no egress gw policy", func() {
				It("connectivity works", func() {
					testConnectivity(&egressGatewayConnectivityTestOpts{
						fromGateway: false,
						ciliumOpts:  ciliumOpts,
					})

					testConnectivity(&egressGatewayConnectivityTestOpts{
						fromGateway: true,
						ciliumOpts:  ciliumOpts,
					})
				})
			})

			Context("egress gw policy", func() {
				var policyYAML string

				BeforeAll(func() {
					policyYAML = applyEgressPolicy("egress-gateway-policy.yaml")

					// Wait for 6 entries:
					// - 3 policies, each with:
					//   - 2 matching endpoints
					//   - 1 destination CIDR

					err := kubectl.WaitForEgressPolicyEntries(helpers.K8s1, 6)
					Expect(err).Should(BeNil(), "Failed waiting for egress policy map entries")

					err = kubectl.WaitForEgressPolicyEntries(helpers.K8s2, 6)
					Expect(err).Should(BeNil(), "Failed waiting for egress policy map entries")
				})
				AfterAll(func() {
					kubectl.Delete(policyYAML)

					err := kubectl.WaitForEgressPolicyEntries(helpers.K8s1, 0)
					Expect(err).Should(BeNil(), "Failed waiting for egress policy map entries")

					err = kubectl.WaitForEgressPolicyEntries(helpers.K8s2, 0)
					Expect(err).Should(BeNil(), "Failed waiting for egress policy map entries")
				})

				AfterFailed(func() {
					kubectl.CiliumReport("cilium bpf egress list", "cilium bpf nat list")
				})

				It("both egress gw and basic connectivity work", func() {
					testEgressGateway(&egressGatewayTestOpts{
						fromGateway:    false,
						shouldBeSNATed: true,
					})

					testEgressGateway(&egressGatewayTestOpts{
						fromGateway:    true,
						shouldBeSNATed: true,
					})

					testConnectivity(&egressGatewayConnectivityTestOpts{
						fromGateway: false,
						ciliumOpts:  ciliumOpts,
					})

					testConnectivity(&egressGatewayConnectivityTestOpts{
						fromGateway: true,
						ciliumOpts:  ciliumOpts,
					})
				})
			})

			Context("egress gw policy with exclusion CIDRs", func() {
				var policyYAML string

				BeforeAll(func() {
					policyYAML = applyEgressPolicy("egress-gateway-policy-excl-cidr.yaml")

					// Wait for 4 entries:
					// - 1 policies with:
					//   - 2 matching endpoints
					//   - 1 destination CIDR
					//   - 1 excluded CIDR

					err := kubectl.WaitForEgressPolicyEntries(helpers.K8s1, 4)
					Expect(err).Should(BeNil(), "Failed waiting for egress policy map entries")

					err = kubectl.WaitForEgressPolicyEntries(helpers.K8s2, 4)
					Expect(err).Should(BeNil(), "Failed waiting for egress policy map entries")
				})
				AfterAll(func() {
					kubectl.Delete(policyYAML)

					err := kubectl.WaitForEgressPolicyEntries(helpers.K8s1, 0)
					Expect(err).Should(BeNil(), "Failed waiting for egress policy map entries")

					err = kubectl.WaitForEgressPolicyEntries(helpers.K8s2, 0)
					Expect(err).Should(BeNil(), "Failed waiting for egress policy map entries")
				})

				AfterFailed(func() {
					kubectl.CiliumReport("cilium bpf egress list", "cilium bpf nat list")
				})

				It("Traffic is not SNATed with egress gateway IP", func() {
					testEgressGateway(&egressGatewayTestOpts{
						fromGateway:    false,
						shouldBeSNATed: false,
					})

					testEgressGateway(&egressGatewayTestOpts{
						fromGateway:    true,
						shouldBeSNATed: false,
					})
				})
			})
			Context("egress gw policy when the gateway is not found", func() {
				var policyYAML string

				BeforeAll(func() {
					policyYAML = applyEgressPolicy("egress-gateway-policy-not-found.yaml")

					// Wait for 2 entries:
					// - 1 policy with 2 matching endpoints

					err := kubectl.WaitForEgressPolicyEntries(helpers.K8s1, 2)
					Expect(err).Should(BeNil(), "Failed waiting for egress policy map entries")

					err = kubectl.WaitForEgressPolicyEntries(helpers.K8s2, 2)
					Expect(err).Should(BeNil(), "Failed waiting for egress policy map entries")
				})
				AfterAll(func() {
					kubectl.Delete(policyYAML)

					err := kubectl.WaitForEgressPolicyEntries(helpers.K8s1, 0)
					Expect(err).Should(BeNil(), "Failed waiting for egress policy map entries")

					err = kubectl.WaitForEgressPolicyEntries(helpers.K8s2, 0)
					Expect(err).Should(BeNil(), "Failed waiting for egress policy map entries")
				})

				AfterFailed(func() {
					kubectl.CiliumReport("cilium bpf egress list", "cilium bpf nat list")
				})

				It("Traffic is dropped", func() {
					testEgressGateway(&egressGatewayTestOpts{
						fromGateway:    false,
						shouldBeSNATed: false,
						shouldFail:     true,
					})
					testEgressGateway(&egressGatewayTestOpts{
						fromGateway:    true,
						shouldBeSNATed: false,
						shouldFail:     true,
					})
				})
			})
		})
	}

	doContext("tunnel disabled with endpointRoutes enabled",
		map[string]string{
			"egressGateway.enabled":     "true",
			"bpf.masquerade":            "true",
			"routingMode":               "native",
			"autoDirectNodeRoutes":      "true",
			"endpointRoutes.enabled":    "true",
			"enableCiliumEndpointSlice": "false",
			"l7Proxy":                   "false",
		},
	)

	doContext("tunnel disabled with endpointRoutes disabled",
		map[string]string{
			"egressGateway.enabled":     "true",
			"bpf.masquerade":            "true",
			"routingMode":               "native",
			"autoDirectNodeRoutes":      "true",
			"endpointRoutes.enabled":    "false",
			"enableCiliumEndpointSlice": "false",
			"l7Proxy":                   "false",
		},
	)

	doContext("tunnel vxlan with endpointRoutes enabled",
		map[string]string{
			"egressGateway.enabled":     "true",
			"bpf.masquerade":            "true",
			"tunnelProtocol":            "vxlan",
			"autoDirectNodeRoutes":      "false",
			"endpointRoutes.enabled":    "true",
			"enableCiliumEndpointSlice": "false",
			"l7Proxy":                   "false",
		},
	)

	doContext("tunnel vxlan with endpointRoutes disabled",
		map[string]string{
			"egressGateway.enabled":     "true",
			"bpf.masquerade":            "true",
			"tunnelProtocol":            "vxlan",
			"autoDirectNodeRoutes":      "false",
			"endpointRoutes.enabled":    "false",
			"enableCiliumEndpointSlice": "false",
			"l7Proxy":                   "false",
		},
	)

	doContext("tunnel disabled with endpointRoutes enabled and XDP",
		map[string]string{
			"egressGateway.enabled":     "true",
			"bpf.masquerade":            "true",
			"routingMode":               "native",
			"autoDirectNodeRoutes":      "true",
			"endpointRoutes.enabled":    "true",
			"enableCiliumEndpointSlice": "false",
			"l7Proxy":                   "false",
			"loadBalancer.acceleration": "testing-only",
		},
	)

	doContext("tunnel disabled with endpointRoutes disabled and XDP",
		map[string]string{
			"egressGateway.enabled":     "true",
			"bpf.masquerade":            "true",
			"routingMode":               "native",
			"autoDirectNodeRoutes":      "true",
			"endpointRoutes.enabled":    "false",
			"enableCiliumEndpointSlice": "false",
			"l7Proxy":                   "false",
			"loadBalancer.acceleration": "testing-only",
		},
	)

	doContext("tunnel disabled with endpointRoutes disabled, XDP and DSR with Geneve dispatch",
		map[string]string{
			"egressGateway.enabled":     "true",
			"bpf.masquerade":            "true",
			"routingMode":               "native",
			"autoDirectNodeRoutes":      "true",
			"endpointRoutes.enabled":    "false",
			"enableCiliumEndpointSlice": "false",
			"l7Proxy":                   "false",
			"loadBalancer.acceleration": "testing-only",
			"loadBalancer.mode":         "dsr",
			"loadBalancer.algorithm":    "maglev",
			"tunnelProtocol":            "geneve",
			"maglev.tableSize":          "251",
			"loadBalancer.dsrDispatch":  "geneve",
		},
	)

	doContext("tunnel vxlan with endpointRoutes enabled and XDP",
		map[string]string{
			"egressGateway.enabled":     "true",
			"bpf.masquerade":            "true",
			"tunnelProtocol":            "vxlan",
			"autoDirectNodeRoutes":      "false",
			"endpointRoutes.enabled":    "true",
			"enableCiliumEndpointSlice": "false",
			"l7Proxy":                   "false",
			"loadBalancer.acceleration": "testing-only",
		},
	)

	doContext("tunnel vxlan with endpointRoutes disabled and XDP",
		map[string]string{
			"egressGateway.enabled":     "true",
			"bpf.masquerade":            "true",
			"tunnelProtocol":            "vxlan",
			"autoDirectNodeRoutes":      "false",
			"endpointRoutes.enabled":    "false",
			"enableCiliumEndpointSlice": "false",
			"l7Proxy":                   "false",
			"loadBalancer.acceleration": "testing-only",
		},
	)
})

// Use x.x.x.100 as the egress IP
func getEgressIP(nodeIP string) string {
	ip := net.ParseIP(nodeIP).To4()
	ip[3] = 100
	return ip.String()
}

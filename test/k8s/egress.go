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

var _ = SkipDescribeIf(func() bool {
	return helpers.RunsOnEKS() || helpers.RunsOnGKE() || helpers.DoesNotRunWithKubeProxyReplacement() || helpers.DoesNotExistNodeWithoutCilium() || helpers.DoesNotRunOn54OrLaterKernel()
}, "K8sEgressGatewayTest", func() {
	const (
		namespaceSelector = "ns=cilium-test"
		testDS            = "zgroup=testDS"
		testDSClient      = "zgroup=testDSClient"
		testDSClient2     = "zgroup=testDSClient2"
	)

	var (
		kubectl         *helpers.Kubectl
		ciliumFilename  string
		randomNamespace string

		egressIP  string
		k8s1IP    string
		k8s2IP    string
		outsideIP string

		assignIPYAML string
		echoPodYAML  string
		policyYAML   string
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

		_, k8s1IP = kubectl.GetNodeInfo(helpers.K8s1)
		_, k8s2IP = kubectl.GetNodeInfo(helpers.K8s2)
		_, outsideIP = kubectl.GetNodeInfo(kubectl.GetFirstNodeWithoutCiliumLabel())

		egressIP = getEgressIP(k8s1IP)

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
	})

	testEgressGateway := func(fromGateway bool) {
		if fromGateway {
			By("Check egress policy from gateway node")
		} else {
			By("Check egress policy from non-gateway node")
		}

		hostIP := k8s1IP
		if fromGateway {
			hostIP = k8s2IP
		}

		srcPod, _ := fetchPodsWithOffset(kubectl, randomNamespace, "client", testDSClient, hostIP, false, 1)
		srcPod2, _ := fetchPodsWithOffset(kubectl, randomNamespace, "client", testDSClient2, hostIP, false, 1)

		for _, src := range []string{srcPod, srcPod2} {
			ctEntriesBeforeConnection := ctEntriesOnNode(helpers.K8s2, outsideIP, "80")
			res := kubectl.ExecPodCmd(randomNamespace, src, helpers.CurlFail("http://%s:80", outsideIP))

			res.ExpectSuccess()
			res.ExpectMatchesRegexp(fmt.Sprintf("client_address=::ffff:%s\n", egressIP))

			ctEntriesAfterConnection := ctEntriesOnNode(helpers.K8s2, outsideIP, "80")
			Expect(ctEntriesAfterConnection - ctEntriesBeforeConnection).Should(Equal(1))
		}
	}

	testConnectivity := func(fromGateway bool, ciliumOpts map[string]string) {
		if fromGateway {
			By("Check connectivity from gateway node")
		} else {
			By("Check connectivity from non-gateway node")
		}
		hostIP := k8s1IP
		if fromGateway {
			hostIP = k8s2IP
		}
		srcPod, _ := fetchPodsWithOffset(kubectl, randomNamespace, "client", testDSClient, hostIP, false, 1)
		srcPod2, _ := fetchPodsWithOffset(kubectl, randomNamespace, "client", testDSClient2, hostIP, false, 1)

		for _, src := range []string{srcPod, srcPod2} {
			// Pod-to-node connectivity should work
			res := kubectl.ExecPodCmd(randomNamespace, src, helpers.PingWithCount(k8s1IP, 1))
			res.ExpectSuccess()

			res = kubectl.ExecPodCmd(randomNamespace, src, helpers.PingWithCount(k8s2IP, 1))
			res.ExpectSuccess()

			// DNS query should work (pod-to-pod connectivity)
			res = kubectl.ExecPodCmd(randomNamespace, src, "dig kubernetes +time=2")
			res.ExpectSuccess()

			// When connecting from outside the cluster to a nodeport service whose pods are
			// selected by an egress policy, the reply traffic should not be SNATed with the
			// egress IP
			var extIPsService v1.Service
			err := kubectl.Get(randomNamespace, fmt.Sprintf("service %s", "test-external-ips")).Unmarshal(&extIPsService)
			ExpectWithOffset(1, err).Should(BeNil(), "Can not retrieve service %s", "test-external-ips")

			res = kubectl.Patch(randomNamespace, "service", "test-external-ips",
				fmt.Sprintf(`{"spec":{"externalIPs":["%s"],  "externalTrafficPolicy": "Local"}}`, hostIP))
			ExpectWithOffset(1, res).Should(helpers.CMDSuccess(), "Error patching external IP service with node IP")

			outsideNodeName, outsideNodeIP := kubectl.GetNodeInfo(kubectl.GetFirstNodeWithoutCiliumLabel())

			res = kubectl.ExecInHostNetNS(context.TODO(), outsideNodeName,
				helpers.CurlFail("http://%s:%d", hostIP, extIPsService.Spec.Ports[0].Port))
			res.ExpectSuccess()
			res.ExpectMatchesRegexp(fmt.Sprintf("client_address=::ffff:%s\n", outsideNodeIP))

			if ciliumOpts["tunnel"] == "disabled" {
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

				targetPodHostIP, err := targetPodJSON.Filter("{.status.hostIP}")
				Expect(err).Should(BeNil(), "Cannot get target pod host IP")

				targetPodIP, err := targetPodJSON.Filter("{.status.podIP}")
				Expect(err).Should(BeNil(), "Cannot get target pod IP")

				// Add a route for the target pod's IP on the node running without Cilium to
				// allow reaching it from outside the cluster
				res = kubectl.AddIPRoute(outsideNodeName, targetPodIP.String(), targetPodHostIP.String(), false)
				Expect(res).Should(helpers.CMDSuccess(),
					"Error adding IP route for %s via %s", targetPodIP.String(), targetPodHostIP.String())

				res = kubectl.ExecInHostNetNS(context.TODO(), outsideNodeName,
					helpers.CurlFail("http://%s:80", targetPodIP.String()))

				res2 := kubectl.DelIPRoute(outsideNodeName, targetPodIP.String(), targetPodHostIP.String())
				Expect(res2).Should(helpers.CMDSuccess(),
					"Error removing IP route for %s via %s", targetPodIP.String(), targetPodHostIP.String())

				res.ExpectSuccess()
				res.ExpectMatchesRegexp(fmt.Sprintf("client_address=::ffff:%s\n", outsideNodeIP))
			}
		}
	}

	applyEgressPolicy := func(manifest string) {
		// Apply egress policy yaml
		originalPolicyYAML := helpers.ManifestGet(kubectl.BasePath(), manifest)
		res := kubectl.ExecMiddle("mktemp")
		res.ExpectSuccess()
		policyYAML = strings.Trim(res.Stdout(), "\n")
		kubectl.ExecMiddle(fmt.Sprintf("sed 's/INPUT_EGRESS_IP/%s/' %s > %s",
			egressIP, originalPolicyYAML, policyYAML)).ExpectSuccess()
		kubectl.ExecMiddle(fmt.Sprintf("sed 's/INPUT_OUTSIDE_NODE_IP/%s/' -i %s",
			outsideIP, policyYAML)).ExpectSuccess()
		res = kubectl.ApplyDefault(policyYAML)
		Expect(res).Should(helpers.CMDSuccess(), "unable to apply %s", policyYAML)
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
					testConnectivity(false, ciliumOpts)
					testConnectivity(true, ciliumOpts)
				})
			})

			Context("egress gw policy", func() {
				BeforeAll(func() {
					applyEgressPolicy("egress-gateway-policy.yaml")

					// Wait for 8 entries:
					// - cegp-sample matching 2 EPs with 1 destination CIDR
					// - egress-to-black-hole matching 2 EPs with 1 destination CIDR
					// - egress-testds matching 2 EPs with 1 destination CIDR
					// - cenp-sample matching 2 EPs with 1 destination CIDR

					err := kubectl.WaitForEgressPolicyEntries(helpers.K8s1, 8)
					Expect(err).Should(BeNil(), "Failed waiting for egress policy map entries")

					err = kubectl.WaitForEgressPolicyEntries(helpers.K8s2, 8)
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
					testEgressGateway(false)
					testEgressGateway(true)
					testConnectivity(false, ciliumOpts)
					testConnectivity(true, ciliumOpts)
				})
			})

			Context("egress gw policy upgrade", func() {
				BeforeAll(func() {
					applyEgressPolicy("egress-gateway-policy-upgrade.yaml")

					// Wait for 8 entries:
					// - cegp-sample matching 2 EPs with 1 destination CIDR
					// - cegp-sample-upgrade matching 2 EPs and 1 destination CIDR
					// - cenp-sample matching matching the same EPs/destination CIDR as cegp-sample-upgrade
					// - egress-to-black-hole matching 2 EPs with 1 destination CIDR
					// - egress-testds matching 2 EPs with 1 destination CIDR

					err := kubectl.WaitForEgressPolicyEntries(helpers.K8s1, 8)
					Expect(err).Should(BeNil(), "Failed waiting for egress policy map entries")

					err = kubectl.WaitForEgressPolicyEntries(helpers.K8s2, 8)
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
					testEgressGateway(false)
					testEgressGateway(true)
					testConnectivity(false, ciliumOpts)
					testConnectivity(true, ciliumOpts)

					// see if things still work after ripping out the
					// duplicated policy:
					kubectl.DeleteResource("cenp", "cenp-sample-upgrade")
					testEgressGateway(false)
					testEgressGateway(true)
					testConnectivity(false, ciliumOpts)
					testConnectivity(true, ciliumOpts)
				})
			})

		})
	}

	doContext("tunnel disabled with endpointRoutes enabled",
		map[string]string{
			"egressGateway.enabled":     "true",
			"bpf.masquerade":            "true",
			"tunnel":                    "disabled",
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
			"tunnel":                    "disabled",
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
			"tunnel":                    "vxlan",
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
			"tunnel":                    "vxlan",
			"autoDirectNodeRoutes":      "false",
			"endpointRoutes.enabled":    "false",
			"enableCiliumEndpointSlice": "false",
			"l7Proxy":                   "false",
		},
	)
})

// Use x.x.x.100 as the egress IP
func getEgressIP(nodeIP string) string {
	ip := net.ParseIP(nodeIP).To4()
	ip[3] = 100
	return ip.String()
}

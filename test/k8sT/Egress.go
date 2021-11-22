// Copyright 2021 Authors of Cilium
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
	"strings"

	. "github.com/cilium/cilium/test/ginkgo-ext"
	"github.com/cilium/cilium/test/helpers"
	. "github.com/onsi/gomega"
	v1 "k8s.io/api/core/v1"
)

var _ = SkipDescribeIf(func() bool {
	return helpers.RunsOnEKS() || helpers.RunsOnGKE() || helpers.DoesNotRunWithKubeProxyReplacement() || helpers.DoesNotExistNodeWithoutCilium() || helpers.DoesNotRunOn54OrLaterKernel()
}, "K8sEgressGatewayTest", func() {
	const (
		namespaceSelector = "ns=cilium-test"
		testDS            = "zgroup=testDS"
		testDSClient      = "zgroup=testDSClient"
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
			helpers.GetNodeWithoutCilium(), originalEchoPodPath, echoPodYAML)).ExpectSuccess()
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

	BeforeAll(func() {

		kubectl = helpers.CreateKubectl(helpers.K8s1VMName(), logger)

		_, k8s1IP = kubectl.GetNodeInfo(helpers.K8s1)
		_, k8s2IP = kubectl.GetNodeInfo(helpers.K8s2)
		_, outsideIP = kubectl.GetNodeInfo(helpers.GetNodeWithoutCilium())

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

		res := kubectl.ExecPodCmd(randomNamespace, srcPod, helpers.CurlFail("http://%s:80", outsideIP))
		res.ExpectSuccess()
		res.ExpectMatchesRegexp(fmt.Sprintf("client_address=::ffff:%s\n", egressIP))
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
		srcPod, _ := fetchPodsWithOffset(kubectl, randomNamespace, "client", "zgroup=testDSClient", hostIP, false, 1)

		// Pod-to-node connectivity should work
		res := kubectl.ExecPodCmd(randomNamespace, srcPod, helpers.PingWithCount(k8s1IP, 1))
		res.ExpectSuccess()

		res = kubectl.ExecPodCmd(randomNamespace, srcPod, helpers.PingWithCount(k8s2IP, 1))
		res.ExpectSuccess()

		// DNS query should work (pod-to-pod connectivity)
		res = kubectl.ExecPodCmd(randomNamespace, srcPod, "dig kubernetes +time=2")
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

		outsideNodeName, outsideNodeIP := kubectl.GetNodeInfo(helpers.GetNodeWithoutCilium())

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
			defer func() {
				res := kubectl.DelIPRoute(outsideNodeName, targetPodIP.String(), targetPodHostIP.String())
				Expect(res).Should(helpers.CMDSuccess(),
					"Error removing IP route for %s via %s", targetPodIP.String(), targetPodHostIP.String())
			}()

			res = kubectl.ExecInHostNetNS(context.TODO(), outsideNodeName,
				helpers.CurlFail("http://%s:%d", targetPodIP.String(), 80))
			res.ExpectSuccess()
			res.ExpectMatchesRegexp(fmt.Sprintf("client_address=::ffff:%s\n", outsideNodeIP))
		}
	}

	applyEgressPolicy := func() {
		// Apply egress policy yaml
		originalPolicyYAML := helpers.ManifestGet(kubectl.BasePath(), "egress-nat-policy.yaml")
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
				DeployCiliumAndDNS(kubectl, ciliumFilename)
			})

			Context("no egress gw policy", func() {
				It("connectivity works", func() {
					testConnectivity(false, ciliumOpts)
					testConnectivity(true, ciliumOpts)
				})
			})

			Context("egress gw policy", func() {
				BeforeAll(func() {
					applyEgressPolicy()
					kubectl.WaitForEgressPolicyEntry(k8s1IP, outsideIP)
					kubectl.WaitForEgressPolicyEntry(k8s2IP, outsideIP)
				})
				AfterAll(func() {
					kubectl.Delete(policyYAML)
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
		})
	}

	doContext("tunnel disabled with endpointRoutes enabled",
		map[string]string{
			"egressGateway.enabled":  "true",
			"bpf.masquerade":         "true",
			"tunnel":                 "disabled",
			"autoDirectNodeRoutes":   "true",
			"endpointRoutes.enabled": "true",
		},
	)

	doContext("tunnel disabled with endpointRoutes disabled",
		map[string]string{
			"egressGateway.enabled":  "true",
			"bpf.masquerade":         "true",
			"tunnel":                 "disabled",
			"autoDirectNodeRoutes":   "true",
			"endpointRoutes.enabled": "false",
		},
	)

	doContext("tunnel vxlan with endpointRoutes enabled",
		map[string]string{
			"egressGateway.enabled":  "true",
			"bpf.masquerade":         "true",
			"tunnel":                 "vxlan",
			"autoDirectNodeRoutes":   "false",
			"endpointRoutes.enabled": "true",
		},
	)

	doContext("tunnel vxlan with endpointRoutes disabled",
		map[string]string{
			"egressGateway.enabled":  "true",
			"bpf.masquerade":         "true",
			"tunnel":                 "vxlan",
			"autoDirectNodeRoutes":   "false",
			"endpointRoutes.enabled": "false",
		},
	)
})

// Use x.x.x.100 as the egress IP
func getEgressIP(nodeIP string) string {
	ip := net.ParseIP(nodeIP).To4()
	ip[3] = 100
	return ip.String()
}

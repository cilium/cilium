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
	"fmt"
	"net"
	"strings"

	. "github.com/cilium/cilium/test/ginkgo-ext"
	"github.com/cilium/cilium/test/helpers"
	. "github.com/onsi/gomega"
)

var _ = SkipDescribeIf(func() bool {
	return helpers.RunsOnEKS() || helpers.RunsOnGKE() || helpers.DoesNotRunWithKubeProxyReplacement() || helpers.DoesNotExistNodeWithoutCilium()
}, "K8sEgressGatewayTest", func() {
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

		namespaceSelector string = "ns=cilium-test"
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
		srcPod, _ := fetchPodsWithOffset(kubectl, randomNamespace, "client", "zgroup=testDSClient", hostIP, false, 1)

		res := kubectl.ExecPodCmd(randomNamespace, srcPod, helpers.CurlFail("http://%s:80", outsideIP))
		res.ExpectSuccess()
		res.ExpectMatchesRegexp(fmt.Sprintf("client_address=::ffff:%s\n", egressIP))
	}

	testConnectivity := func(fromGateway bool) {
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

	Context("tunnel disabled with endpoint routes enabled", func() {
		BeforeAll(func() {
			DeployCiliumOptionsAndDNS(kubectl, ciliumFilename, map[string]string{
				"egressGateway.enabled":  "true",
				"tunnel":                 "disabled",
				"autoDirectNodeRoutes":   "true",
				"bpf.masquerade":         "true",
				"endpointRoutes.enabled": "true",
			})

			randomNamespace = deploymentManager.DeployRandomNamespaceShared(DemoDaemonSet)
			kubectl.NamespaceLabel(randomNamespace, namespaceSelector)
			deploymentManager.WaitUntilReady()

		})

		AfterAll(func() {
			deploymentManager.DeleteAll()
			DeployCiliumAndDNS(kubectl, ciliumFilename)
		})

		It("Checks connectivity works without policy", func() {
			testConnectivity(false)
			testConnectivity(true)
		})

		It("Checks egress policy and basic connectivity both work", func() {
			applyEgressPolicy()
			kubectl.WaitForEgressPolicyEntry(k8s1IP, outsideIP)
			kubectl.WaitForEgressPolicyEntry(k8s2IP, outsideIP)

			defer kubectl.Delete(policyYAML)

			testEgressGateway(true)
			testEgressGateway(false)
			testConnectivity(true)
			testConnectivity(false)
		})

	})

	Context("tunnel disabled with endpoint routes disabled", func() {

		BeforeAll(func() {
			DeployCiliumOptionsAndDNS(kubectl, ciliumFilename, map[string]string{
				"egressGateway.enabled":  "true",
				"tunnel":                 "disabled",
				"autoDirectNodeRoutes":   "true",
				"bpf.masquerade":         "true",
				"endpointRoutes.enabled": "false",
			})

			randomNamespace = deploymentManager.DeployRandomNamespaceShared(DemoDaemonSet)
			kubectl.NamespaceLabel(randomNamespace, namespaceSelector)
			deploymentManager.WaitUntilReady()
		})

		AfterAll(func() {
			deploymentManager.DeleteAll()
			DeployCiliumAndDNS(kubectl, ciliumFilename)
		})

		It("Checks connectivity works without policy", func() {
			testConnectivity(false)
			testConnectivity(true)
		})

		It("Checks egress policy and basic connectivity both work", func() {
			applyEgressPolicy()
			kubectl.WaitForEgressPolicyEntry(k8s1IP, outsideIP)
			kubectl.WaitForEgressPolicyEntry(k8s2IP, outsideIP)

			defer kubectl.Delete(policyYAML)

			testEgressGateway(false)
			testEgressGateway(true)
			testConnectivity(false)
			testConnectivity(true)
		})

	})

	Context("tunnel vxlan", func() {

		BeforeAll(func() {
			DeployCiliumOptionsAndDNS(kubectl, ciliumFilename, map[string]string{
				"egressGateway.enabled": "true",
				"bpf.masquerade":        "true",
				"tunnel":                "vxlan",
			})

			randomNamespace = deploymentManager.DeployRandomNamespaceShared(DemoDaemonSet)
			kubectl.NamespaceLabel(randomNamespace, namespaceSelector)
			deploymentManager.WaitUntilReady()
		})

		AfterAll(func() {
			deploymentManager.DeleteAll()
			DeployCiliumAndDNS(kubectl, ciliumFilename)
		})

		It("Checks connectivity works without policy", func() {
			testConnectivity(false)
			testConnectivity(true)
		})

		It("Checks egress policy and basic connectivity both work", func() {
			applyEgressPolicy()
			kubectl.WaitForEgressPolicyEntry(k8s1IP, outsideIP)
			kubectl.WaitForEgressPolicyEntry(k8s2IP, outsideIP)

			defer kubectl.Delete(policyYAML)

			testEgressGateway(false)
			testEgressGateway(true)
			testConnectivity(false)
			testConnectivity(true)
		})

	})

})

// Use x.x.x.100 as the egress IP
func getEgressIP(nodeIP string) string {
	ip := net.ParseIP(nodeIP).To4()
	ip[3] = 100
	return ip.String()
}

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
	"fmt"
	"net"
	"strings"
	"time"

	. "github.com/cilium/cilium/test/ginkgo-ext"
	"github.com/cilium/cilium/test/helpers"
	. "github.com/onsi/gomega"
)

var _ = Describe("K8sEgressGatewayTest", func() {
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
	}

	BeforeAll(func() {
		if !helpers.ExistNodeWithoutCilium() {
			Skip("EgressGatewayTest requires outside nodes")
		}

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
		kubectl.CiliumReport("cilium bpf egress list", "cilium endpoint list")
	})

	testEgressGateway := func(fromGateway bool) {
		hostIP := k8s1IP
		if fromGateway {
			hostIP = k8s2IP
		}
		srcPod, _ := fetchPodsWithOffset(kubectl, randomNamespace, "client", "zgroup=testDSClient", hostIP, false, 1)

		res := kubectl.ExecPodCmd(randomNamespace, srcPod, helpers.CurlFail("http://%s:80", outsideIP))
		res.ExpectSuccess()
		res.ExpectMatchesRegexp(fmt.Sprintf("client_address=::ffff:%s\n", egressIP))
	}

	applyEgressPolicy := func() {
		// Apply egress policy yaml
		originalPolicyYAML := helpers.ManifestGet(kubectl.BasePath(), "egress-policy-demo.yaml")
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

	Context("tunnel disabled", func() {
		BeforeAll(func() {
			DeployCiliumOptionsAndDNS(kubectl, ciliumFilename, map[string]string{
				"egressGateway.enabled": "true",
				"tunnel":                "disabled",
				"bpf.masquerade":        "true",
			})

			randomNamespace = deploymentManager.DeployRandomNamespaceShared(DemoDaemonSet)
			deploymentManager.WaitUntilReady()

			applyEgressPolicy()
			// There is no easy way to wait for policy to be reconciled now
			time.Sleep(time.Second)
		})

		AfterAll(func() {
			_ = kubectl.Delete(policyYAML)

			deploymentManager.DeleteAll()
			DeployCiliumAndDNS(kubectl, ciliumFilename)

		})

		It("Checks egress IP is applied to egress traffic", func() {
			testEgressGateway(false)
			testEgressGateway(true)
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
			deploymentManager.WaitUntilReady()

			applyEgressPolicy()
			// There is no easy way to wait for policy to be reconciled now
			time.Sleep(time.Second)
		})

		AfterAll(func() {
			_ = kubectl.Delete(policyYAML)

			deploymentManager.DeleteAll()
			DeployCiliumAndDNS(kubectl, ciliumFilename)
		})

		It("Checks egress IP is applied to egress traffic", func() {
			testEgressGateway(false)
			testEgressGateway(true)
		})

	})

})

// Use x.x.x.100 as the egress IP
func getEgressIP(nodeIP string) string {
	ip := net.ParseIP(nodeIP).To4()
	ip[3] = 100
	return ip.String()
}

// Copyright 2020 Authors of Cilium
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
	"bytes"
	"fmt"
	"net"
	"path/filepath"

	. "github.com/cilium/cilium/test/ginkgo-ext"
	"github.com/cilium/cilium/test/helpers"
	"github.com/cilium/cilium/test/k8sT/manifests/externalIPs"

	. "github.com/onsi/ginkgo/extensions/table"
	. "github.com/onsi/gomega"
)

const (
	namespaceTest = "external-ips-test"
)

var _ = Describe("K8sKubeProxyFreeMatrix tests", func() {
	var (
		kubectl      *helpers.Kubectl
		podNode1     string
		podNode2     string
		hostPodNode1 string
		hostPodNode2 string
	)
	run := func(ns, pod, ip, port string) string {
		curlCmd := fmt.Sprintf("curl --connect-timeout 2 -v %s", net.JoinHostPort(ip, port))
		cmd := kubectl.ExecPodContainerCmd(ns, pod, "curl", curlCmd)
		b := cmd.CombineOutput().Bytes()
		var got string
		switch {
		case bytes.Contains(b, []byte("Guestbook")):
			got = "app1"
		case bytes.Contains(b, []byte("Connection refused")):
			got = "connection refused"
		case bytes.Contains(b, []byte("No route to host")),
			bytes.Contains(b, []byte("Host is unreachable")),
			bytes.Contains(b, []byte("Connection timed out")):
			got = "No route to host / connection timed out"
		case bytes.Contains(b, []byte("It works!")):
			got = "app2"
		case bytes.Contains(b, []byte("app4")):
			got = "app4"
		case bytes.Contains(b, []byte("app6")):
			got = "app6"
		default:
			got = "None? " + string(b)
		}
		return got
	}

	getPodName := func(lbl string) string {
		podNames, err := kubectl.GetPodNames(namespaceTest, lbl)
		Expect(err).To(BeNil(), "Cannot get pods names")
		Expect(len(podNames)).To(BeNumerically("=", 1), "No pods available to test connectivity, expected 1, got", len(podNames))
		return podNames[0]
	}
	getPodNodeName := func(nodeName, lbl string) string {
		podNames, err := kubectl.GetPodsNodes(namespaceTest, lbl)
		Expect(err).To(BeNil(), "Cannot get pods names")
		Expect(len(podNames)).To(BeNumerically(">", 0), "No pods available to test connectivity")
		podName, ok := podNames[nodeName]
		Expect(ok).To(BeTrue(), "No pods available to test connectivity, expected pods to be running on node", nodeName)
		return podName
	}

	BeforeAll(func() {
		kubectl = helpers.CreateKubectl(helpers.K8s1VMName(), logger)
		DeployCiliumAndDNS(kubectl)

		res := kubectl.NamespaceCreate(namespaceTest)
		res.ExpectSuccess("unable to create namespace %q", namespaceTest)

		externalIPsDir := filepath.Join(kubectl.BasePath(), "externalIPs")

		appsDir := filepath.Join(externalIPsDir, "apps")
		kubectl.Apply(helpers.ApplyOptions{
			FilePath: appsDir,
		})

		err := kubectl.WaitforPods(namespaceTest, "", helpers.HelperTimeout)
		Expect(err).To(BeNil())

		podNode1 = getPodName("-l id=app1")
		podNode2 = getPodName("-l id=app3")
		hostPodNode1 = getPodNodeName(helpers.K8s1VMName(), "-l id=host-client")
		hostPodNode2 = getPodNodeName(helpers.K8s2VMName(), "-l id=host-client")

		publicIPGrep := fmt.Sprintf(`ip -4 address show dev %s | grep inet | awk '{ print $2 }' | sed 's+/.*++'`, external_ips.PublicInterfaceName)
		privateIPGrep := fmt.Sprintf(`ip -4 address show dev %s | grep inet | awk '{ print $2 }' | sed 's+/.*++'`, external_ips.PrivateInterfaceName)
		cmd := kubectl.ExecPodContainerCmd(namespaceTest, hostPodNode1, "curl", publicIPGrep)
		publicIP := cmd.CombineOutput().String()
		cmd = kubectl.ExecPodContainerCmd(namespaceTest, hostPodNode1, "curl", privateIPGrep)
		privateIP := cmd.CombineOutput().String()

		svcsDir := filepath.Join(externalIPsDir, "svcs")

		svcA := filepath.Join(svcsDir, "svc-a-external-ips.yaml")
		svcB := filepath.Join(svcsDir, "svc-b-external-ips.yaml")
		svcC := filepath.Join(svcsDir, "svc-c-node-port.yaml")
		svcD := filepath.Join(svcsDir, "svc-d-node-port.yaml")
		svcE := filepath.Join(svcsDir, "svc-e-node-port.yaml")
		patch := fmt.Sprintf(`{spec:{"externalIPs":["192.0.2.223","%s","%s"]}}`, publicIP, privateIP)
		err = kubectl.DeployPatchStdIn(svcA, patch)
		Expect(err).To(BeNil())
		err = kubectl.DeployPatchStdIn(svcB, patch)
		Expect(err).To(BeNil())

		kubectl.ApplyDefault(svcC).ExpectSuccess("Unable to deploy service-c")
		kubectl.ApplyDefault(svcD).ExpectSuccess("Unable to deploy service-d")
		kubectl.ApplyDefault(svcE).ExpectSuccess("Unable to deploy service-e")
	})

	AfterFailed(func() {
		kubectl.CiliumReport(helpers.KubeSystemNamespace,
			"cilium service list",
			"cilium endpoint list")
	})

	AfterAll(func() {
		_ = kubectl.NamespaceDelete(namespaceTest)
		ExpectAllPodsTerminated(kubectl)
		kubectl.CloseSSHClient()
	})

	DescribeTable("From pod running on node-1 to services being backed by a pod running on node-1",
		func(ip, port, expected, skipReason string) {
			// clientPod := "app1-749d589d77-4qnlh"
			got := run(namespaceTest, podNode1, ip, port)
			if skipReason != "" {
				if got != expected {
					Skip(skipReason)
				}
				Expect(got).ToNot(Equal(expected), "It seems this test is disabled but your changes have fix this test case")
				return
			}
			Expect(got).To(Equal(expected))
		},
		getTableEntries(external_ips.ExpectedResultFromPodInNode1)...,
	)
	DescribeTable("From host running on node-1 to services being backed by a pod running on node-1",
		func(ip, port, expected, skipReason string) {
			// clientPod := "host-client-mt4wv"
			got := run(namespaceTest, hostPodNode1, ip, port)
			if skipReason != "" {
				if got != expected {
					Skip(skipReason)
				}
				Expect(got).ToNot(Equal(expected), "It seems this test is disabled but your changes have fix this test case")
				return
			}
			Expect(got).To(Equal(expected))
		},
		getTableEntries(external_ips.ExpectedResultFromNode1)...,
	)
	DescribeTable("From pod running on node-2 to services being backed by a pod running on node-1",
		func(ip, port, expected, skipReason string) {
			// clientPod := "app3-cf6c8d494-nvk9v"
			got := run(namespaceTest, podNode2, ip, port)
			if skipReason != "" {
				if got != expected {
					Skip(skipReason)
				}
				Expect(got).ToNot(Equal(expected), "It seems this test is disabled but your changes have fix this test case")
				return
			}
			Expect(got).To(Equal(expected))
		},
		getTableEntries(external_ips.ExpectedResultFromPodInNode2)...,
	)
	DescribeTable("From host running on node-2 to services being backed by a pod running on node-1",
		func(ip, port, expected, skipReason string) {
			// clientPod := "host-client-nz96t"
			got := run(namespaceTest, hostPodNode2, ip, port)
			if skipReason != "" {
				if got != expected {
					Skip(skipReason)
				}
				Expect(got).ToNot(Equal(expected), "It seems this test is disabled but your changes have fix this test case")
				return
			}
			Expect(got).To(Equal(expected))
		},
		getTableEntries(external_ips.ExpectedResultFromNode2)...,
	)
	// DescribeTable("From host running on node-3 to services being backed by a pod running on node-1",
	// 	func(ip, port, expected , skipReason string) {
	// 		namespace := "external-ips-test"
	// 		clientPod := "host-client-nz96t"
	// 		got := run(namespace, clientPod, ip, port)
	// 		// fmt.Println(cmd, got)
	// 		Expect(got).To(Equal(expected))
	// 	},
	// 	podNode1ToPodNode1...,
	// )
})

func getTableEntries(expectedResult map[string]map[string]external_ips.EntryTestArgs) []TableEntry {
	var te []TableEntry
	for _, ipPortTest := range expectedResult {
		for _, testCaseExpected := range ipPortTest {
			te = append(te, Entry(
				fmt.Sprintf("%s curl %s",
					testCaseExpected.Description,
					net.JoinHostPort(testCaseExpected.IP, testCaseExpected.Port),
				),
				testCaseExpected.IP,
				testCaseExpected.Port,
				testCaseExpected.Expected,
				testCaseExpected.SkipReason,
			))
		}
	}
	return te
}

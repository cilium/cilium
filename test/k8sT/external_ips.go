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
	"context"
	"fmt"
	"net"
	"path/filepath"
	"time"

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
		kubectl             *helpers.Kubectl
		ciliumFilename      string
		podNode1            string
		podNode2            string
		hostNetworkPodNode1 string
		hostNetworkPodNode2 string

		// name2IP maps the service-name-cluster-ip to the running clusterIP
		// assigned by kubernetes. Since the IPs are ephemeral over CI runs,
		// it's the only way we can have consistent test results for the same
		// unit test.
		name2IP = map[string]string{
			"svc-a-external-ips-cluster-ip": "",
			"svc-b-external-ips-cluster-ip": "",
			"svc-c-node-port-cluster-ip":    "",
			"svc-d-node-port-cluster-ip":    "",
			"svc-e-node-port-cluster-ip":    "",
		}
	)

	// deploys cilium with the given options.
	deployCilium := func(options map[string]string) {
		DeployCiliumOptionsAndDNS(kubectl, ciliumFilename, options)

		_, err := kubectl.CiliumNodesWait()
		ExpectWithOffset(1, err).Should(BeNil(), "Failure while waiting for k8s nodes to be annotated by Cilium")

		By("Making sure all endpoints are in ready state")
		err = kubectl.CiliumEndpointWaitReady()
		ExpectWithOffset(1, err).To(BeNil(), "Failure while waiting for all cilium endpoints to reach ready state")
	}

	// Returns the pod nome for the given label.
	getPodName := func(lbl string) string {
		podNames, err := kubectl.GetPodNames(namespaceTest, lbl)
		Expect(err).To(BeNil(), "Cannot get pods names")
		Expect(len(podNames)).To(BeNumerically("==", 1), "No pods available to test connectivity, expected 1, got %d", len(podNames))
		return podNames[0]
	}

	// Returns the pod name running in the given node for the given filter.
	getPodNodeName := func(nodeName, filter string) string {
		podNames, err := kubectl.GetPodsNodes(namespaceTest, filter)
		Expect(err).To(BeNil(), "Cannot get pods names")
		Expect(len(podNames)).To(BeNumerically(">", 0), "No pods available to test connectivity")
		var podName string
		for nodePodName, node := range podNames {
			if nodeName == node {
				podName = nodePodName
				break
			}
		}
		Expect(podName).To(Not(Equal("")), "No pods available to test connectivity, expected pods to be running on node %s: %+v", nodeName, podNames)
		return podName
	}

	BeforeAll(func() {
		if !helpers.RunsOnNetNext() {
			return
		}
		kubectl = helpers.CreateKubectl(helpers.K8s1VMName(), logger)
		ciliumFilename = helpers.TimestampFilename("cilium.yaml")
		DeployCiliumAndDNS(kubectl, ciliumFilename)

		// create namespace used for this test
		res := kubectl.NamespaceCreate(namespaceTest)
		res.ExpectSuccess("unable to create namespace %q", namespaceTest)

		externalIPsDir := helpers.ManifestGet(kubectl.BasePath(), "externalIPs")

		// Deploy server and client pods
		appsDir := filepath.Join(externalIPsDir, "apps")
		kubectl.ApplyDefault(appsDir)
		err := kubectl.WaitforPods(namespaceTest, "", helpers.HelperTimeout)
		Expect(err).To(BeNil())

		podNode1 = getPodName("id=app1")
		podNode2 = getPodName("id=app3")
		hostNetworkPodNode1 = getPodNodeName(helpers.K8s1, "-l id=host-client")
		hostNetworkPodNode2 = getPodNodeName(helpers.K8s2, "-l id=host-client")

		// map the public and private ip addresses of k8s1. We need to do this
		// since the public and private IP addresses are also ephemeral across
		// CI runs.
		getIntIP := `ip -4 address show dev %s | grep inet | awk '{ print $2 }' | sed 's+/.*++' | tr -d '\n'`
		publicIPGrep := fmt.Sprintf(getIntIP, external_ips.PublicInterfaceName)
		privateIPGrep := fmt.Sprintf(getIntIP, external_ips.PrivateInterfaceName)
		cmd := kubectl.ExecPodContainerCmd(namespaceTest, hostNetworkPodNode1, "curl", publicIPGrep)
		publicIP := cmd.CombineOutput().String()
		cmd = kubectl.ExecPodContainerCmd(namespaceTest, hostNetworkPodNode1, "curl", privateIPGrep)
		privateIP := cmd.CombineOutput().String()

		for k, v := range external_ips.NetDevTranslation {
			switch v {
			case external_ips.PublicInterfaceName:
				name2IP[k] = publicIP
			case external_ips.PrivateInterfaceName:
				name2IP[k] = privateIP
			}
		}

		svcsDir := filepath.Join(externalIPsDir, "svcs")

		svcA := filepath.Join(svcsDir, "svc-a-external-ips.yaml")
		svcB := filepath.Join(svcsDir, "svc-b-external-ips.yaml")
		svcC := filepath.Join(svcsDir, "svc-c-node-port.yaml")
		svcD := filepath.Join(svcsDir, "svc-d-node-port.yaml")
		svcE := filepath.Join(svcsDir, "svc-e-node-port.yaml")

		// Create svcA and svcB with the patched IP addresses that we have discovered
		patch := fmt.Sprintf(`'{"spec":{"externalIPs":["192.0.2.223","%s","%s"]}}'`, publicIP, privateIP)
		err = kubectl.DeployPatchStdIn(svcA, patch)
		Expect(err).To(BeNil())
		err = kubectl.DeployPatchStdIn(svcB, patch)
		Expect(err).To(BeNil())

		kubectl.ApplyDefault(svcC).ExpectSuccess("Unable to deploy service-c")
		kubectl.ApplyDefault(svcD).ExpectSuccess("Unable to deploy service-d")
		kubectl.ApplyDefault(svcE).ExpectSuccess("Unable to deploy service-e")

		setClusterIPOf := func(name string) {
			ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
			defer cancel()
			clusterIP, err := kubectl.GetSvcIP(ctx, namespaceTest, name)
			Expect(err).To(BeNil())
			name2IP[name+"-cluster-ip"] = clusterIP
		}

		setClusterIPOf("svc-a-external-ips")
		setClusterIPOf("svc-b-external-ips")
		setClusterIPOf("svc-c-node-port")
		setClusterIPOf("svc-d-node-port")
		setClusterIPOf("svc-e-node-port")
	})

	AfterFailed(func() {
		if !helpers.RunsOnNetNext() {
			return
		}
		kubectl.CiliumReport(helpers.CiliumNamespace,
			"cilium service list",
			"cilium endpoint list")
	})

	AfterAll(func() {
		if !helpers.RunsOnNetNext() {
			return
		}
		_ = kubectl.NamespaceDelete(namespaceTest)
		kubectl.DeleteCiliumDS()
		ExpectAllPodsTerminated(kubectl)
		kubectl.CloseSSHClient()
	})

	testFunc := func(podClient string) func(ipName, ip, port, expected, skipReason string) {
		return func(ipName, ip, port, expected, skipReason string) {
			testIP, ok := name2IP[ipName]
			if !ok {
				testIP = ip
			}
			curlCmd := fmt.Sprintf("curl --connect-timeout 2 -v %s", net.JoinHostPort(testIP, port))
			cmd := kubectl.ExecPodContainerCmd(namespaceTest, podClient, "curl", curlCmd)
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

			if skipReason != "" {
				if got != expected {
					Skip(skipReason)
					return
				}
				// TODO @brb, once the kube-proxy free is merged in master
				// we can uncomment this
				// Expect(got).ToNot(Equal(expected), "It seems this test is disabled but your changes have fix this test case")
				return
			}
			Expect(got).To(Equal(expected), cmd.GetCmd())
		}
	}

	SkipContextIf(
		func() bool { return helpers.DoesNotRunOnNetNext() },
		"DirectRouting", func() {
			BeforeAll(func() {
				deployCilium(map[string]string{
					"global.tunnel":               "disabled",
					"global.autoDirectNodeRoutes": "true",
					"global.nodePort.device":      external_ips.PublicInterfaceName,
					"global.nodePort.enabled":     "true",
				})
			})
			DescribeTable("From pod running on node-1 to services being backed by a pod running on node-1",
				func(ipName, ip, port, expected, skipReason string) {
					testFunc(podNode1)(ipName, ip, port, expected, skipReason)
				},
				getTableEntries(external_ips.ExpectedResultFromPodInNode1)...,
			)
			DescribeTable("From host running on node-1 to services being backed by a pod running on node-1",
				func(ipName, ip, port, expected, skipReason string) {
					testFunc(hostNetworkPodNode1)(ipName, ip, port, expected, skipReason)
				},
				getTableEntries(external_ips.ExpectedResultFromNode1)...,
			)
			DescribeTable("From pod running on node-2 to services being backed by a pod running on node-1",
				func(ipName, ip, port, expected, skipReason string) {
					testFunc(podNode2)(ipName, ip, port, expected, skipReason)
				},
				getTableEntries(external_ips.ExpectedResultFromPodInNode2)...,
			)
			DescribeTable("From host running on node-2 to services being backed by a pod running on node-1",
				func(ipName, ip, port, expected, skipReason string) {
					testFunc(hostNetworkPodNode2)(ipName, ip, port, expected, skipReason)
				},
				getTableEntries(external_ips.ExpectedResultFromNode2)...,
			)
			// TODO: Enable me once the 3rd VM is added to the CI
			// DescribeTable("From host running on node-3 to services being backed by a pod running on node-1",
			// 	func(ipName, ip, port, expected, skipReason string) {
			// 		testFunc(hostNetworkPodNode3)(ipName, ip, port, expected, skipReason)
			// 	},
			// 	getTableEntries(external_ips.ExpectedResultFromNode2)...,
			// )
		},
	)

	SkipContextIf(
		func() bool { return helpers.DoesNotRunOnNetNext() },
		"VxLANMode", func() {
			BeforeAll(func() {
				deployCilium(map[string]string{
					"global.tunnel":           "vxlan",
					"global.nodePort.device":  external_ips.PublicInterfaceName,
					"global.nodePort.enabled": "true",
				})
			})
			DescribeTable("From pod running on node-1 to services being backed by a pod running on node-1",
				func(ipName, ip, port, expected, skipReason string) {
					testFunc(podNode1)(ipName, ip, port, expected, skipReason)
				},
				getTableEntries(external_ips.ExpectedResultFromPodInNode1)...,
			)
			DescribeTable("From host running on node-1 to services being backed by a pod running on node-1",
				func(ipName, ip, port, expected, skipReason string) {
					testFunc(hostNetworkPodNode1)(ipName, ip, port, expected, skipReason)
				},
				getTableEntries(external_ips.ExpectedResultFromNode1)...,
			)
			DescribeTable("From pod running on node-2 to services being backed by a pod running on node-1",
				func(ipName, ip, port, expected, skipReason string) {
					testFunc(podNode2)(ipName, ip, port, expected, skipReason)
				},
				getTableEntries(external_ips.ExpectedResultFromPodInNode2)...,
			)
			DescribeTable("From host running on node-2 to services being backed by a pod running on node-1",
				func(ipName, ip, port, expected, skipReason string) {
					testFunc(hostNetworkPodNode2)(ipName, ip, port, expected, skipReason)
				},
				getTableEntries(external_ips.ExpectedResultFromNode2)...,
			)
			// TODO: Enable me once the 3rd VM is added to the CI
			// DescribeTable("From host running on node-3 to services being backed by a pod running on node-1",
			// 	func(ipName, ip, port, expected, skipReason string) {
			// 		testFunc(hostNetworkPodNode3)(ipName, ip, port, expected, skipReason)
			// 	},
			// 	getTableEntries(external_ips.ExpectedResultFromNode2)...,
			// )
		},
	)
})

func getTableEntries(expectedResult map[string]map[string]external_ips.EntryTestArgs) []TableEntry {
	var te []TableEntry
	for ipName, ipPortTest := range expectedResult {
		for _, testCaseExpected := range ipPortTest {
			te = append(te, Entry(
				fmt.Sprintf("%s curl %s",
					testCaseExpected.Description,
					net.JoinHostPort(ipName, testCaseExpected.Port),
				),
				ipName,
				testCaseExpected.IP,
				testCaseExpected.Port,
				testCaseExpected.Expected,
				testCaseExpected.SkipReason,
			))
		}
	}
	return te
}

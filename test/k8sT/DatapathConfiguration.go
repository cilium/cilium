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
	"time"

	. "github.com/cilium/cilium/test/ginkgo-ext"
	"github.com/cilium/cilium/test/helpers"

	. "github.com/onsi/gomega"
	"github.com/sirupsen/logrus"
)

var _ = Describe("K8sDatapathConfig", func() {

	var kubectl *helpers.Kubectl
	var demoDSPath string
	var ipsecDSPath string

	BeforeAll(func() {
		kubectl = helpers.CreateKubectl(helpers.K8s1VMName(), logger)
		demoDSPath = helpers.ManifestGet("demo_ds.yaml")
		ipsecDSPath = helpers.ManifestGet("ipsec_ds.yaml")

		kubectl.Exec("kubectl -n kube-system delete ds cilium")

		Expect(waitToDeleteCilium(kubectl, logger)).To(BeNil(), "timed out deleting Cilium pods")
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

		// Do not assert on success in AfterEach intentionally to avoid
		// incomplete teardown.
		_ = kubectl.DeleteResource(
			"ds", fmt.Sprintf("-n %s cilium", helpers.KubeSystemNamespace))
		Expect(waitToDeleteCilium(kubectl, logger)).To(BeNil(), "timed out deleting Cilium pods")
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
			testPodConnectivityAcrossNodes(kubectl, true, true, "Connectivity test with IPsec between nodes failed")
			cleanService()
		}, 600)

		It("Check connectivity with sockops and VXLAN encapsulation", func() {
			// Note if run on kernel without sockops feature is ignored
			deployCilium([]string{
				"--set global.sockops.enabled=true",
			})
			validateBPFTunnelMap()
			testPodConnectivityAcrossNodes(kubectl, true, true, "Connectivity test with sockops & vxlan between nodes failed")
			cleanService()
		}, 600)

		It("Check connectivity with VXLAN encapsulation", func() {
			deployCilium([]string{
				"--set global.tunnel=vxlan",
			})
			validateBPFTunnelMap()
			testPodConnectivityAcrossNodes(kubectl, true, true, "Connectivity test with vxlan between nodes failed")
			cleanService()
		}, 600)

		It("Check connectivity with Geneve encapsulation", func() {
			deployCilium([]string{
				"--set global.tunnel=geneve",
			})
			validateBPFTunnelMap()
			testPodConnectivityAcrossNodes(kubectl, true, true, "Connectivity test with geneve between nodes failed")
			cleanService()
		})
	})

	Context("DirectRouting", func() {
		It("Check connectivity with automatic direct nodes routes", func() {
			SkipIfFlannel()

			deployCilium([]string{
				"--set global.tunnel=disabled",
				"--set global.autoDirectNodeRoutes=true",
			})
			testPodConnectivityAcrossNodes(kubectl, true, true, "Connectivity test with direct routing between nodes failed")
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
			testPodConnectivityAcrossNodes(kubectl, true, true, "Connectivity test with transparent encyrption & direct routing between nodes failed")
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
			testPodConnectivityAcrossNodes(kubectl, true, false, "Connectivity test with IPv4 only between nodes failed")
			cleanService()
		})
	})

	Context("IPv6Only", func() {
		It("Check connectivity with IPv4 disabled", func() {
			// Flannel always disables IPv6, this test is a no-op in that case.
			SkipIfFlannel()

			deployCilium([]string{
				"--set global.ipv4.enabled=false",
				"--set global.ipv6.enabled=true",
				"--set global.tunnel=vxlan",
			})
			testPodConnectivityAcrossNodes(kubectl, false, true, "Connectivity test with IPv6 only between nodes failed")
			cleanService()
		})
	})

	Context("PerEndpointRoute", func() {
		It("Check connectivity with per endpoint routes", func() {
			// Flannel always disables IPv6, this test is a no-op in that case.
			SkipIfFlannel()

			deployCilium([]string{
				"--set global.endpointRoutes.enabled=true",
			})
			testPodConnectivityAcrossNodes(kubectl, false, false, "Connectivity test between nodes failed")
			cleanService()
		})
	})

	Context("ManagedEtcd", func() {
		It("Check connectivity with managed etcd", func() {
			deployCilium([]string{
				"--set global.etcd.enabled=true",
				"--set global.etcd.managed=true",
			})
			testPodConnectivityAcrossNodes(kubectl, true, true, "Connectivity test with managed etcd only between nodes failed")
			cleanService()
		})
	})
})

func testPodConnectivityAcrossNodes(kubectl *helpers.Kubectl, checkNodeIPv4, checkNodeIPv6 bool, desc string) {
	By("Checking pod connectivity between nodes")

	filter := "zgroup=testDS"

	err := kubectl.WaitforPods(helpers.DefaultNamespace, fmt.Sprintf("-l %s", filter), helpers.HelperTimeout)
	ExpectWithOffset(1, err).Should(BeNil(), "%s: Failure while waiting for connectivity test pods to start", desc)

	pods, err := kubectl.GetPodNames(helpers.DefaultNamespace, filter)
	Expect(err).Should(BeNil(), "%s: Failure while retrieving pod name for %s", desc, filter)
	podIP, err := kubectl.Get(
		helpers.DefaultNamespace,
		fmt.Sprintf("pod %s -o json", pods[1])).Filter("{.status.podIP}")
	Expect(err).Should(BeNil(), "%s: Failure to retrieve IP of pod %s", desc, pods[1])

	res := kubectl.ExecPodCmd(helpers.DefaultNamespace, pods[0], helpers.Ping(podIP.String()))
	res.ExpectSuccess("%s: Pod %s cannot ping to pod %s(%s)", desc, pods[0], pods[1], podIP)

	// short-circuit node IP connectivity checks if not requested
	if !(checkNodeIPv4 || checkNodeIPv6) {
		return
	}

	// for each pod
	//   ping each node
	ipv4Addr, ipv6Addr, err := kubectl.GetNodeAddresses()
	Expect(err).Should(BeNil(), "%s: Failure while retrieving nodes %s", desc, filter)
	for _, pod := range pods {
		if checkNodeIPv4 {
			for nodeIP := range ipv4Addr {
				res := kubectl.ExecPodCmd(helpers.DefaultNamespace, pod, helpers.Ping(nodeIP))
				res.ExpectSuccess("%s: Pod %s cannot ping to Node IP %s", desc, pod, nodeIP)
			}
		}

		if checkNodeIPv6 {
			for nodeIP := range ipv6Addr {
				res := kubectl.ExecPodCmd(helpers.DefaultNamespace, pod, helpers.Ping6(nodeIP))
				res.ExpectSuccess("%s: Pod %s cannot ping to Node IP %s", desc, pod, nodeIP)
			}
		}
	}
}

func waitToDeleteCilium(kubectl *helpers.Kubectl, logger *logrus.Entry) error {
	var (
		pods []string
		err  error
	)

	ctx, cancel := context.WithTimeout(context.Background(), helpers.HelperTimeout)
	defer cancel()

	status := 1
	for status > 0 {

		select {
		case <-ctx.Done():
			return fmt.Errorf("timed out waiting to delete Cilium: pods still remaining: %s", pods)
		default:
		}

		pods, err = kubectl.GetCiliumPodsContext(ctx, helpers.KubeSystemNamespace)
		status := len(pods)
		logger.Infof("Cilium pods terminating '%d' err='%v' pods='%v'", status, err, pods)
		if status == 0 {
			return nil
		}
		time.Sleep(1 * time.Second)
	}
	return nil
}

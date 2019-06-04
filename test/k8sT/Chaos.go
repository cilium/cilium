// Copyright 2017-2018 Authors of Cilium
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

	. "github.com/cilium/cilium/test/ginkgo-ext"
	"github.com/cilium/cilium/test/helpers"

	. "github.com/onsi/gomega"
)

var _ = Describe("K8sChaosTest", func() {

	var (
		kubectl       *helpers.Kubectl
		demoDSPath    = helpers.ManifestGet("demo_ds.yaml")
		testDSService = "testds-service"
	)

	BeforeAll(func() {
		kubectl = helpers.CreateKubectl(helpers.K8s1VMName(), logger)

		_ = kubectl.Apply(helpers.DNSDeployment())

		// Deploy the etcd operator
		By("Deploying etcd-operator")
		err := kubectl.DeployETCDOperator()
		Expect(err).To(BeNil(), "Unable to deploy etcd operator")

		err = kubectl.CiliumInstall(helpers.CiliumDefaultDSPatch, helpers.CiliumConfigMapPatch)
		Expect(err).To(BeNil(), "Cilium cannot be installed")

		ExpectCiliumReady(kubectl)
		ExpectKubeDNSReady(kubectl)
		ExpectETCDOperatorReady(kubectl)
	})

	AfterFailed(func() {
		kubectl.CiliumReport(helpers.KubeSystemNamespace,
			"cilium service list",
			"cilium endpoint list")
	})

	JustAfterEach(func() {
		kubectl.ValidateNoErrorsOnLogs(CurrentGinkgoTestDescription().Duration)
	})

	AfterAll(func() {
		ExpectAllPodsTerminated(kubectl)
	})

	Context("Connectivity demo application", func() {
		BeforeEach(func() {
			kubectl.Apply(demoDSPath).ExpectSuccess("DS deployment cannot be applied")

			err := kubectl.WaitforPods(
				helpers.DefaultNamespace, fmt.Sprintf("-l zgroup=testDS"), 300)
			Expect(err).Should(BeNil(), "Pods are not ready after timeout")
		})

		AfterEach(func() {
			kubectl.Delete(demoDSPath).ExpectSuccess(
				"%s deployment cannot be deleted", demoDSPath)
			ExpectAllPodsTerminated(kubectl)

		})

		// connectivityTest  performs a few test inside:
		// - tests connectivity of all client pods to the backend pods directly via ping
		// - tests connectivity of all client pods to the ClusterIP of the test-ds service via curl
		// - tests connectivity of all client pods to the DNS name for the test-ds service via curl
		connectivityTest := func() {
			pods, err := kubectl.GetPodNames(helpers.DefaultNamespace, "zgroup=testDSClient")
			Expect(err).To(BeNil(), "Cannot get pods names")
			Expect(len(pods)).To(BeNumerically(">", 0), "No pods available to test connectivity")

			dsPods, err := kubectl.GetPodsIPs(helpers.DefaultNamespace, "zgroup=testDS")
			Expect(err).To(BeNil(), "Cannot get daemonset pods IPS")
			Expect(len(dsPods)).To(BeNumerically(">", 0), "No pods available to test connectivity")

			By("Waiting for kube-dns entry for service testds-service")
			err = kubectl.WaitForKubeDNSEntry(testDSService, helpers.DefaultNamespace)
			ExpectWithOffset(1, err).To(BeNil(), "DNS entry is not ready after timeout")

			By("Getting ClusterIP For testds-service")
			host, _, err := kubectl.GetServiceHostPort(helpers.DefaultNamespace, "testds-service")
			ExpectWithOffset(1, err).To(BeNil(), "unable to get ClusterIP and port for service testds-service")

			for _, pod := range pods {
				for _, ip := range dsPods {
					By("Pinging testds pod with IP %q from client pod %q", ip, pod)
					res := kubectl.ExecPodCmd(
						helpers.DefaultNamespace, pod, helpers.Ping(ip))
					log.Debugf("Pod %s ping %v", pod, ip)
					ExpectWithOffset(1, res).To(helpers.CMDSuccess(),
						"Cannot ping from %q to %q", pod, ip)
				}

				By("Curling testds-service via ClusterIP %q", host)
				res := kubectl.ExecPodCmd(
					helpers.DefaultNamespace, pod, helpers.CurlFail("http://%s:80/", host))
				ExpectWithOffset(1, res).To(helpers.CMDSuccess(),
					"Cannot curl from %q to testds-service via ClusterIP", pod)

				By("Curling testds-service via DNS hostname")
				res = kubectl.ExecPodCmd(
					helpers.DefaultNamespace, pod, helpers.CurlFail("http://%s:80/", testDSService))
				ExpectWithOffset(1, res).To(helpers.CMDSuccess(),
					"Cannot curl from %q to testds-service via DNS hostname", pod)
			}
		}

		It("Endpoint can still connect while Cilium is not running", func() {
			By("Waiting for deployed pods to be ready")
			err := kubectl.WaitforPods(
				helpers.DefaultNamespace,
				fmt.Sprintf("-l zgroup=testDSClient"), 300)
			Expect(err).Should(BeNil(), "Pods are not ready after timeout")

			err = kubectl.CiliumEndpointWaitReady()
			Expect(err).To(BeNil(), "Endpoints are not ready after timeout")

			By("Checking connectivity before restarting Cilium")
			connectivityTest()

			By("Deleting cilium pods")
			res := kubectl.Exec(fmt.Sprintf("%s -n %s delete pods -l k8s-app=cilium",
				helpers.KubectlCmd, helpers.KubeSystemNamespace))
			res.ExpectSuccess()

			ExpectAllPodsTerminated(kubectl)

			ExpectCiliumReady(kubectl)
			err = kubectl.CiliumEndpointWaitReady()
			Expect(err).To(BeNil(), "Endpoints are not ready after Cilium restarts")

			By("Checking connectivity after restarting Cilium")
			connectivityTest()

			By("Uninstall cilium pods")

			res = kubectl.DeleteResource(
				"ds", fmt.Sprintf("-n %s cilium", helpers.KubeSystemNamespace))
			res.ExpectSuccess("Cilium DS cannot be deleted")

			ExpectAllPodsTerminated(kubectl)

			By("Checking connectivity after uninstalling Cilium")
			connectivityTest()

			By("Install cilium pods")

			err = kubectl.CiliumInstall(helpers.CiliumDefaultDSPatch, helpers.CiliumConfigMapPatch)
			Expect(err).To(BeNil(), "Cilium cannot be installed")

			ExpectCiliumReady(kubectl)

			err = kubectl.CiliumEndpointWaitReady()
			Expect(err).To(BeNil(), "Endpoints are not ready after timeout")

			By("Checking connectivity after reinstalling Cilium")
			connectivityTest()
		})
	})

	Context("Restart with long lived connections", func() {

		var (
			netperfManifest    = helpers.ManifestGet("netperf-deployment.yaml")
			netperfPolicy      = helpers.ManifestGet("netperf-policy.yaml")
			netperfServiceName = "netperf-service"
			podsIps            map[string]string
			netperfClient      = "netperf-client"
			netperfServer      = "netperf-server"
		)

		BeforeAll(func() {
			kubectl.Apply(netperfManifest).ExpectSuccess("Netperf cannot be deployed")

			err := kubectl.WaitforPods(
				helpers.DefaultNamespace,
				fmt.Sprintf("-l zgroup=testapp"), 300)
			Expect(err).Should(BeNil(), "Pods are not ready after timeout")

			podsIps, err = kubectl.GetPodsIPs(helpers.DefaultNamespace, "zgroup=testapp")
			Expect(err).To(BeNil(), "Cannot get pods ips")

			_, _, err = kubectl.GetServiceHostPort(helpers.DefaultNamespace, netperfServiceName)
			Expect(err).To(BeNil(), "cannot get service netperf ip")
		})

		AfterAll(func() {
			_ = kubectl.Delete(netperfManifest)
		})

		AfterEach(func() {
			_ = kubectl.Delete(netperfPolicy)
		})

		restartCilium := func() {
			ciliumFilter := "k8s-app=cilium"

			By("Deleting all cilium pods")
			res := kubectl.Exec(fmt.Sprintf(
				"%s -n %s delete pods -l %s",
				helpers.KubectlCmd, helpers.KubeSystemNamespace, ciliumFilter))
			res.ExpectSuccess("Failed to delete cilium pods")

			By("Waiting cilium pods to terminate")
			ExpectAllPodsTerminated(kubectl)

			By("Waiting for cilium pods to be ready")
			err := kubectl.WaitforPods(
				helpers.KubeSystemNamespace, fmt.Sprintf("-l %s", ciliumFilter), 300)
			Expect(err).Should(BeNil(), "Pods are not ready after timeout")
		}

		It("TCP connection is not dropped when cilium restarts", func() {
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			res := kubectl.ExecPodCmdContext(
				ctx,
				helpers.DefaultNamespace,
				netperfClient,
				fmt.Sprintf("netperf -l 300 -t TCP_STREAM -H %s", podsIps[netperfServer]))

			restartCilium()

			By("Stopping netperf client test")
			cancel()
			res.WaitUntilFinish()
			res.ExpectSuccess("Failed while cilium was restarting")
		})

		It("L3/L4 policies still work while Cilium is restarted", func() {

			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			res := kubectl.ExecPodCmdContext(
				ctx,
				helpers.DefaultNamespace,
				netperfClient,
				fmt.Sprintf("netperf -l 300 -t TCP_STREAM -H %s", podsIps[netperfServer]))

			By("Installing the L3-L4 Policy")
			_, err := kubectl.CiliumPolicyAction(
				helpers.KubeSystemNamespace, netperfPolicy, helpers.KubectlApply, 300)
			Expect(err).Should(BeNil(), "Cannot install %q policy", netperfPolicy)

			restartCilium()

			By("Stopping netperf client test")
			cancel()
			res.WaitUntilFinish()
			res.ExpectSuccess("Failed while cilium was restarting")
		})
	})
})

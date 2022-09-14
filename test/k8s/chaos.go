// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package k8sTest

import (
	"context"
	"fmt"

	. "github.com/onsi/gomega"

	. "github.com/cilium/cilium/test/ginkgo-ext"
	"github.com/cilium/cilium/test/helpers"
)

// The 5.4 CI job is intended to catch BPF complexity regressions and as such
// doesn't need to execute this test suite.
var _ = SkipDescribeIf(helpers.RunsOn54Kernel, "K8sAgentChaosTest", func() {

	var (
		kubectl        *helpers.Kubectl
		demoDSPath     string
		ciliumFilename string
		testDSService  = "testds-service"
	)

	BeforeAll(func() {
		kubectl = helpers.CreateKubectl(helpers.K8s1VMName(), logger)
		demoDSPath = helpers.ManifestGet(kubectl.BasePath(), "demo_ds.yaml")

		ciliumFilename = helpers.TimestampFilename("cilium.yaml")
		DeployCiliumAndDNS(kubectl, ciliumFilename)
	})

	AfterFailed(func() {
		kubectl.CiliumReport("cilium service list", "cilium endpoint list")
	})

	JustAfterEach(func() {
		kubectl.ValidateNoErrorsInLogs(CurrentGinkgoTestDescription().Duration)
	})

	AfterAll(func() {
		UninstallCiliumFromManifest(kubectl, ciliumFilename)
		kubectl.CloseSSHClient()
	})

	Context("Connectivity demo application", func() {
		BeforeEach(func() {
			kubectl.ApplyDefault(demoDSPath).ExpectSuccess("DS deployment cannot be applied")

			err := kubectl.WaitforPods(
				helpers.DefaultNamespace, "-l zgroup=testDS", helpers.HelperTimeout)
			Expect(err).Should(BeNil(), "Pods are not ready after timeout")
		})

		AfterEach(func() {
			kubectl.DeleteLong(demoDSPath).ExpectSuccess(
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
				"-l zgroup=testDSClient", helpers.HelperTimeout)
			Expect(err).Should(BeNil(), "Pods are not ready after timeout")

			err = kubectl.CiliumEndpointWaitReady()
			Expect(err).To(BeNil(), "Endpoints are not ready after timeout")

			By("Checking connectivity before restarting Cilium")
			connectivityTest()

			By("Deleting cilium pods")
			res := kubectl.Exec(fmt.Sprintf("%s -n %s delete pods -l k8s-app=cilium",
				helpers.KubectlCmd, helpers.CiliumNamespace))
			res.ExpectSuccess()

			ExpectAllPodsTerminated(kubectl)

			ExpectCiliumReady(kubectl)
			err = kubectl.CiliumEndpointWaitReady()
			Expect(err).To(BeNil(), "Endpoints are not ready after Cilium restarts")

			By("Checking connectivity after restarting Cilium")
			connectivityTest()

			By("Uninstall cilium pods")

			res = kubectl.DeleteResource(
				"ds", fmt.Sprintf("-n %s cilium", helpers.CiliumNamespace))
			res.ExpectSuccess("Cilium DS cannot be deleted")

			ExpectAllPodsTerminated(kubectl)

			By("Checking connectivity after uninstalling Cilium")
			connectivityTest()

			By("Reinstall cilium DaemonSet")
			err = kubectl.CiliumInstall(ciliumFilename, map[string]string{})
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
			netperfManifest    string
			netperfPolicy      string
			netperfServiceName = "netperf-service"
			podsIps            map[string]string
			netperfClient      = "netperf-client"
			netperfServer      = "netperf-server"
		)

		BeforeAll(func() {
			netperfManifest = helpers.ManifestGet(kubectl.BasePath(), "netperf-deployment.yaml")
			netperfPolicy = helpers.ManifestGet(kubectl.BasePath(), "netperf-policy.yaml")

			kubectl.ApplyDefault(netperfManifest).ExpectSuccess("Netperf cannot be deployed")

			err := kubectl.WaitforPods(
				helpers.DefaultNamespace,
				"-l zgroup=testapp", helpers.HelperTimeout)
			Expect(err).Should(BeNil(), "Pods are not ready after timeout")

			podsIps, err = kubectl.GetPodsIPs(helpers.DefaultNamespace, "zgroup=testapp")
			Expect(err).To(BeNil(), "Cannot get pods ips")

			_, _, err = kubectl.GetServiceHostPort(helpers.DefaultNamespace, netperfServiceName)
			Expect(err).To(BeNil(), "cannot get service netperf ip")
		})

		AfterAll(func() {
			_ = kubectl.Delete(netperfManifest)
			ExpectAllPodsTerminated(kubectl)
		})

		AfterEach(func() {
			_ = kubectl.Delete(netperfPolicy)
		})

		restartCilium := func() {
			ciliumFilter := "k8s-app=cilium"

			By("Deleting all cilium pods")
			res := kubectl.Exec(fmt.Sprintf(
				"%s -n %s delete pods -l %s",
				helpers.KubectlCmd, helpers.CiliumNamespace, ciliumFilter))
			res.ExpectSuccess("Failed to delete cilium pods")

			By("Waiting cilium pods to terminate")
			ExpectAllPodsTerminated(kubectl)

			By("Waiting for cilium pods to be ready")
			err := kubectl.WaitforPods(
				helpers.CiliumNamespace, fmt.Sprintf("-l %s", ciliumFilter), helpers.HelperTimeout)
			Expect(err).Should(BeNil(), "Pods are not ready after timeout")

			err = kubectl.CiliumEndpointWaitReady()
			Expect(err).To(BeNil(), "Endpoints are not ready after timeout")
		}

		It("TCP connection is not dropped when cilium restarts", func() {
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			res := kubectl.ExecPodCmdBackground(
				ctx,
				helpers.DefaultNamespace,
				netperfClient, "",
				fmt.Sprintf("netperf -l 60 -t TCP_STREAM -H %s", podsIps[netperfServer]))

			restartCilium()

			By("Stopping netperf client test")
			res.WaitUntilFinish()
			res.ExpectSuccess("Failed while cilium was restarting")
		})

		It("L3/L4 policies still work while Cilium is restarted", func() {

			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			res := kubectl.ExecPodCmdBackground(
				ctx,
				helpers.DefaultNamespace,
				netperfClient, "",
				fmt.Sprintf("netperf -l 60 -t TCP_STREAM -H %s", podsIps[netperfServer]))

			By("Installing the L3-L4 Policy")
			_, err := kubectl.CiliumPolicyAction(
				helpers.DefaultNamespace, netperfPolicy, helpers.KubectlApply, helpers.HelperTimeout)
			Expect(err).Should(BeNil(), "Cannot install %q policy", netperfPolicy)

			restartCilium()

			By("Stopping netperf client test")
			res.WaitUntilFinish()
			res.ExpectSuccess("Failed while cilium was restarting")
		})
	})
})

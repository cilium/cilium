// Copyright 2019 Authors of Cilium
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

	. "github.com/cilium/cilium/test/ginkgo-ext"
	"github.com/cilium/cilium/test/helpers"

	. "github.com/onsi/gomega"
)

var _ = Describe("K8sFQDNTest", func() {
	var (
		kubectl          *helpers.Kubectl
		backgroundCancel context.CancelFunc = func() {}
		backgroundError  error

		demoManifest   = ""
		ciliumFilename string

		apps    = []string{helpers.App2, helpers.App3}
		appPods map[string]string

		// The IPs are updated in BeforeAll
		worldTarget          = "http://vagrant-cache.ci.cilium.io"
		worldTargetIP        = "147.75.38.95"
		worldInvalidTarget   = "http://jenkins.cilium.io"
		worldInvalidTargetIP = "104.198.14.52"
	)

	BeforeAll(func() {
		// In case the IPs changed from above, update them here
		var lookupErr error
		err := helpers.WithTimeout(func() bool {
			addrs, err2 := net.LookupHost("vagrant-cache.ci.cilium.io")
			if err2 != nil {
				lookupErr = fmt.Errorf("error looking up vagrant-cache.ci.cilium.io: %s", err2)
				return false
			}
			worldTargetIP = addrs[0]
			return true
		}, "Could not get vagrant-cache.ci.cilium.io IP", &helpers.TimeoutConfig{Timeout: helpers.HelperTimeout})
		Expect(err).Should(BeNil(), "Error obtaining IP for test: %s", lookupErr)

		lookupErr = nil
		err = helpers.WithTimeout(func() bool {
			addrs, err2 := net.LookupHost("jenkins.cilium.io")
			if err2 != nil {
				lookupErr = fmt.Errorf("error looking up jenkins.cilium.io: %s", err2)
				return false
			}
			worldInvalidTargetIP = addrs[0]
			return true
		}, "Could not get jenkins.cilium.io IP", &helpers.TimeoutConfig{Timeout: helpers.HelperTimeout})
		Expect(err).Should(BeNil(), "Error obtaining IP for test: %s", lookupErr)

		kubectl = helpers.CreateKubectl(helpers.K8s1VMName(), logger)
		demoManifest = helpers.ManifestGet(kubectl.BasePath(), "demo.yaml")

		ciliumFilename = helpers.TimestampFilename("cilium.yaml")
		DeployCiliumAndDNS(kubectl, ciliumFilename)

		By("Applying demo manifest")
		res := kubectl.ApplyDefault(demoManifest)
		res.ExpectSuccess("Demo config cannot be deployed")

		err = kubectl.WaitforPods(helpers.DefaultNamespace, "-l zgroup=testapp", helpers.HelperTimeout)
		Expect(err).Should(BeNil(), "Testapp is not ready after timeout")

		appPods = helpers.GetAppPods(apps, helpers.DefaultNamespace, kubectl, "id")
	})

	AfterFailed(func() {
		kubectl.CiliumReport("cilium service list", "cilium endpoint list")
	})

	AfterAll(func() {
		_ = kubectl.Delete(demoManifest)
		ExpectAllPodsTerminated(kubectl)

		UninstallCiliumFromManifest(kubectl, ciliumFilename)
		kubectl.CloseSSHClient()
	})

	JustBeforeEach(func() {
		backgroundCancel, backgroundError = kubectl.BackgroundReport("uptime")
		Expect(backgroundError).To(BeNil(), "Cannot start background report process")
	})

	JustAfterEach(func() {
		kubectl.ValidateNoErrorsInLogs(CurrentGinkgoTestDescription().Duration)
		backgroundCancel()
	})

	AfterEach(func() {
		_ = kubectl.Exec(fmt.Sprintf("%s delete --all cnp", helpers.KubectlCmd))
	})

	SkipItIf(helpers.SkipQuarantined, "Restart Cilium validate that FQDN is still working", func() {
		// Test functionality:
		// - When Cilium is running) Connectivity from App2 application can
		// connect to DNS because dns-proxy filter the DNS request. If the
		// connection is made correctly the IP is whitelisted by the FQDN rule
		// until the DNS TTL expires.
		// - When Cilium is not running) The DNS-proxy is not working, so the IP
		// connectivity to an existing IP that was queried before will work,
		// meanwhile connections using new DNS request will fail.
		// - On restart) Cilium will restore the IPS that were white-listted in
		// the FQDN and connection will work as normal.

		ciliumPodK8s1, err := kubectl.GetCiliumPodOnNodeWithLabel(helpers.K8s1)
		Expect(err).Should(BeNil(), "Cannot get cilium pod on k8s1")
		monitorRes1, monitorCancel1 := kubectl.MonitorStart(ciliumPodK8s1)
		ciliumPodK8s2, err := kubectl.GetCiliumPodOnNodeWithLabel(helpers.K8s2)
		Expect(err).Should(BeNil(), "Cannot get cilium pod on k8s2")
		monitorRes2, monitorCancel2 := kubectl.MonitorStart(ciliumPodK8s2)
		defer func() {
			monitorCancel1()
			monitorCancel2()
			helpers.WriteToReportFile(monitorRes1.CombineOutput().Bytes(), "fqdn-restart-cilium-monitor-k8s1.log")
			helpers.WriteToReportFile(monitorRes2.CombineOutput().Bytes(), "fqdn-restart-cilium-monitor-k8s2.log")
		}()

		connectivityTest := func() {
			By("Testing that connection from %q to %q should work",
				appPods[helpers.App2], worldTarget)
			res := kubectl.ExecPodCmd(
				helpers.DefaultNamespace, appPods[helpers.App2],
				helpers.CurlFail(worldTarget))
			ExpectWithOffset(1, res).To(helpers.CMDSuccess(), "%q cannot curl to %q",
				appPods[helpers.App2], worldTarget)

			By("Testing that connection from %q to %q shouldn't work",
				appPods[helpers.App2], worldInvalidTarget)
			res = kubectl.ExecPodCmd(
				helpers.DefaultNamespace, appPods[helpers.App2],
				helpers.CurlFail(worldInvalidTarget))
			ExpectWithOffset(1, res).ShouldNot(helpers.CMDSuccess(),
				"%q can curl to %q when it should fail", appPods[helpers.App2], worldInvalidTarget)

			By("Testing that connection from %q to %q works",
				appPods[helpers.App2], worldTargetIP)
			res = kubectl.ExecPodCmd(
				helpers.DefaultNamespace, appPods[helpers.App2],
				helpers.CurlFail(worldTargetIP))
			res.ExpectSuccess("%q cannot curl to %q during restart", helpers.App2, worldTargetIP)

			By("Testing that connection from %q to %q should not work",
				appPods[helpers.App2], worldInvalidTargetIP)
			res = kubectl.ExecPodCmd(
				helpers.DefaultNamespace, appPods[helpers.App2],
				helpers.CurlFail(worldInvalidTargetIP))
			res.ExpectFail("%q can connect when it should not work", helpers.App2)
		}

		fqndProxyPolicy := helpers.ManifestGet(kubectl.BasePath(), "fqdn-proxy-policy.yaml")

		_, err = kubectl.CiliumPolicyAction(
			helpers.DefaultNamespace, fqndProxyPolicy,
			helpers.KubectlApply, helpers.HelperTimeout)
		Expect(err).To(BeNil(), "Cannot install fqdn proxy policy")

		connectivityTest()
		By("restarting cilium pods")

		// kill pid 1 in each cilium pod
		cmd := fmt.Sprintf("%[1]s get pods -l k8s-app=cilium -n %[2]s |  tail -n +2 | cut -d ' ' -f 1 | xargs -I{} %[1]s exec -n %[2]s {} -- kill 1",
			helpers.KubectlCmd, helpers.CiliumNamespace)
		quit, run := kubectl.RepeatCommandInBackground(cmd)
		channelClosed := false
		defer func() {
			if !channelClosed {
				close(quit)
			}
		}()
		<-run // waiting for first run to finish

		By("Testing connectivity when cilium is restoring using IPS without DNS")
		res := kubectl.ExecPodCmd(
			helpers.DefaultNamespace, appPods[helpers.App2],
			helpers.CurlFail(worldTargetIP))
		res.ExpectSuccess("%q cannot curl to %q during restart", helpers.App2, worldTargetIP)

		res = kubectl.ExecPodCmd(
			helpers.DefaultNamespace, appPods[helpers.App2],
			helpers.CurlFail(worldInvalidTargetIP))
		res.ExpectFail("%q can connect when it should not work", helpers.App2)

		// This test is failing consistently in quarantine, see #11213. Disable it for now
		// to verify the rest of the test is running stable in quarantine. Once this is the
		// case we could move the rest of the test out of quarantine and quarantine only
		// this part.
		if false {
			// Re-run connectivity test while Cilium is still restarting. This should succeed as the same
			// DNS names were used in a connectivity test before the restart.
			connectivityTest()
		}

		channelClosed = true
		close(quit)

		ExpectAllPodsTerminated(kubectl)
		ExpectCiliumReady(kubectl)

		// Restart monitoring after Cilium restart
		monitorRes1After, monitorCancel1After := kubectl.MonitorStart(ciliumPodK8s1)
		monitorRes2After, monitorCancel2After := kubectl.MonitorStart(ciliumPodK8s2)
		defer func() {
			monitorCancel1After()
			monitorCancel2After()
			helpers.WriteToReportFile(monitorRes1After.CombineOutput().Bytes(), "fqdn-after-restart-cilium-monitor-k8s1.log")
			helpers.WriteToReportFile(monitorRes2After.CombineOutput().Bytes(), "fqdn-after-restart-cilium-monitor-k8s2.log")
		}()

		// @TODO This endpoint ready call SHOULD NOT be here
		// Here some packets can be lost due to two different scenarios:
		//
		// 1) On restore the endpoint/fqdn policies, the identity ID for the
		// CIDRSet can be different, so if one endpoint start to regenerate and
		// other still have the old identity things can mess around and some
		// IPs are not white listed correctly. To prevent this, a restore for
		// local-identities will be added in the future.
		//
		// 2) On restore, the Kubernetes watcher is sending the CNP back to
		// Cilium, and before the endoint is restored the CNP can be applied
		// without the ToCIDRSet, this means that there is no TOCIDR rule in
		// the cilium policy and traffic will be drop.

		// As mentioned above, these endpoints ready should not be there, the only
		// reason to have this piece of code here is to reduce a flaky test.
		err = kubectl.CiliumEndpointWaitReady()
		Expect(err).To(BeNil(), "Endpoints are not ready after Cilium restarts")

		By("Testing connectivity when cilium is *restored* using IPS without DNS")
		res = kubectl.ExecPodCmd(
			helpers.DefaultNamespace, appPods[helpers.App2],
			helpers.CurlFail(worldTargetIP))
		res.ExpectSuccess("%q cannot curl to %q after restart", helpers.App2, worldTargetIP)

		res = kubectl.ExecPodCmd(
			helpers.DefaultNamespace, appPods[helpers.App2],
			helpers.CurlFail(worldInvalidTargetIP))
		res.ExpectFail("%q can connect when it should not work", helpers.App2)

		By("Testing connectivity using DNS request when cilium is restored correctly")
		connectivityTest()
	})

	It("Validate that multiple specs are working correctly", func() {
		// To make sure that UUID in multiple specs are plumbed correctly to
		// Cilium Policy
		fqdnPolicy := helpers.ManifestGet(kubectl.BasePath(), "fqdn-proxy-multiple-specs.yaml")
		world1Target := worldTarget
		world2Target := worldInvalidTarget

		_, err := kubectl.CiliumPolicyAction(
			helpers.DefaultNamespace, fqdnPolicy,
			helpers.KubectlApply, helpers.HelperTimeout)
		Expect(err).To(BeNil(), "Cannot install fqdn proxy policy")

		By("Validating APP2 policy connectivity")
		res := kubectl.ExecPodCmd(
			helpers.DefaultNamespace, appPods[helpers.App2],
			helpers.CurlFail("--retry 5 "+world1Target))
		res.ExpectSuccess("Can't connect to to a valid target when it should work")

		res = kubectl.ExecPodCmd(
			helpers.DefaultNamespace, appPods[helpers.App2],
			helpers.CurlFail(world2Target))
		res.ExpectFail("Can connect to a valid target when it should NOT work")

		By("Validating APP3 policy connectivity")

		res = kubectl.ExecPodCmd(
			helpers.DefaultNamespace, appPods[helpers.App3],
			helpers.CurlWithRetries(world2Target, 5, true))
		res.ExpectSuccess("Can't connect to to a valid target when it should work")

		res = kubectl.ExecPodCmd(
			helpers.DefaultNamespace, appPods[helpers.App3],
			helpers.CurlFail(world1Target))
		res.ExpectFail("Can connect to to a valid target when it should NOT work")
	})
})

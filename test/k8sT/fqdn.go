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
		backgroundCancel context.CancelFunc = func() { return }
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
		// In case the IPs changed, update them here
		addrs, err := net.LookupHost("vagrant-cache.ci.cilium.io")
		Expect(err).Should(BeNil(), "Error getting IPs for test")
		worldTargetIP = addrs[0]

		addrs, err = net.LookupHost("jenkins.cilium.io")
		Expect(err).Should(BeNil(), "Error getting IPs for test")
		worldInvalidTargetIP = addrs[0]

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
		kubectl.CiliumReport(helpers.CiliumNamespace,
			"cilium service list",
			"cilium endpoint list")
	})

	AfterAll(func() {
		_ = kubectl.Delete(demoManifest)
		kubectl.DeleteCiliumDS()
		ExpectAllPodsTerminated(kubectl)
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

	It("Restart Cilium validate that FQDN is still working", func() {
		// Test functionality:
		// - When Cilium is running) Connectivity from App2 application can
		// connect to DNS because dns-proxy filter the DNS request. If the
		// connection is made correctly the IP is whitelisted by the FQDN rule
		// until the DNS TTL expires.
		// When Cilium is not running) The DNS-proxy is not working, so the IP
		// connectivity to an existing IP that was queried before will work,
		// meanwhile connections using new DNS request will fail.
		// On restart) Cilium will restore the IPS that were white-listted in
		// the FQDN and connection will work as normal.

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
			res.ExpectFail("%q can  connect when it should not work", helpers.App2)
		}

		fqndProxyPolicy := helpers.ManifestGet(kubectl.BasePath(), "fqdn-proxy-policy.yaml")

		_, err := kubectl.CiliumPolicyAction(
			helpers.DefaultNamespace, fqndProxyPolicy,
			helpers.KubectlApply, helpers.HelperTimeout)
		Expect(err).To(BeNil(), "Cannot install fqdn proxy policy")

		connectivityTest()
		By("Deleting cilium pods")

		res := kubectl.Exec(fmt.Sprintf("%s -n %s delete pods -l k8s-app=cilium",
			helpers.KubectlCmd, helpers.CiliumNamespace))
		res.ExpectSuccess()

		By("Testing connectivity when cilium is restoring using IPS without DNS")
		res = kubectl.ExecPodCmd(
			helpers.DefaultNamespace, appPods[helpers.App2],
			helpers.CurlFail(worldTargetIP))
		res.ExpectSuccess("%q cannot curl to %q during restart", helpers.App2, worldTargetIP)

		res = kubectl.ExecPodCmd(
			helpers.DefaultNamespace, appPods[helpers.App2],
			helpers.CurlFail(worldInvalidTargetIP))
		res.ExpectFail("%q can  connect when it should not work", helpers.App2)

		ExpectAllPodsTerminated(kubectl)
		ExpectCiliumReady(kubectl)

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
		res.ExpectFail("%q can  connect when it should not work", helpers.App2)

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
			helpers.CurlFail(world1Target))
		res.ExpectSuccess("Can't connect to to a valid target when it should work")

		res = kubectl.ExecPodCmd(
			helpers.DefaultNamespace, appPods[helpers.App2],
			helpers.CurlFail(world2Target))
		res.ExpectFail("Can connect to a valid target when it should NOT work")

		By("Validating APP3 policy connectivity")

		res = kubectl.ExecPodCmd(
			helpers.DefaultNamespace, appPods[helpers.App3],
			helpers.CurlFail(world2Target))
		res.ExpectSuccess("Can't connect to to a valid target when it should work")

		res = kubectl.ExecPodCmd(
			helpers.DefaultNamespace, appPods[helpers.App3],
			helpers.CurlFail(world1Target))
		res.ExpectFail("Can connect to to a valid target when it should NOT work")
	})
})

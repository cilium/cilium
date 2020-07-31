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
		// Test overview:
		//
		// When Cilium is running:
		// Connectivity from App2 can connect to DNS because dns-proxy handles
		// the DNS request. If the connection is made correctly, the IP is
		// allowed by the FQDN rule until the DNS TTL expires.
		//
		// When Cilium is not running:
		// The dns-proxy is not running either, so the IP connectivity to an
		// existing IP that was queried before will work, meanwhile connections
		// using a new DNS request will fail.
		//
		// On restart:
		// Cilium will restore the IPs that were allowed in the FQDN and
		// connectivity resumes.

		fqndProxyPolicy := helpers.ManifestGet(kubectl.BasePath(), "fqdn-proxy-policy.yaml")

		_, err := kubectl.CiliumPolicyAction(
			helpers.DefaultNamespace, fqndProxyPolicy,
			helpers.KubectlApply, helpers.HelperTimeout)
		Expect(err).To(BeNil(), "Cannot install fqdn proxy policy")

		By("Performing baseline test to validate connectivity")
		connectivityTest(kubectl, appPods,
			worldTarget, worldInvalidTarget, worldTargetIP, worldInvalidTargetIP)

		By("Deleting Cilium pods")
		kubectl.Exec(
			fmt.Sprintf("%s -n %s delete pods -l k8s-app=cilium",
				helpers.KubectlCmd,
				helpers.CiliumNamespace),
		).ExpectSuccess()

		By("Testing connectivity when cilium is restoring using IPs without DNS")
		connectivityTestIPs(kubectl, appPods, worldTargetIP, worldInvalidTargetIP)

		ExpectAllPodsTerminated(kubectl)
		ExpectCiliumReady(kubectl)

		By("Testing connectivity when cilium is *restored* using IPs without DNS")
		connectivityTestIPs(kubectl, appPods, worldTargetIP, worldInvalidTargetIP)

		By("Testing connectivity using DNS request when cilium is restored correctly")
		connectivityTest(kubectl, appPods,
			worldTarget, worldInvalidTarget, worldTargetIP, worldInvalidTargetIP)
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

func connectivityTest(kubectl *helpers.Kubectl, appPods map[string]string,
	dnsTarget, dnsInvalidTarget, ipTarget, ipInvalidTarget string) {

	connectivityTestDNS(kubectl, appPods, dnsTarget, dnsInvalidTarget)
	connectivityTestIPs(kubectl, appPods, ipTarget, ipInvalidTarget)
}

func connectivityTestDNS(kubectl *helpers.Kubectl, appPods map[string]string,
	target, invalidTarget string) {
	By("Testing that connection from %q to %q should work", appPods[helpers.App2], target)
	res := kubectl.ExecPodCmd(
		helpers.DefaultNamespace, appPods[helpers.App2],
		helpers.CurlFail(target))
	ExpectWithOffset(1, res).To(helpers.CMDSuccess(), "%q cannot curl to %q",
		appPods[helpers.App2], target)

	By("Testing that connection from %q to %q shouldn't work",
		appPods[helpers.App2], invalidTarget)
	res = kubectl.ExecPodCmd(
		helpers.DefaultNamespace, appPods[helpers.App2],
		helpers.CurlFail(invalidTarget))
	ExpectWithOffset(1, res).ShouldNot(helpers.CMDSuccess(),
		"%q can curl to %q when it should fail", appPods[helpers.App2], invalidTarget)
}

func connectivityTestIPs(kubectl *helpers.Kubectl, appPods map[string]string,
	target, invalidTarget string) {
	By("Testing that connection from %q to %q works", appPods[helpers.App2], target)
	kubectl.ExecPodCmd(
		helpers.DefaultNamespace,
		appPods[helpers.App2],
		helpers.CurlFail(target),
	).ExpectSuccess("%q cannot curl to %q during restart", helpers.App2, target)

	By("Testing that connection from %q to %q should not work",
		appPods[helpers.App2], invalidTarget)
	kubectl.ExecPodCmd(
		helpers.DefaultNamespace,
		appPods[helpers.App2],
		helpers.CurlFail(invalidTarget),
	).ExpectFail("%q can  connect when it should not work", helpers.App2)
}

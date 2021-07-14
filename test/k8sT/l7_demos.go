// SPDX-License-Identifier: Apache-2.0
// Copyright 2018-2019 Authors of Cilium

package k8sTest

import (
	"fmt"
	"path/filepath"

	. "github.com/cilium/cilium/test/ginkgo-ext"
	"github.com/cilium/cilium/test/helpers"

	. "github.com/onsi/gomega"
)

// The 5.4 CI job is intended to catch BPF complexity regressions and as such
// doesn't need to execute this test suite.
var _ = SkipDescribeIf(helpers.RunsOn54Kernel, "K8sDemosTest", func() {

	var (
		kubectl        *helpers.Kubectl
		ciliumFilename string

		deathStarYAMLLink, xwingYAMLLink, l7PolicyYAMLLink string
	)

	BeforeAll(func() {
		kubectl = helpers.CreateKubectl(helpers.K8s1VMName(), logger)
		starWarsDemoDir := helpers.ManifestGet(kubectl.BasePath(), "star-wars-demo")
		deathStarYAMLLink = filepath.Join(starWarsDemoDir, "01-deathstar.yaml")
		xwingYAMLLink = filepath.Join(starWarsDemoDir, "02-xwing.yaml")
		l7PolicyYAMLLink = filepath.Join(starWarsDemoDir, "policy/l7_policy.yaml")

		ciliumFilename = helpers.TimestampFilename("cilium.yaml")
		DeployCiliumAndDNS(kubectl, ciliumFilename)
	})

	AfterFailed(func() {
		kubectl.CiliumReport("cilium endpoint list", "cilium service list")
	})

	JustAfterEach(func() {
		kubectl.ValidateNoErrorsInLogs(CurrentGinkgoTestDescription().Duration)
	})

	AfterEach(func() {
		By("Deleting all resources created during test")
		kubectl.Delete(l7PolicyYAMLLink)
		kubectl.Delete(deathStarYAMLLink)
		kubectl.Delete(xwingYAMLLink)

		By("Waiting for all pods to finish terminating")
		ExpectAllPodsTerminated(kubectl)
	})

	AfterAll(func() {
		UninstallCiliumFromManifest(kubectl, ciliumFilename)
		kubectl.CloseSSHClient()
	})

	It("Tests Star Wars Demo", func() {

		allianceLabel := "org=alliance"
		deathstarServiceName := "deathstar"
		deathstarFQDN := fmt.Sprintf("%s.%s.svc.cluster.local", deathstarServiceName, helpers.DefaultNamespace)

		exhaustPortPath := filepath.Join(deathstarFQDN, "/v1/exhaust-port")

		By("Applying deployments")

		res := kubectl.ApplyDefault(deathStarYAMLLink)
		res.ExpectSuccess("unable to apply %s: %s", deathStarYAMLLink, res.CombineOutput())

		res = kubectl.ApplyDefault(xwingYAMLLink)
		res.ExpectSuccess("unable to apply %s: %s", xwingYAMLLink, res.CombineOutput())

		By("Waiting for pods to be ready")
		err := kubectl.WaitforPods(helpers.DefaultNamespace, "", helpers.HelperTimeout)
		Expect(err).Should(BeNil(), "Pods are not ready after timeout")

		By("Getting xwing pod names")
		xwingPods, err := kubectl.GetPodNames(helpers.DefaultNamespace, allianceLabel)
		Expect(err).Should(BeNil())
		Expect(xwingPods).ShouldNot(BeEmpty(), "Unable to get xwing pod names")

		// Test only needs to access one of the pods.
		xwingPod := xwingPods[0]

		By("Making sure all endpoints are in ready state")
		err = kubectl.CiliumEndpointWaitReady()
		Expect(err).To(BeNil(), "Endpoints are not ready after timeout")

		By("Showing how alliance can execute REST API call to main API endpoint")

		err = kubectl.WaitForKubeDNSEntry(deathstarServiceName, helpers.DefaultNamespace)
		Expect(err).To(BeNil(), "DNS entry is not ready after timeout")

		res = kubectl.ExecPodCmd(helpers.DefaultNamespace, xwingPod,
			helpers.CurlFail("http://%s/v1", deathstarFQDN))
		res.ExpectSuccess("unable to curl %s/v1: %s", deathstarFQDN, res.Stdout())

		By("Importing L7 Policy which restricts access to %q", exhaustPortPath)
		_, err = kubectl.CiliumPolicyAction(
			helpers.DefaultNamespace, l7PolicyYAMLLink, helpers.KubectlApply, helpers.HelperTimeout)
		Expect(err).Should(BeNil(), "Unable to apply %s", l7PolicyYAMLLink)

		By("Waiting for endpoints to be ready after importing policy")
		err = kubectl.CiliumEndpointWaitReady()
		Expect(err).To(BeNil(), "Endpoints are not ready after timeout")

		By("Showing how alliance cannot access %q without force header in API request after importing L7 Policy", exhaustPortPath)
		res = kubectl.ExecPodCmd(helpers.DefaultNamespace, xwingPod,
			helpers.CurlWithHTTPCode("-X PUT http://%s", exhaustPortPath))
		res.ExpectContains("403", "able to access %s when policy disallows it; %s", exhaustPortPath, res.Stdout())

		By("Showing how alliance can access %q with force header in API request to attack the deathstar", exhaustPortPath)
		res = kubectl.ExecPodCmd(helpers.DefaultNamespace, xwingPod,
			helpers.CurlWithHTTPCode("-X PUT -H 'X-Has-Force: True' http://%s", exhaustPortPath))
		By("Expecting 503 to be returned when using force header to attack the deathstar")
		res.ExpectContains("503", "unable to access %s when policy allows it; %s", exhaustPortPath, res.Stdout())
	})
})

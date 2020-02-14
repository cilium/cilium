// Copyright 2018-2019 Authors of Cilium
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
	"path/filepath"

	. "github.com/cilium/cilium/test/ginkgo-ext"
	"github.com/cilium/cilium/test/helpers"

	. "github.com/onsi/gomega"
)

var (
	starWarsDemoLinkRoot = "https://raw.githubusercontent.com/cilium/star-wars-demo/v1.0.1"
)

func getStarWarsResourceLink(file string) string {
	// Cannot use filepath.Join because it removes one of the '/' from
	// https:// and results in a malformed URL.
	return fmt.Sprintf("%s/%s", starWarsDemoLinkRoot, file)
}

var _ = Describe("K8sDemosTest", func() {

	var (
		kubectl        *helpers.Kubectl
		ciliumFilename string

		backgroundCancel context.CancelFunc = func() { return }
		backgroundError  error

		deathStarYAMLLink = getStarWarsResourceLink("01-deathstar.yaml")
		xwingYAMLLink     = getStarWarsResourceLink("02-xwing.yaml")
		l7PolicyYAMLLink  = getStarWarsResourceLink("policy/l7_policy.yaml")
	)

	BeforeAll(func() {
		kubectl = helpers.CreateKubectl(helpers.K8s1VMName(), logger)
		ciliumFilename = helpers.TimestampFilename("cilium.yaml")
		DeployCiliumAndDNS(kubectl, ciliumFilename)
	})

	AfterFailed(func() {
		kubectl.CiliumReport(helpers.CiliumNamespace,
			"cilium endpoint list",
			"cilium service list")
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
		By("Deleting all resources created during test")
		kubectl.Delete(l7PolicyYAMLLink)
		kubectl.Delete(deathStarYAMLLink)
		kubectl.Delete(xwingYAMLLink)

		By("Waiting for all pods to finish terminating")
		ExpectAllPodsTerminated(kubectl)
	})

	AfterAll(func() {
		kubectl.DeleteCiliumDS()
		ExpectAllPodsTerminated(kubectl)
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
		res.ExpectSuccess("unable to curl %s/v1: %s", deathstarFQDN, res.Output())

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
		res.ExpectContains("403", "able to access %s when policy disallows it; %s", exhaustPortPath, res.Output())

		By("Showing how alliance can access %q with force header in API request to attack the deathstar", exhaustPortPath)
		res = kubectl.ExecPodCmd(helpers.DefaultNamespace, xwingPod,
			helpers.CurlWithHTTPCode("-X PUT -H 'X-Has-Force: True' http://%s", exhaustPortPath))
		By("Expecting 503 to be returned when using force header to attack the deathstar")
		res.ExpectContains("503", "unable to access %s when policy allows it; %s", exhaustPortPath, res.Output())
	})
})

// Copyright 2018 Authors of Cilium
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
	"fmt"
	"path/filepath"

	. "github.com/cilium/cilium/test/ginkgo-ext"
	"github.com/cilium/cilium/test/helpers"

	. "github.com/onsi/gomega"
	"github.com/sirupsen/logrus"
)

var (
	starWarsDemoLinkRoot = "https://raw.githubusercontent.com/cilium/star-wars-demo/v1.0"
)

func getStarWarsResourceLink(file string) string {
	// Cannot use filepath.Join because it removes one of the '/' from
	// https:// and results in a malformed URL.
	return fmt.Sprintf("%s/%s", starWarsDemoLinkRoot, file)
}

var _ = Describe("K8sDemosTest", func() {

	var (
		kubectl          *helpers.Kubectl
		logger           *logrus.Entry
		microscopeErr    error
		microscopeCancel = func() error { return nil }

		backgroundCancel context.CancelFunc = func() { return }
		backgroundError  error

		deathStarYAMLLink = getStarWarsResourceLink("01-deathstar.yaml")
		xwingYAMLLink     = getStarWarsResourceLink("02-xwing.yaml")
		l7PolicyYAMLLink  = getStarWarsResourceLink("policy/l7_policy.yaml")
	)

	BeforeAll(func() {
		logger.Info("Starting")
		kubectl = helpers.CreateKubectl(helpers.K8s1VMName(), logger)

		err := kubectl.CiliumInstall(helpers.CiliumDSPath)
		Expect(err).To(BeNil(), "Cilium cannot be installed")

		ExpectCiliumReady(kubectl)
		ExpectKubeDNSReady(kubectl)
	})

	AfterFailed(func() {
		kubectl.CiliumReport(helpers.KubeSystemNamespace,
			"cilium endpoint list",
			"cilium service list")
	})

	JustBeforeEach(func() {
		microscopeErr, microscopeCancel = kubectl.MicroscopeStart()
		Expect(microscopeErr).To(BeNil(), "Microscope cannot be started")
	})

	JustAfterEach(func() {
		kubectl.ValidateNoErrorsOnLogs(CurrentGinkgoTestDescription().Duration)
		Expect(microscopeCancel()).To(BeNil(), "cannot stop microscope")
	})

	AfterEach(func() {
		By("Deleting all resources created during test")
		kubectl.Delete(l7PolicyYAMLLink)
		kubectl.Delete(deathStarYAMLLink)
		kubectl.Delete(xwingYAMLLink)

		By("Waiting for all pods to finish terminating")
		ExpectAllPodsTerminated(kubectl)
	})

	It("Tests Star Wars Demo", func() {

		allianceLabel := "org=alliance"
		empireLabel := "org=empire"
		deathstarServiceName := "deathstar.default.svc.cluster.local"

		exhaustPortPath := filepath.Join(deathstarServiceName, "/v1/exhaust-port")

		// Taint the node instead of adding a nodeselector in the file so that we
		// don't have to customize the YAML for this test.
		By("Tainting %s so that all pods run on %s", helpers.K8s1, helpers.K8s2)
		res := kubectl.Exec(fmt.Sprintf("kubectl taint nodes %s demo=false:NoSchedule", helpers.K8s1))
		defer func() {
			By("Removing taint from %s after test finished", helpers.K8s1)
			res := kubectl.Exec(fmt.Sprintf("kubectl taint nodes %s demo:NoSchedule-", helpers.K8s1))
			res.ExpectSuccess("Unable to remove taint from k8s1: %s", res.CombineOutput())
		}()
		res.ExpectSuccess("Unable to apply taint to %s: %s", helpers.K8s1, res.CombineOutput())

		By("Applying deathstar deployment")
		res = kubectl.Apply(deathStarYAMLLink)
		res.ExpectSuccess("unable to apply %s: %s", deathStarYAMLLink, res.CombineOutput())

		By("Waiting for deathstar deployment pods to be ready")
		err := kubectl.WaitforPods(helpers.DefaultNamespace, fmt.Sprintf("-l %s", empireLabel), 300)
		Expect(err).Should(BeNil(), "Empire pods are not ready after timeout")

		By("Getting xwing pod names")
		xwingPods, err := kubectl.GetPodNames(helpers.DefaultNamespace, allianceLabel)
		Expect(err).Should(BeNil())
		Expect(xwingPods[0]).ShouldNot(Equal(""), "unable to get xwing pod names")

		// Test only needs to access one of the pods.
		xwingPod := xwingPods[0]

		By("Making sure all endpoints are in ready state")
		err = kubectl.CiliumEndpointWaitReady()
		Expect(err).To(BeNil(), "Endpoints are not ready after timeout")

		By("Showing how alliance can execute REST API call to main API endpoint")

		err = kubectl.WaitForKubeDNSEntry(deathstarServiceName)
		Expect(err).To(BeNil(), "DNS entry is not ready after timeout")

		res = kubectl.ExecPodCmd(helpers.DefaultNamespace, xwingPod,
			helpers.CurlWithHTTPCode("http://%s/v1", deathstarServiceName))
		res.ExpectContains("200", "unable to curl %s/v1: %s", deathstarServiceName, res.Output())

		By("Importing L7 Policy which restricts access to %q", exhaustPortPath)
		_, err = kubectl.CiliumPolicyAction(
			helpers.KubeSystemNamespace, l7PolicyYAMLLink, helpers.KubectlApply, 300)
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

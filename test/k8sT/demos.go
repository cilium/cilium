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
	"sync"

	. "github.com/cilium/cilium/test/ginkgo-ext"
	"github.com/cilium/cilium/test/helpers"

	. "github.com/onsi/gomega"
	"github.com/sirupsen/logrus"
)

var (
	demoTestName         = "K8sValidatedDemosTest"
	starWarsDemoLinkRoot = "https://raw.githubusercontent.com/cilium/star-wars-demo/master/v1"
)

func getStarWarsResourceLink(file string) string {
	// Cannot use filepath.Join because it removes one of the '/' from
	// https:// and results in a malformed URL.
	return fmt.Sprintf("%s/%s", starWarsDemoLinkRoot, file)
}

var _ = Describe(demoTestName, func() {

	var (
		demoPath         string
		once             sync.Once
		kubectl          *helpers.Kubectl
		logger           *logrus.Entry
		ciliumYAML       string
		microscopeErr    error
		microscopeCancel func() error

		deathStarYAMLLink = getStarWarsResourceLink("02-deathstar.yaml")
		l4PolicyYAMLLink  = getStarWarsResourceLink("policy/l4_policy.yaml")
		xwingYAMLLink     = getStarWarsResourceLink("03-xwing.yaml")
		l7PolicyYAMLLink  = getStarWarsResourceLink("policy/l7_policy.yaml")
	)

	initialize := func() {
		logger = log.WithFields(logrus.Fields{"testName": demoTestName})
		logger.Info("Starting")
		kubectl = helpers.CreateKubectl(helpers.K8s1VMName(), logger)

		//Manifest paths
		demoPath = helpers.ManifestGet("demo.yaml")

		// TODO (ianvernon) - factor this code out into separate functions as it's
		// boilerplate for most K8s test setup.
		ciliumYAML = helpers.ManifestGet("cilium_ds.yaml")
		res := kubectl.Apply(ciliumYAML)
		res.ExpectSuccess("unable to apply %s: %s", ciliumYAML, res.CombineOutput())
		status, err := kubectl.WaitforPods(helpers.KubeSystemNamespace, "-l k8s-app=cilium", 300)
		Expect(status).Should(BeTrue())
		Expect(err).Should(BeNil())
		err = kubectl.WaitKubeDNS()
		Expect(err).Should(BeNil())
	}

	BeforeEach(func() {
		once.Do(initialize)
	})

	AfterFailed(func() {
		kubectl.CiliumReport(helpers.KubeSystemNamespace)
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
		kubectl.Delete(l4PolicyYAMLLink)
		kubectl.Delete(deathStarYAMLLink)
		kubectl.Delete(xwingYAMLLink)

		By("Waiting for all pods to finish terminating")
		err := kubectl.WaitCleanAllTerminatingPods()
		Expect(err).To(BeNil(), "Terminating pods are not deleted after timeout")
	})

	It("Tests Star Wars Demo", func() {

		allianceLabel := "org=alliance"
		empireLabel := "org=empire"
		deathstarServiceName := "deathstar.default.svc.cluster.local"

		exhaustPortPath := filepath.Join(deathstarServiceName, "/v1/exhaust-port")

		By(fmt.Sprintf("Getting Cilium Pod on node %s", helpers.K8s2))
		ciliumPod2, err := kubectl.GetCiliumPodOnNode(helpers.KubeSystemNamespace, helpers.K8s2)
		Expect(err).Should(BeNil(), "unable to get Cilium pod on node %s", helpers.K8s2)

		// Taint the node instead of adding a nodeselector in the file so that we
		// don't have to customize the YAML for this test.
		By(fmt.Sprintf("Tainting %s so that all pods run on %s", helpers.K8s1, helpers.K8s2))
		res := kubectl.Exec(fmt.Sprintf("kubectl taint nodes %s demo=false:NoSchedule", helpers.K8s1))
		defer func() {
			By(fmt.Sprintf("Removing taint from %s after test finished", helpers.K8s1))
			res := kubectl.Exec(fmt.Sprintf("kubectl taint nodes %s demo:NoSchedule-", helpers.K8s1))
			res.ExpectSuccess("Unable to remove taint from k8s1: %s", res.CombineOutput())
		}()
		res.ExpectSuccess("Unable to apply taint to %s: %s", helpers.K8s1, res.CombineOutput())

		By("Applying deathstar deployment")
		res = kubectl.Apply(deathStarYAMLLink)
		res.ExpectSuccess("unable to apply %s: %s", deathStarYAMLLink, res.CombineOutput())

		By("Waiting for deathstar deployment pods to be ready")
		_, err = kubectl.WaitforPods(helpers.DefaultNamespace, fmt.Sprintf("-l %s", empireLabel), 300)
		Expect(err).Should(BeNil(), "Empire pods are not ready after timeout")

		By("Applying policy and waiting for policy revision to increase in Cilium pods")
		res = kubectl.Apply(l4PolicyYAMLLink)
		res.ExpectSuccess("unable to apply %s: %s", l4PolicyYAMLLink, res.CombineOutput())

		By("Applying alliance deployment")
		res = kubectl.Apply(xwingYAMLLink)
		res.ExpectSuccess("unable to apply %s: %s", xwingYAMLLink, res.CombineOutput())

		By("Waiting for alliance pods to be ready")
		_, err = kubectl.WaitforPods(helpers.DefaultNamespace, fmt.Sprintf("-l %s", allianceLabel), 300)
		Expect(err).Should(BeNil(), "Alliance pods are not ready after timeout")

		By("Getting xwing pod names")
		xwingPods, err := kubectl.GetPodNames(helpers.DefaultNamespace, allianceLabel)
		Expect(err).Should(BeNil())
		Expect(xwingPods[0]).ShouldNot(Equal(""), "unable to get xwing pod names")

		// Test only needs to access one of the pods.
		xwingPod := xwingPods[0]

		By("Making sure all endpoints are in ready state")
		arePodsReady := kubectl.CiliumEndpointWait(ciliumPod2)
		Expect(arePodsReady).To(BeTrue(), "pods running on k8s2 are not ready")

		By("Showing how alliance can execute REST API call to main API endpoint")

		err = kubectl.WaitForKubeDNSEntry(deathstarServiceName)
		Expect(err).To(BeNil(), "DNS entry is not ready after timeout")

		res = kubectl.ExecPodCmd(helpers.DefaultNamespace, xwingPod,
			helpers.CurlWithHTTPCode("http://%s/v1", deathstarServiceName))
		res.ExpectContains("200", "unable to curl %s/v1: %s", deathstarServiceName, res.Output())

		By(fmt.Sprintf("Importing L7 Policy which restricts access to %s", exhaustPortPath))
		kubectl.Delete(l4PolicyYAMLLink)
		res = kubectl.Apply(l7PolicyYAMLLink)
		res.ExpectSuccess("unable to apply %s: %s", l7PolicyYAMLLink, res.CombineOutput())

		By("Waiting for endpoints to be ready after importing policy")
		arePodsReady = kubectl.CiliumEndpointWait(ciliumPod2)
		Expect(arePodsReady).To(BeTrue(), "pods running on k8s2 are not ready")

		By(fmt.Sprintf("Showing how alliance cannot access %s without force header in API request after importing L7 Policy", exhaustPortPath))
		res = kubectl.ExecPodCmd(helpers.DefaultNamespace, xwingPod,
			helpers.CurlWithHTTPCode("-X PUT http://%s", exhaustPortPath))
		res.ExpectContains("403", "able to access %s when policy disallows it; %s", exhaustPortPath, res.Output())

		By(fmt.Sprintf("Showing how alliance can access %s with force header in API request to attack the deathstar", exhaustPortPath))
		res = kubectl.ExecPodCmd(helpers.DefaultNamespace, xwingPod,
			helpers.CurlWithHTTPCode("-X PUT -H 'X-Has-Force: True' http://%s", exhaustPortPath))
		By("Expecting 503 to be returned when using force header to attack the deathstar")
		res.ExpectContains("503", "unable to access %s when policy allows it; %s", exhaustPortPath, res.Output())
	})

})

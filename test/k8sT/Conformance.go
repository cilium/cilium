// Copyright 2020 Authors of Cilium
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
	. "github.com/cilium/cilium/test/ginkgo-ext"
	"github.com/cilium/cilium/test/helpers"

	. "github.com/onsi/gomega"
)

var _ = Describe("K8sConformance", func() {
	var kubectl *helpers.Kubectl
	var ciliumFilename string
	var connectivityCheckYaml string
	var connectivityCheckYamlSimple string

	BeforeAll(func() {
		kubectl = helpers.CreateKubectl(helpers.K8s1VMName(), logger)
		connectivityCheckYaml = kubectl.GetFilePath("../examples/kubernetes/connectivity-check/connectivity-check-hostport.yaml")
		connectivityCheckYamlSimple = kubectl.GetFilePath("../examples/kubernetes/connectivity-check/connectivity-check-single-node.yaml")
		ciliumFilename = helpers.TimestampFilename("cilium.yaml")
	})

	AfterEach(func() {
		kubectl.Delete(connectivityCheckYaml)
		kubectl.Delete(connectivityCheckYamlSimple)
		ExpectAllPodsInNsTerminated(kubectl, "default")
	})

	AfterFailed(func() {
		kubectl.CiliumReport(helpers.CiliumNamespace,
			"cilium endpoint list")
	})

	AfterAll(func() {
		kubectl.CloseSSHClient()
	})

	JustAfterEach(func() {
		blacklist := helpers.GetBadLogMessages()
		kubectl.ValidateListOfErrorsInLogs(CurrentGinkgoTestDescription().Duration, blacklist)
	})

	deployCilium := func(options map[string]string) {
		DeployCiliumOptionsAndDNS(kubectl, ciliumFilename, options)

		_, err := kubectl.CiliumNodesWait()
		ExpectWithOffset(1, err).Should(BeNil(), "Failure while waiting for k8s nodes to be annotated by Cilium")

		By("Making sure all endpoints are in ready state")
		err = kubectl.CiliumEndpointWaitReady()
		ExpectWithOffset(1, err).To(BeNil(), "Failure while waiting for all cilium endpoints to reach ready state")
	}

	Context("Portmap Chaining", func() {
		It("Check connectivity-check compliance with portmap chaining", func() {
			SkipIfIntegration(helpers.CIIntegrationFlannel)
			SkipItIfNoKubeProxy()

			deployCilium(map[string]string{
				"global.cni.chainingMode": "portmap",
			})

			kubectl.ApplyDefault(connectivityCheckYaml).ExpectSuccess("cannot install connectivity-check")

			err := kubectl.WaitforPods(helpers.DefaultNamespace, "", helpers.HelperTimeout)
			ExpectWithOffset(1, err).Should(BeNil(), "connectivity-check pods are not ready after timeout")
		})

		It("Check one node connectivity-check compliance with portmap chaining", func() {
			SkipIfIntegration(helpers.CIIntegrationFlannel)
			SkipItIfNoKubeProxy()

			deployCilium(map[string]string{
				"global.cni.chainingMode": "portmap",
			})

			kubectl.ApplyDefault(connectivityCheckYamlSimple).ExpectSuccess("cannot install connectivity-check-single-node")

			err := kubectl.WaitforPods(helpers.DefaultNamespace, "", helpers.HelperTimeout)
			ExpectWithOffset(1, err).Should(BeNil(), "connectivity-check pods are not ready after timeout")
		})

	})
})

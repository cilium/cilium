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
	"time"

	. "github.com/cilium/cilium/test/ginkgo-ext"
	"github.com/cilium/cilium/test/helpers"

	. "github.com/onsi/gomega"
)

var _ = Describe("K8sIdentity", func() {
	var kubectl *helpers.Kubectl
	var ciliumFilename string

	BeforeAll(func() {
		kubectl = helpers.CreateKubectl(helpers.K8s1VMName(), logger)
		ciliumFilename = helpers.TimestampFilename("cilium.yaml")
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

	Context("Identity expiration", func() {
		It("Expiration of CiliumIdentity", func() {
			deployCilium(map[string]string{
				"global.endpointGCInterval":       "2s",
				"global.identityGCInterval":       "2s",
				"global.identityHeartbeatTimeout": "2s",
			})

			By("Creating unused CiliumIdentity")
			dummyIdentity := helpers.ManifestGet(kubectl.BasePath(), "dummy_identity.yaml")
			kubectl.ApplyDefault(dummyIdentity).ExpectSuccess("Cannot import dummy identity")

			By("Waiting for CiliumIdentity to be garbage collected")
			err := helpers.RepeatUntilTrue(func() bool {
				return !kubectl.ExecShort(helpers.KubectlCmd + " get ciliumidentity 99999").WasSuccessful()
			}, &helpers.TimeoutConfig{Timeout: 2 * time.Minute})
			Expect(err).Should(BeNil(), "CiliumIdentity did not get garbage collected before timeout")
		})
	})
})

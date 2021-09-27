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
	var (
		kubectl        *helpers.Kubectl
		ciliumFilename string
	)

	BeforeAll(func() {
		kubectl = helpers.CreateKubectl(helpers.K8s1VMName(), logger)

		ciliumFilename = helpers.TimestampFilename("cilium.yaml")
	})

	AfterFailed(func() {
		kubectl.CiliumReport("cilium endpoint list")
	})

	AfterAll(func() {
		kubectl.CloseSSHClient()
	})

	JustAfterEach(func() {
		kubectl.ValidateNoErrorsInLogs(CurrentGinkgoTestDescription().Duration)
	})

	SkipContextIf(func() bool {
		return helpers.DoesNotRunOnGKE() && helpers.DoesNotRunOnEKS()
	}, "Identity expiration", func() {

		BeforeAll(func() {
			DeployCiliumOptionsAndDNS(kubectl, ciliumFilename, map[string]string{
				"endpointGCInterval":       "2s",
				"identityGCInterval":       "2s",
				"identityHeartbeatTimeout": "2s",
			})

			_, err := kubectl.CiliumNodesWait()
			ExpectWithOffset(1, err).Should(BeNil(), "Failure while waiting for k8s nodes to be annotated by Cilium")

			By("Making sure all endpoints are in ready state")
			err = kubectl.CiliumEndpointWaitReady()
			ExpectWithOffset(1, err).To(BeNil(), "Failure while waiting for all cilium endpoints to reach ready state")
		})

		AfterAll(func() {
			UninstallCiliumFromManifest(kubectl, ciliumFilename)
		})

		AfterFailed(func() {
			kubectl.CiliumReport("cilium endpoint list")
		})

		It("Expiration of CiliumIdentity", func() {
			By("Creating unused CiliumIdentity")
			dummyIdentity := helpers.ManifestGet(kubectl.BasePath(), "dummy_identity.yaml")
			kubectl.ApplyDefault(dummyIdentity).ExpectSuccess("Cannot import dummy identity")

			By("Waiting for CiliumIdentity to be garbage collected")
			Eventually(func() bool {
				return !kubectl.ExecShort(helpers.KubectlCmd + " get ciliumidentity 99999").WasSuccessful()
			}, 2*time.Minute, time.Second).Should(BeTrue(), "CiliumIdentity did not get garbage collected before timeout")
		})
	})

	Context("CiliumEndpointBatch Identity testing", func() {

		var (
			identityDeploy string
		)

		BeforeAll(func() {
			DeployCiliumOptionsAndDNS(kubectl, ciliumFilename, map[string]string{
				"enableCiliumEndpointBatch": "true",
			})

			By("Making sure all endpoints are in ready state")
			err := kubectl.CiliumEndpointWaitReady()
			ExpectWithOffset(1, err).To(BeNil(), "Failure while waiting for all cilium endpoints to reach ready state")

			identityDeploy = helpers.ManifestGet(kubectl.BasePath(), "identity_modify.yaml")
			kubectl.ApplyDefault(identityDeploy).ExpectSuccess("Unable to deploy identity_modify.yaml")
			err = kubectl.WaitforPods(helpers.DefaultNamespace, "-l zgroup=test-identity", helpers.HelperTimeout)
			Expect(err).Should(BeNil())
		})

		AfterAll(func() {
			kubectl.DeleteLong(identityDeploy).ExpectSuccess(
				"%s deployment cannot be deleted", identityDeploy)
			UninstallCiliumFromManifest(kubectl, ciliumFilename)
		})

		AfterFailed(func() {
			kubectl.CiliumReport("cilium endpoint list")
		})

		It("Change CiliumEndpoint Identity", func() {
			pods, err := kubectl.GetPodNames(helpers.DefaultNamespace, "zgroup=test-identity")
			Expect(pods).ToNot(BeEmpty())
			Expect(err).ToNot(HaveOccurred())
			// Get CEP name, CEP Identity ID and corresponding CEB name
			err = kubectl.WaitForCEPIdentity(helpers.DefaultNamespace, pods[0])
			Expect(err).Should(BeNil())
			ep, err := kubectl.GetEndpointSecurityIdentityId(helpers.DefaultNamespace, pods[0])
			Expect(err).ToNot(HaveOccurred())
			oldCeb, err := kubectl.GetCEBNameForCEPIdentity(pods[0], ep)
			Expect(err).ToNot(HaveOccurred())

			By("Changing pod labels")
			err = kubectl.LabelPod(helpers.DefaultNamespace, pods[0], "ceb=identity")
			Expect(err).ToNot(HaveOccurred())

			// Get new Identity ID and new corresponding CEB name
			err = kubectl.WaitForNewCEPIdentity(helpers.DefaultNamespace, pods[0], ep)
			Expect(err).ToNot(HaveOccurred())
			newEp, err := kubectl.GetEndpointSecurityIdentityId(helpers.DefaultNamespace, pods[0])
			Expect(err).ToNot(HaveOccurred())
			newCeb, err := kubectl.GetCEBNameForCEPIdentity(pods[0], newEp)
			Expect(err).ToNot(HaveOccurred())
			// old and new Identities shouldn't match
			Expect(ep).Should(Not(Equal(newEp)))
			// oldCEB shouldn't exist now
			_, err = kubectl.GetCEBNameForCEPIdentity(pods[0], ep)
			Expect(err).To(HaveOccurred())
		})
	})

})

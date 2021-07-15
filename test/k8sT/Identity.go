// SPDX-License-Identifier: Apache-2.0
// Copyright 2020 Authors of Cilium

package k8sTest

import (
	"time"

	. "github.com/cilium/cilium/test/ginkgo-ext"
	"github.com/cilium/cilium/test/helpers"

	. "github.com/onsi/gomega"
)

var _ = Describe("K8sIdentity", func() {
	SkipContextIf(func() bool {
		return helpers.DoesNotRunOnGKE() && helpers.DoesNotRunOnEKS()
	}, "Identity expiration", func() {
		var (
			kubectl        *helpers.Kubectl
			ciliumFilename string
		)

		BeforeAll(func() {
			kubectl = helpers.CreateKubectl(helpers.K8s1VMName(), logger)

			ciliumFilename = helpers.TimestampFilename("cilium.yaml")
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

		AfterFailed(func() {
			kubectl.CiliumReport("cilium endpoint list")
		})

		AfterAll(func() {
			UninstallCiliumFromManifest(kubectl, ciliumFilename)
			kubectl.CloseSSHClient()
		})

		JustAfterEach(func() {
			kubectl.ValidateNoErrorsInLogs(CurrentGinkgoTestDescription().Duration)
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
})

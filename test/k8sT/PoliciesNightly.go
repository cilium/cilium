// SPDX-License-Identifier: Apache-2.0
// Copyright 2017-2019 Authors of Cilium

package k8sTest

import (
	"fmt"
	"time"

	. "github.com/cilium/cilium/test/ginkgo-ext"
	"github.com/cilium/cilium/test/helpers"
	"github.com/cilium/cilium/test/helpers/policygen"

	. "github.com/onsi/gomega"
)

var _ = Describe("NightlyPolicies", func() {

	var kubectl *helpers.Kubectl
	var timeout = 10 * time.Minute
	var ciliumFilename string

	BeforeAll(func() {
		kubectl = helpers.CreateKubectl(helpers.K8s1VMName(), logger)

		ciliumFilename = helpers.TimestampFilename("cilium.yaml")
		DeployCiliumAndDNS(kubectl, ciliumFilename)
	})

	AfterFailed(func() {
		kubectl.CiliumReport("cilium endpoint list", "cilium service list")
	})

	JustAfterEach(func() {
		kubectl.ValidateNoErrorsInLogs(CurrentGinkgoTestDescription().Duration)
	})

	AfterAll(func() {
		// Delete all pods created
		kubectl.Exec(fmt.Sprintf(
			"%s delete pods,svc,cnp -n %s -l test=policygen",
			helpers.KubectlCmd, helpers.DefaultNamespace))
		kubectl.DeleteCiliumDS()
		err := kubectl.WaitTerminatingPods(timeout)
		Expect(err).To(BeNil(), "Cannot clean pods during timeout")

		UninstallCiliumFromManifest(kubectl, ciliumFilename)
		kubectl.CloseSSHClient()
	})

	Context("PolicyEnforcement default", func() {
		createTests := func() {
			testSpecs := policygen.GeneratedTestSpec()
			for _, test := range testSpecs {
				func(testSpec policygen.TestSpec) {
					It(testSpec.String(), func() {
						testSpec.RunTest(kubectl)
					})
				}(test)
			}
		}
		createTests()
	})
})

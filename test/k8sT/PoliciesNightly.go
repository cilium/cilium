// Copyright 2017-2019 Authors of Cilium
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

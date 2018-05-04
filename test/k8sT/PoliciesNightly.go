// Copyright 2017 Authors of Cilium
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

	. "github.com/cilium/cilium/test/ginkgo-ext"
	"github.com/cilium/cilium/test/helpers"
	"github.com/cilium/cilium/test/helpers/policygen"

	"github.com/sirupsen/logrus"
)

var _ = Describe("NightlyPolicies", func() {

	var kubectl *helpers.Kubectl
	var logger *logrus.Entry

	BeforeAll(func() {
		logger = log.WithFields(logrus.Fields{"testName": "NightlyK8sPolicies"})
		logger.Info("Starting")

		kubectl = helpers.CreateKubectl(helpers.K8s1VMName(), logger)
		ciliumPath := helpers.ManifestGet("cilium_ds.yaml")
		kubectl.Apply(ciliumPath)
		ExpectCiliumReady(kubectl)
		ExpectKubeDNSReady(kubectl)
	})

	AfterFailed(func() {
		kubectl.CiliumReport(helpers.KubeSystemNamespace,
			"cilium policy get",
			"cilium endpoint list",
			"cilium service list")
	})

	JustAfterEach(func() {
		kubectl.ValidateNoErrorsOnLogs(CurrentGinkgoTestDescription().Duration)
	})

	AfterEach(func() {
		ExpectAllPodsTerminated(kubectl)
	})

	AfterAll(func() {
		// Delete all pods created
		kubectl.Exec(fmt.Sprintf(
			"%s delete --all pods,svc,cnp -n %s", helpers.KubectlCmd, helpers.DefaultNamespace))

		ExpectAllPodsTerminated(kubectl)
	})
	Context("PolicyEnforcement default", func() {
		createTests := func() {
			testSpecs := policygen.GeneratedTestSpec()
			for _, test := range testSpecs {
				func(testSpec policygen.TestSpec) {
					It(fmt.Sprintf("%s", testSpec), func() {
						testSpec.RunTest(kubectl)
					})
				}(test)
			}
		}
		createTests()
	})
})

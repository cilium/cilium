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
	"sync"

	"github.com/cilium/cilium/test/helpers"
	"github.com/cilium/cilium/test/helpers/policygen"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	"github.com/sirupsen/logrus"
)

var _ = Describe("NightlyPolicies", func() {

	var kubectl *helpers.Kubectl
	var logger *logrus.Entry
	var once sync.Once

	initialize := func() {
		logger = log.WithFields(logrus.Fields{"testName": "NightlyK8sPolicies"})
		logger.Info("Starting")

		kubectl = helpers.CreateKubectl(helpers.K8s1VMName(), logger)
		ciliumPath := kubectl.ManifestGet("cilium_ds.yaml")
		kubectl.Apply(ciliumPath)
		_, err := kubectl.WaitforPods(helpers.KubeSystemNamespace, "-l k8s-app=cilium", 600)
		Expect(err).Should(BeNil())

		err = kubectl.WaitKubeDNS()
		Expect(err).Should(BeNil())
	}

	BeforeEach(func() {
		once.Do(initialize)
	})

	AfterEach(func() {
		kubectl.ValidateNoErrorsOnLogs(CurrentGinkgoTestDescription().Duration)
		if CurrentGinkgoTestDescription().Failed {
			ciliumPod, _ := kubectl.GetCiliumPodOnNode(helpers.KubeSystemNamespace, "k8s1")
			kubectl.CiliumReport("kube-system", ciliumPod, []string{
				"cilium policy get",
				"cilium endpoint list",
				"cilium service list"})
		}
		err := kubectl.WaitCleanAllTerminatingPods()
		Expect(err).To(BeNil(), "Terminating containers are not deleted after timeout")
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

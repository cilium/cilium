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
	. "github.com/cilium/cilium/test/ginkgo-ext"
	"github.com/cilium/cilium/test/helpers"

	. "github.com/onsi/gomega"
)

var _ = Describe("K8sMicroscope", func() {
	var (
		kubectl *helpers.Kubectl
	)

	BeforeAll(func() {
		kubectl = helpers.CreateKubectl(helpers.K8s1VMName(), logger)

		_ = kubectl.Apply(helpers.DNSDeployment())

		// Deploy the etcd operator
		err := kubectl.DeployETCDOperator()
		Expect(err).To(BeNil(), "Unable to deploy etcd operator")

		err = kubectl.CiliumInstall(helpers.CiliumDefaultDSPatch, helpers.CiliumConfigMapPatch)
		Expect(err).To(BeNil(), "Cilium cannot be installed")

		ExpectCiliumReady(kubectl)
	})

	AfterFailed(func() {
		kubectl.CiliumReport(helpers.KubeSystemNamespace,
			"cilium endpoint list")
	})

	AfterAll(func() {
		ExpectAllPodsTerminated(kubectl)
	})

	It("Runs microscope", func() {
		microscopeErr, microscopeCancel := kubectl.MicroscopeStart()
		Expect(microscopeErr).To(BeNil(), "Microscope cannot be started")

		err := helpers.WithTimeout(func() bool {
			res := kubectl.ExecPodCmd("kube-system", "microscope", "pgrep -f microscope")
			return res.WasSuccessful()
		}, "running microscope processes not found",
			&helpers.TimeoutConfig{
				Ticker:  5,
				Timeout: 120,
			})

		Expect(err).To(BeNil())

		kubectl.ValidateNoErrorsOnLogs(CurrentGinkgoTestDescription().Duration)
		Expect(microscopeCancel()).To(BeNil(), "cannot stop microscope")

		err = helpers.WithTimeout(func() bool {
			res := kubectl.ExecPodCmd("kube-system", "microscope", "pgrep -f microscope")
			return !res.WasSuccessful()
		}, "found running microscope processes; no microscope processes should be running",
			&helpers.TimeoutConfig{
				Ticker:  5,
				Timeout: 120,
			})
		Expect(err).To(BeNil())
	})
})

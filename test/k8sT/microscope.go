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
	"time"

	. "github.com/cilium/cilium/test/ginkgo-ext"
	"github.com/cilium/cilium/test/helpers"

	. "github.com/onsi/gomega"
	"github.com/sirupsen/logrus"
)

var (
	microscopeTestName = "K8sValidatedMicroscope"
)

var _ = Describe(microscopeTestName, func() {

	var (
		kubectl *helpers.Kubectl
		logger  *logrus.Entry
	)

	BeforeAll(func() {
		logger = log.WithFields(logrus.Fields{"testName": microscopeTestName})
		logger.Info("Starting")
		kubectl = helpers.CreateKubectl(helpers.K8s1VMName(), logger)

		err := kubectl.CiliumInstall(helpers.CiliumDSPath)
		Expect(err).To(BeNil(), "Cilium cannot be installed")

		ExpectCiliumReady(kubectl)
		ExpectKubeDNSReady(kubectl)
	})

	AfterFailed(func() {
		kubectl.CiliumReport(helpers.KubeSystemNamespace,
			"cilium endpoint list")
	})

	It("Runs microscope", func() {
		microscopeErr, microscopeCancel := kubectl.MicroscopeStart()
		Expect(microscopeErr).To(BeNil(), "Microscope cannot be started")

		time.Sleep(time.Second * 10)

		kubectl.ValidateNoErrorsOnLogs(CurrentGinkgoTestDescription().Duration)
		Expect(microscopeCancel()).To(BeNil(), "cannot stop microscope")

		time.Sleep(time.Second * 10)

		res := kubectl.ExecPodCmd("kube-system", "microscope", "pgrep -f microscope")
		res.ExpectFail()
	})
})

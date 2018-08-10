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
	"context"
	"fmt"
	. "github.com/cilium/cilium/test/ginkgo-ext"
	"github.com/cilium/cilium/test/helpers"

	. "github.com/onsi/gomega"
	"github.com/sirupsen/logrus"
)

var _ = Describe("K8sLabelChanges", func() {

	var (
		kubectl          *helpers.Kubectl
		demoPath                            = helpers.ManifestGet("demo.yaml")
		backgroundCancel context.CancelFunc = func() { return }
		backgroundError  error
	)

	BeforeAll(func() {
		kubectl = helpers.CreateKubectl(helpers.K8s1VMName(), logger)

		err := kubectl.CiliumInstall(helpers.CiliumDSPath)
		Expect(err).To(BeNil(), "Cilium cannot be installed")

		ExpectCiliumReady(kubectl)
		ExpectKubeDNSReady(kubectl)
	})

	AfterEach(func() {
		ExpectAllPodsTerminated(kubectl)
	})

	AfterFailed(func() {
		kubectl.CiliumReport(helpers.KubeSystemNamespace,
			"cilium service list",
			"cilium endpoint list")
	})

	AfterAll(func() {
		_ = kubectl.WaitCleanAllTerminatingPods()
		_ = kubectl.Exec(fmt.Sprintf("%s label ns/%s foo-bar-",
			helpers.KubectlCmd, helpers.DefaultNamespace))
	})

	JustBeforeEach(func() {
		backgroundCancel, backgroundError = kubectl.BackgroundReport("uptime")
		Expect(backgroundError).To(BeNil(), "Cannot start background report process")
	})

	JustAfterEach(func() {
		kubectl.ValidateNoErrorsOnLogs(CurrentGinkgoTestDescription().Duration)
		backgroundCancel()
	})

	Context("Cilium Endpoint Label Changes", func() {
		BeforeAll(func() {
			kubectl.Apply(demoPath).ExpectSuccess("Unable to create demo pods")
			err := kubectl.WaitforPods(helpers.DefaultNamespace, "-l zgroup=testapp", 300)
			Expect(err).Should(BeNil(), "Test pods are not ready after timeout")
			err = kubectl.CiliumEndpointWaitReady()
			Expect(err).Should(BeNil(), "Cilium Endpoints are not ready after timeout")
		})

		AfterAll(func() {
			kubectl.Delete(demoPath)
		})

		It("Changes Endpoint Labels on Pod and Namespace Label Changes", func() {
			checkIfPodLabelsUpdated := func(podAnnotationPrev map[string]string) (newLabels map[string]string, err error) {
				// Wait for all pods to have a new identity
				err = helpers.WithTimeout(func() bool {
					var err error
					newLabels, err = kubectl.GetPodsIdentities(helpers.DefaultNamespace, "-l zgroup=testapp")
					Expect(err).Should(BeNil(), "Test pods are not available")
					for pod, identity := range newLabels {
						if identity == podAnnotationPrev[pod] {
							logger.WithFields(logrus.Fields{
								"identity":     identity,
								"pre-identity": podAnnotationPrev[pod],
								"pod":          pod,
							}).Debugf("Pod identity is the same")
							return false
						}
					}
					return true
				}, "Not all pods got a new identity", &helpers.TimeoutConfig{Timeout: 180})
				return
			}

			podAnnotationPrev := map[string]string{}
			var err error

			// Wait for all pods to have an identity
			podAnnotationPrev, err = checkIfPodLabelsUpdated(podAnnotationPrev)
			Expect(err).Should(BeNil(), "Test pods don't have an identity")

			By("Adding a new label in pods")
			for pod := range podAnnotationPrev {
				kubectl.Exec(fmt.Sprintf("%s -n %s label pod/%s foo-bar=new-label",
					helpers.KubectlCmd, helpers.DefaultNamespace, pod)).ExpectSuccess("Unable to add a pod label")
			}

			podAnnotationPrev, err = checkIfPodLabelsUpdated(podAnnotationPrev)
			Expect(err).Should(BeNil(), "Test pods don't have a new identity")

			By("Adding a label in the namespace")
			kubectl.Exec(fmt.Sprintf("%s label ns/%s foo-bar=new-label",
				helpers.KubectlCmd, helpers.DefaultNamespace)).ExpectSuccess("Unable to add a namespace label")

			podAnnotationPrev, err = checkIfPodLabelsUpdated(podAnnotationPrev)
			Expect(err).Should(BeNil(), "Test pods don't have a new identity")

			By("Removing the previous label from the namespace")
			kubectl.Exec(fmt.Sprintf("%s label ns/%s foo-bar-",
				helpers.KubectlCmd, helpers.DefaultNamespace)).ExpectSuccess("Unable to remove a namespace label")

			podAnnotationPrev, err = checkIfPodLabelsUpdated(podAnnotationPrev)
			Expect(err).Should(BeNil(), "Test pods don't have a new identity")

			By("Removing labels from pods")
			for pod := range podAnnotationPrev {
				kubectl.Exec(fmt.Sprintf("%s -n %s label pod/%s foo-bar-",
					helpers.KubectlCmd, helpers.DefaultNamespace, pod)).ExpectSuccess("Unable to remove a pod label")
			}

			podAnnotationPrev, err = checkIfPodLabelsUpdated(podAnnotationPrev)
			Expect(err).Should(BeNil(), "Test pods don't have a new identity")
		})
	})
})

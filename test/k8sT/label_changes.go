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
	"time"

	. "github.com/cilium/cilium/test/ginkgo-ext"
	"github.com/cilium/cilium/test/helpers"

	. "github.com/onsi/gomega"
)

var _ = Describe("K8sPolicyTest", func() {

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
			kubectl.Apply(demoPath)
			err := kubectl.WaitforPods(helpers.DefaultNamespace, "-l zgroup=testapp", 300)
			Expect(err).Should(BeNil(), "Test pods are not ready after timeout")
		})

		AfterAll(func() {
			kubectl.Delete(demoPath)
		})

		It("Changes Endpoint Labels on Pod Label Changes", func() {
			checkIfPodsHaveLabels := func(podAnnotationPrev map[string]string) map[string]string {
				podAnnotation := map[string]string{}
				// Wait for all pods to have a new identity
				err := helpers.WithTimeout(func() bool {
					var err error
					podAnnotation, err = kubectl.GetPodsIdentities(helpers.DefaultNamespace, "-l zgroup=testapp")
					Expect(err).Should(BeNil(), "Test pods are not available")
					for key, identity := range podAnnotation {
						if identity == podAnnotationPrev[key] {
							return false
						}
					}
					return true
				}, "Not all pods got a new identity", &helpers.TimeoutConfig{Timeout: 3 * time.Minute})
				Expect(err).Should(BeNil(), "Not all pods got a new identity")
				return podAnnotation
			}

			podAnnotationPrev := map[string]string{}

			// Wait for all pods to have an identity
			err := helpers.WithTimeout(func() bool {
				var err error
				podAnnotationPrev, err = kubectl.GetPodsIdentities(helpers.DefaultNamespace, "-l zgroup=testapp")
				Expect(err).Should(BeNil(), "Test pods are not available")
				for _, identity := range podAnnotationPrev {
					if identity == "" {
						return false
					}
				}
				return true
			}, "Found pods without an identity", &helpers.TimeoutConfig{Timeout: 3 * time.Minute})
			Expect(err).Should(BeNil(), "Test pods don't have an identity")

			By("Adding a new label in pods")
			for pod := range podAnnotationPrev {
				kubectl.Exec(fmt.Sprintf("%s -n %s label pod/%s pods foo-bar=new-label",
					helpers.KubectlCmd, helpers.DefaultNamespace, pod))
			}

			podAnnotationPrev = checkIfPodsHaveLabels(podAnnotationPrev)

			By("Adding a label in the namespace")
			kubectl.Exec(fmt.Sprintf("%s label ns/%s foo-bar=new-label",
				helpers.KubectlCmd, helpers.DefaultNamespace))

			podAnnotationPrev = checkIfPodsHaveLabels(podAnnotationPrev)

			By("Removing the previous label from the namespace")
			kubectl.Exec(fmt.Sprintf("%s label ns/%s foo-bar-",
				helpers.KubectlCmd, helpers.DefaultNamespace))

			podAnnotationPrev = checkIfPodsHaveLabels(podAnnotationPrev)

			By("Adding a new label in pods")
			for pod := range podAnnotationPrev {
				kubectl.Exec(fmt.Sprintf("%s -n %s label pod/%s pods foo-bar-",
					helpers.KubectlCmd, helpers.DefaultNamespace, pod))
			}

			podAnnotationPrev = checkIfPodsHaveLabels(podAnnotationPrev)
		})
	})
})

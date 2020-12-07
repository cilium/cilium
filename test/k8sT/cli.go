// Copyright 2018-2020 Authors of Cilium
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
	"strings"

	. "github.com/cilium/cilium/test/ginkgo-ext"
	"github.com/cilium/cilium/test/helpers"

	. "github.com/onsi/gomega"
)

var _ = Describe("K8sCLI", func() {
	SkipContextIf(helpers.DoesNotRunOnGKE, "CLI", func() {
		var kubectl *helpers.Kubectl
		var ciliumFilename string

		BeforeAll(func() {
			kubectl = helpers.CreateKubectl(helpers.K8s1VMName(), logger)

			ciliumFilename = helpers.TimestampFilename("cilium.yaml")
			DeployCiliumAndDNS(kubectl, ciliumFilename)
			ExpectCiliumReady(kubectl)
		})

		AfterAll(func() {
			UninstallCiliumFromManifest(kubectl, ciliumFilename)
		})

		JustAfterEach(func() {
			kubectl.ValidateNoErrorsInLogs(CurrentGinkgoTestDescription().Duration)
		})

		Context("Identity CLI testing", func() {
			const (
				manifestYAML = "test-cli.yaml"
				fooID        = "foo"
				fooSHA       = "a83c739e630049e46b9ac6883dc2682b31bf8472b09c8bb81d87092a51d14ddf"
				fooNode      = "k8s1"
				// These labels are automatically added to all pods in the default namespace.
				defaultLabels = "k8s:io.cilium.k8s.policy.cluster=default " +
					"k8s:io.cilium.k8s.policy.serviceaccount=default k8s:io.kubernetes.pod.namespace=default"
			)

			var (
				cliManifest string
				ciliumPod   string
				err         error
				identity    int64
			)

			BeforeAll(func() {
				cliManifest = helpers.ManifestGet(kubectl.BasePath(), manifestYAML)
				res := kubectl.ApplyDefault(cliManifest)
				res.ExpectSuccess("Unable to apply %s", cliManifest)
				err = kubectl.WaitforPods(helpers.DefaultNamespace, "-l id", helpers.HelperTimeout)
				Expect(err).Should(BeNil(), "The pods were not ready after timeout")

				ciliumPod, err = kubectl.GetCiliumPodOnNodeWithLabel(fooNode)
				Expect(err).Should(BeNil())

				err := kubectl.WaitForCEPIdentity(helpers.DefaultNamespace, fooID)
				Expect(err).Should(BeNil())

				ep, err := kubectl.GetCiliumEndpoint(helpers.DefaultNamespace, fooID)
				Expect(err).Should(BeNil(), fmt.Sprintf("Unable to get CEP for pod %s", fooID))
				identity = ep.Identity.ID
			})

			AfterAll(func() {
				_ = kubectl.Delete(cliManifest)
				ExpectAllPodsTerminated(kubectl)
			})

			It("Test labelsSHA256", func() {
				cmd := fmt.Sprintf("cilium identity get %d -o json", identity)
				res := kubectl.ExecPodCmd(helpers.CiliumNamespace, ciliumPod, cmd)
				res.ExpectSuccess()
				out, err := res.Filter("{[0].labelsSHA256}")
				Expect(err).Should(BeNil(), "Error getting SHA from identity")
				Expect(out.String()).Should(Equal(fooSHA))
			})

			It("Test identity list", func() {
				By("Testing 'cilium identity list' for an endpoint's identity")
				cmd := fmt.Sprintf("cilium identity list k8s:id=%s %s", fooID, defaultLabels)
				res := kubectl.ExecPodCmd(helpers.CiliumNamespace, ciliumPod, cmd)
				res.ExpectSuccess(fmt.Sprintf("Unable to get identity list output for label k8s:id=%s %s", fooID, defaultLabels))

				resSingleOut := res.SingleOut()
				containsIdentity := strings.Contains(resSingleOut, fmt.Sprintf("%d", identity))
				Expect(containsIdentity).To(BeTrue(), "Identity %d of endpoint %s not in 'cilium identity list' output", identity, resSingleOut)

				By("Testing 'cilium identity list' for reserved identities")
				res = kubectl.ExecPodCmd(helpers.CiliumNamespace, ciliumPod, "cilium identity list")
				res.ExpectSuccess("Unable to get identity list output")
				resSingleOut = res.SingleOut()

				reservedIdentities := []string{"health", "host", "world", "init"}
				for _, id := range reservedIdentities {
					By("Checking that reserved identity '%s' is in 'cilium identity list' output", id)
					containsReservedIdentity := strings.Contains(resSingleOut, id)
					Expect(containsReservedIdentity).To(BeTrue(), "Reserved identity '%s' not in 'cilium identity list' output", id)
				}
			})
		})

		Context("stdout/stderr testing", func() {
			var (
				ciliumPod string
				err       error
			)

			BeforeAll(func() {
				ciliumPod, err = kubectl.GetCiliumPodOnNodeWithLabel("k8s1")
				Expect(err).Should(BeNil())
			})

			It("Root command help should print to stdout", func() {
				res := kubectl.ExecPodCmd(helpers.CiliumNamespace, ciliumPod, "cilium help")
				Expect(res.Stdout()).Should(ContainSubstring("Use \"cilium [command] --help\" for more information about a command."))
			})

			It("Subcommand help should print to stdout", func() {
				res := kubectl.ExecPodCmd(helpers.CiliumNamespace, ciliumPod, "cilium help bpf")
				Expect(res.Stdout()).Should(ContainSubstring("Use \"cilium bpf [command] --help\" for more information about a command."))
			})

			It("Failed subcommand should print help to stdout", func() {
				res := kubectl.ExecPodCmd(helpers.CiliumNamespace, ciliumPod, "cilium endpoint confi 173")
				Expect(res.Stdout()).Should(ContainSubstring("Use \"cilium endpoint [command] --help\" for more information about a command."))
			})
		})
	})
})

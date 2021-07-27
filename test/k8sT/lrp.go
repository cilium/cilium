// Copyright 2020-2021 Authors of Cilium
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
	"strings"
	"sync"
	"time"

	. "github.com/cilium/cilium/test/ginkgo-ext"
	"github.com/cilium/cilium/test/helpers"

	. "github.com/onsi/gomega"
)

// The 5.4 CI job is intended to catch BPF complexity regressions and as such
// doesn't need to execute this test suite.
var _ = SkipDescribeIf(helpers.RunsOn54Kernel, "K8sLRPTests", func() {
	var (
		kubectl        *helpers.Kubectl
		ciliumFilename string
	)

	BeforeAll(func() {
		kubectl = helpers.CreateKubectl(helpers.K8s1VMName(), logger)
		ciliumFilename = helpers.TimestampFilename("cilium.yaml")
	})

	JustAfterEach(func() {
		kubectl.ValidateNoErrorsInLogs(CurrentGinkgoTestDescription().Duration)
	})

	AfterEach(func() {
		ExpectAllPodsTerminated(kubectl)
	})

	AfterAll(func() {
		UninstallCiliumFromManifest(kubectl, ciliumFilename)
		kubectl.CloseSSHClient()
	})

	SkipContextIf(func() bool { return !helpers.RunsOn419OrLaterKernel() }, "Checks local redirect policy", func() {
		const (
			lrpServiceName = "lrp-demo-service"
			be1Name        = "k8s1-backend"
			be2Name        = "k8s2-backend"
			feFilter       = "role=frontend"
			beFilter       = "role=backend"
		)

		var (
			deploymentYAML string
			lrpSvcYAML     string
			svcIP          string
			curl4TCP       string
			curl4UDP       string
			curl4in6TCP    string
			curl4in6UDP    string
		)

		BeforeAll(func() {
			DeployCiliumOptionsAndDNS(kubectl, ciliumFilename, map[string]string{
				"localRedirectPolicy": "true",
			})
			deploymentYAML = helpers.ManifestGet(kubectl.BasePath(), "lrp-test.yaml")
			lrpSvcYAML = helpers.ManifestGet(kubectl.BasePath(), "lrp-svc.yaml")
			res := kubectl.ApplyDefault(deploymentYAML)
			res.ExpectSuccess("Unable to apply %s", deploymentYAML)
			for _, pod := range []string{feFilter, beFilter} {
				err := kubectl.WaitforPods(helpers.DefaultNamespace, fmt.Sprintf("-l %s", pod), helpers.HelperTimeout)
				Expect(err).Should(BeNil())
			}
			clusterIP, _, err := kubectl.GetServiceHostPort(helpers.DefaultNamespace, lrpServiceName)
			svcIP = clusterIP
			Expect(err).To(BeNil(), "Cannot get svc IP")

			http4SVCURL := getHTTPLink(svcIP, 80)
			tftp4SVCURL := getTFTPLink(svcIP, 69)
			http4in6SVCURL := getHTTPLink("::ffff:"+svcIP, 80)
			tftp4in6SVCURL := getTFTPLink("::ffff:"+svcIP, 69)

			curl4TCP = helpers.CurlFailNoStats(http4SVCURL)
			curl4UDP = helpers.CurlFailNoStats(tftp4SVCURL)
			curl4in6TCP = helpers.CurlFailNoStats(http4in6SVCURL)
			curl4in6UDP = helpers.CurlFailNoStats(tftp4in6SVCURL)
		})

		AfterAll(func() {
			_ = kubectl.Delete(deploymentYAML)
		})

		It("LRP connectivity", func() {
			type lrpTestCase struct {
				selector string
				cmd      string
				want     string
				notWant  string
			}

			// Basic sanity check
			ciliumPods, err := kubectl.GetCiliumPods()
			Expect(err).To(BeNil(), "Cannot get cilium pods")
			for _, pod := range ciliumPods {
				service := kubectl.CiliumExecMustSucceed(context.TODO(), pod, fmt.Sprintf("cilium service list | grep \" %s:\"", svcIP), "Cannot retrieve services on cilium pod")
				service.ExpectContains("LocalRedirect", "LocalRedirect is not present in the cilium service list")
			}

			By("Checking traffic goes to local backend")
			testCases := []lrpTestCase{
				{
					selector: "id=app1",
					cmd:      curl4TCP,
					// Expects to see local backend name in returned Hostname field
					want: be1Name,
					// Expects never to see remote backend name in returned Hostname field
					notWant: be2Name,
				},
				{
					selector: "id=app2",
					cmd:      curl4TCP,
					want:     be2Name,
					notWant:  be1Name,
				},
				{
					selector: "id=app1",
					cmd:      curl4UDP,
					want:     be1Name,
					notWant:  be2Name,
				},
				{
					selector: "id=app2",
					cmd:      curl4UDP,
					want:     be2Name,
					notWant:  be1Name,
				},
				{
					selector: "id=app1",
					cmd:      curl4in6TCP,
					want:     be1Name,
					notWant:  be2Name,
				},
				{
					selector: "id=app2",
					cmd:      curl4in6TCP,
					want:     be2Name,
					notWant:  be1Name,
				},
				{
					selector: "id=app1",
					cmd:      curl4in6UDP,
					want:     be1Name,
					notWant:  be2Name,
				},
				{
					selector: "id=app2",
					cmd:      curl4in6UDP,
					want:     be2Name,
					notWant:  be1Name,
				},
			}

			var wg sync.WaitGroup
			for _, testCase := range testCases {
				wg.Add(1)
				go func(tc lrpTestCase) {
					defer GinkgoRecover()
					defer wg.Done()
					Consistently(func() bool {
						pods, err := kubectl.GetPodNames(helpers.DefaultNamespace, tc.selector)
						Expect(err).Should(BeNil(), "cannot retrieve pod names by filter %q", tc.selector)
						Expect(len(pods)).Should(BeNumerically(">", 0), "no pod exists by filter %q", tc.selector)
						ret := true
						for _, pod := range pods {
							res := kubectl.ExecPodCmd(helpers.DefaultNamespace, pod, tc.cmd)
							Expect(err).To(BeNil(), "%s failed in %s pod", tc.cmd, pod)
							ret = ret && strings.Contains(res.Stdout(), tc.want) && !strings.Contains(res.Stdout(), tc.notWant)
						}
						return ret
					}, 30*time.Second, 1*time.Second).Should(BeTrue(), "assertion fails for test case: %v", tc)
				}(testCase)
			}
			wg.Wait()
		})

		It("LRP restores service when removed", func() {
			type lrpTestCase struct {
				selector string
				cmd      string
				pod      string
			}

			_ = kubectl.Delete(lrpSvcYAML)
			// Basic sanity check
			ciliumPods, err := kubectl.GetCiliumPods()
			Expect(err).To(BeNil(), "Cannot get cilium pods")
			for _, pod := range ciliumPods {
				service := kubectl.CiliumExecMustSucceed(context.TODO(), pod, fmt.Sprintf("cilium service list | grep \" %s:\"", svcIP), "Cannot retrieve services on cilium pod")
				service.ExpectContains("ClusterIP", "Original service is not present in the cilium service list")
			}

			By("Checking traffic goes to both backends")
			testCases := []lrpTestCase{
				{
					selector: "id=app1",
					cmd:      curl4TCP,
				},
				{
					selector: "id=app2",
					cmd:      curl4TCP,
				},
				{
					selector: "id=app1",
					cmd:      curl4UDP,
				},
				{
					selector: "id=app2",
					cmd:      curl4UDP,
				},
			}

			var wg sync.WaitGroup
			for _, tc := range testCases {
				pods, err := kubectl.GetPodNames(helpers.DefaultNamespace, tc.selector)
				Expect(err).Should(BeNil(), "cannot retrieve pod names by filter %q", tc.selector)
				Expect(len(pods)).Should(BeNumerically(">", 0), "no pod exists by filter %q", tc.selector)
				for _, pod := range pods {
					wg.Add(1)
					go func(tc lrpTestCase, pod string) {
						defer GinkgoRecover()
						defer wg.Done()
						want := []string{be1Name, be2Name}
						be1Found := false
						be2Found := false
						Eventually(func() bool {
							res := kubectl.ExecPodCmd(helpers.DefaultNamespace, pod, tc.cmd)
							ExpectWithOffset(1, res).Should(helpers.CMDSuccess(),
								"%s failed in %s pod", tc.cmd, pod)
							be1Found = be1Found || strings.Contains(res.Stdout(), want[0])
							be2Found = be2Found || strings.Contains(res.Stdout(), want[1])
							return be1Found && be2Found
						}, 30*time.Second, 1*time.Second).Should(BeTrue(), "assertion fails for test case: %v", tc)
					}(tc, pod)
				}
			}
			wg.Wait()
		})
	})

})

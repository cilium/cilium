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
	"fmt"

	. "github.com/cilium/cilium/test/ginkgo-ext"
	"github.com/cilium/cilium/test/helpers"

	. "github.com/onsi/gomega"
)

var _ = Describe("K8sHealthTest", func() {

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
		ExpectETCDOperatorReady(kubectl)
	})

	AfterFailed(func() {
		kubectl.CiliumReport(helpers.KubeSystemNamespace,
			"cilium endpoint list")
	})

	JustAfterEach(func() {
		kubectl.ValidateNoErrorsOnLogs(CurrentGinkgoTestDescription().Duration)
	})

	AfterEach(func() {
		ExpectAllPodsTerminated(kubectl)
	})

	getCilium := func(node string) (pod, ip string) {
		pod, err := kubectl.GetCiliumPodOnNode(helpers.KubeSystemNamespace, node)
		Expect(err).Should(BeNil())

		res, err := kubectl.Get(
			helpers.KubeSystemNamespace,
			fmt.Sprintf("pod %s", pod)).Filter("{.status.podIP}")
		Expect(err).Should(BeNil())
		ip = res.String()

		return pod, ip
	}

	checkIP := func(pod, ip string) {
		jsonpath := fmt.Sprintf("{.cluster.nodes[*].primary-address.*}")
		ciliumCmd := fmt.Sprintf("cilium status -o jsonpath='%s'", jsonpath)

		err := kubectl.CiliumExecUntilMatch(pod, ciliumCmd, ip)
		ExpectWithOffset(1, err).NotTo(HaveOccurred(), "Never saw cilium-health ip %s in pod %s", ip, pod)
	}

	It("checks cilium-health status between nodes", func() {
		cilium1, cilium1IP := getCilium(helpers.K8s1)
		cilium2, cilium2IP := getCilium(helpers.K8s2)

		By("checking that cilium API exposes health instances")
		checkIP(cilium1, cilium1IP)
		checkIP(cilium1, cilium2IP)
		checkIP(cilium2, cilium1IP)
		checkIP(cilium2, cilium2IP)

		By("checking that `cilium-health --probe` succeeds")
		healthCmd := fmt.Sprintf("cilium-health status --probe -o json")
		status := kubectl.CiliumExec(cilium1, healthCmd)
		Expect(status.Output()).ShouldNot(ContainSubstring("error"))
		status.ExpectSuccess()

		apiPaths := []string{
			"endpoint.icmp",
			"endpoint.http",
			"host.primary-address.icmp",
			"host.primary-address.http",
		}
		for node := 0; node <= 1; node++ {
			healthCmd := "cilium-health status -o json"
			status := kubectl.CiliumExec(cilium1, healthCmd)
			status.ExpectSuccess("Cannot retrieve health status")
			for _, path := range apiPaths {
				filter := fmt.Sprintf("{.nodes[%d].%s.status}", node, path)
				By("checking API response for %q", filter)
				data, err := status.Filter(filter)
				Expect(err).To(BeNil(), "cannot retrieve filter %q from health output", filter)
				Expect(data.String()).Should(BeEmpty())
			}
		}
	}, 30)
})

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
	"sync"

	. "github.com/cilium/cilium/test/ginkgo-ext"
	"github.com/cilium/cilium/test/helpers"

	. "github.com/onsi/gomega"
	"github.com/sirupsen/logrus"
)

var testName = "K8sValidatedHealthTest"

var _ = Describe(testName, func() {

	var kubectl *helpers.Kubectl
	var logger *logrus.Entry
	var once sync.Once
	initialize := func() {
		logger = log.WithFields(logrus.Fields{"testName": testName})
		logger.Info("Starting")

		kubectl = helpers.CreateKubectl(helpers.K8s1VMName(), logger)
		path := helpers.ManifestGet("cilium_ds.yaml")
		kubectl.Apply(path)
		_, err := kubectl.WaitforPods(helpers.KubeSystemNamespace, "-l k8s-app=cilium", 600)
		Expect(err).Should(BeNil())
	}

	BeforeEach(func() {
		once.Do(initialize)
	})

	AfterFailed(func() {
		kubectl.CiliumReport(helpers.KubeSystemNamespace,
			"cilium service list",
			"cilium endpoint list",
			"cilium policy get")
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

		By(fmt.Sprintf("checking that cilium API exposes health instances"))
		checkIP(cilium1, cilium1IP)
		checkIP(cilium1, cilium2IP)
		checkIP(cilium2, cilium1IP)
		checkIP(cilium2, cilium2IP)

		By(fmt.Sprintf("checking that `cilium-health --probe` succeeds"))
		healthCmd := fmt.Sprintf("cilium-health status --probe -o json")
		status := kubectl.CiliumExec(cilium1, healthCmd)
		Expect(status.Output()).ShouldNot(ContainSubstring("error"))
		status.ExpectSuccess()

		apiPaths := []string{
			"endpoint.icmp",
			"endpoint.http",
			"host.\"primary-address\".icmp",
			"host.\"primary-address\".http",
		}
		for node := 0; node <= 1; node++ {
			for _, path := range apiPaths {
				jqArg := fmt.Sprintf(".nodes[%d].%s.status", node, path)
				By(fmt.Sprintf("checking API response for '%s'", jqArg))
				healthCmd := fmt.Sprintf("cilium-health status -o json | jq '%s'", jqArg)
				status := kubectl.CiliumExec(cilium1, healthCmd)
				Expect(status.Output().String()).Should(ContainSubstring("null"))
				status.ExpectSuccess()
			}
		}
	}, 30)
})

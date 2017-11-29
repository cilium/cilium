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

	"github.com/cilium/cilium/test/helpers"
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	"github.com/sirupsen/logrus"
)

var _ = Describe("K8sPolicyTest", func() {

	var demoPath string
	var initialized bool
	var kubectl *helpers.Kubectl
	var l3Policy, l7Policy string
	var logger *logrus.Entry
	var path string
	var podFilter string

	initialize := func() {
		if initialized == true {
			return
		}

		logger = log.WithFields(logrus.Fields{"testName": "K8sPolicyTest"})
		logger.Info("Starting")
		kubectl = helpers.CreateKubectl(helpers.K8s1VMName(), logger)
		podFilter = "k8s:zgroup=testapp"

		//Manifest paths
		demoPath = fmt.Sprintf("%s/demo.yaml", kubectl.ManifestsPath())
		l3Policy = fmt.Sprintf("%s/l3_l4_policy.yaml", kubectl.ManifestsPath())
		l7Policy = fmt.Sprintf("%s/l7_policy.yaml", kubectl.ManifestsPath())

		path = fmt.Sprintf("%s/cilium_ds.yaml", kubectl.ManifestsPath())
		kubectl.Apply(path)
		status, err := kubectl.WaitforPods(helpers.KubeSystemNamespace, "-l k8s-app=cilium", 300)
		Expect(status).Should(BeTrue())
		Expect(err).Should(BeNil())
		initialized = true
	}

	BeforeEach(func() {
		initialize()
		kubectl.Apply(demoPath)
		_, err := kubectl.WaitforPods(helpers.DefaultNamespace, "-l zgroup=testapp", 300)
		Expect(err).Should(BeNil())
	})

	AfterEach(func() {
		if CurrentGinkgoTestDescription().Failed {
			ciliumPod, _ := kubectl.GetCiliumPodOnNode(helpers.KubeSystemNamespace, helpers.K8s1)
			kubectl.CiliumReport(helpers.KubeSystemNamespace, ciliumPod, []string{
				"cilium bpf tunnel list",
				"cilium endpoint list"})
		}

		kubectl.Delete(demoPath)
		// TO make sure that are not in place
		kubectl.Delete(l3Policy)
		kubectl.Delete(l7Policy)
	})

	waitUntilEndpointUpdates := func(pod string, eps map[string]int64, min int) error {
		body := func() bool {
			updated := 0
			newEps := kubectl.CiliumEndpointPolicyVersion(pod)
			for k, v := range newEps {
				if eps[k] < v {
					logger.Infof("Endpoint %s had version %d now %d", k, eps[k], v)
					updated++
				}
			}
			return updated >= min
		}
		err := helpers.WithTimeout(body, "No new version applied", &helpers.TimeoutConfig{Timeout: 100})
		return err
	}

	getAppPods := func() map[string]string {
		appPods := make(map[string]string)
		apps := []string{helpers.App1, helpers.App2, helpers.App3}
		for _, v := range apps {
			res, err := kubectl.GetPodNames(helpers.DefaultNamespace, fmt.Sprintf("id=%s", v))
			Expect(err).Should(BeNil())
			appPods[v] = res[0]
			logger.Infof("PolicyRulesTest: pod=%q assigned to %q", res[0], v)
		}
		return appPods
	}

	It("PolicyEnforcement Changes", func() {
		//This is a small test that check that everything is working in k8s. Full monkey testing
		// is in runtime/Policies
		ciliumPod, err := kubectl.GetCiliumPodOnNode(helpers.KubeSystemNamespace, helpers.K8s1)
		Expect(err).Should(BeNil())

		status := kubectl.CiliumExec(ciliumPod, fmt.Sprintf("cilium config %s=%s", helpers.PolicyEnforcement, helpers.PolicyEnforcementDefault))
		status.ExpectSuccess()
		helpers.Sleep(5)
		kubectl.CiliumEndpointWait(ciliumPod)

		epsStatus := helpers.WithTimeout(func() bool {
			endpoints, err := kubectl.CiliumEndpointsListByLabel(ciliumPod, podFilter)
			if err != nil {
				return false
			}
			return endpoints.AreReady()
		}, "Could not get endpoints", &helpers.TimeoutConfig{Timeout: 100})
		Expect(epsStatus).Should(BeNil())

		endpoints, err := kubectl.CiliumEndpointsListByLabel(ciliumPod, podFilter)
		Expect(err).Should(BeNil())
		Expect(endpoints.AreReady()).Should(BeTrue())
		policyStatus := endpoints.GetPolicyStatus()
		Expect(policyStatus[helpers.Enabled]).Should(Equal(0))
		Expect(policyStatus[helpers.Disabled]).Should(Equal(4))

		By("Set PolicyEnforcement to always")

		status = kubectl.CiliumExec(ciliumPod, fmt.Sprintf("cilium config %s=%s", helpers.PolicyEnforcement, helpers.PolicyEnforcementAlways))
		status.ExpectSuccess()

		kubectl.CiliumEndpointWait(ciliumPod)

		endpoints, err = kubectl.CiliumEndpointsListByLabel(ciliumPod, podFilter)
		Expect(err).Should(BeNil())
		Expect(endpoints.AreReady()).Should(BeTrue())
		policyStatus = endpoints.GetPolicyStatus()
		Expect(policyStatus[helpers.Enabled]).Should(Equal(4))
		Expect(policyStatus[helpers.Disabled]).Should(Equal(0))

		By("Return PolicyEnforcement to default")

		status = kubectl.CiliumExec(ciliumPod, fmt.Sprintf("cilium config %s=%s", helpers.PolicyEnforcement, helpers.PolicyEnforcementDefault))
		status.ExpectSuccess()

		kubectl.CiliumEndpointWait(ciliumPod)

		endpoints, err = kubectl.CiliumEndpointsListByLabel(ciliumPod, podFilter)
		Expect(err).Should(BeNil())
		Expect(endpoints.AreReady()).Should(BeTrue())
		policyStatus = endpoints.GetPolicyStatus()
		Expect(policyStatus[helpers.Enabled]).Should(Equal(0))
		Expect(policyStatus[helpers.Disabled]).Should(Equal(4))
	}, 500)

	It("Policies", func() {
		appPods := getAppPods()
		clusterIP, err := kubectl.Get(helpers.DefaultNamespace, "svc").Filter(
			"{.items[?(@.metadata.name == \"app1-service\")].spec.clusterIP}")
		logger.Infof("PolicyRulesTest: cluster service ip '%s'", clusterIP)
		Expect(err).Should(BeNil())

		ciliumPod, err := kubectl.GetCiliumPodOnNode(helpers.KubeSystemNamespace, helpers.K8s1)
		Expect(err).Should(BeNil())

		status := kubectl.CiliumExec(ciliumPod, fmt.Sprintf("cilium config %s=%s", helpers.PolicyEnforcement, helpers.PolicyEnforcementDefault))
		status.ExpectSuccess()

		kubectl.CiliumEndpointWait(ciliumPod)

		By("Testing L3/L4 rules")

		eps := kubectl.CiliumEndpointPolicyVersion(ciliumPod)
		_, err = kubectl.CiliumImportPolicy(helpers.KubeSystemNamespace, l3Policy, 300)
		Expect(err).Should(BeNil())

		err = waitUntilEndpointUpdates(ciliumPod, eps, 4)
		Expect(err).Should(BeNil())
		epsStatus := helpers.WithTimeout(func() bool {
			endpoints, err := kubectl.CiliumEndpointsListByLabel(ciliumPod, podFilter)
			if err != nil {
				return false
			}
			return endpoints.AreReady()
		}, "could not get endpoints", &helpers.TimeoutConfig{Timeout: 100})

		Expect(epsStatus).Should(BeNil())
		appPods = getAppPods()

		endpoints, err := kubectl.CiliumEndpointsListByLabel(ciliumPod, podFilter)
		policyStatus := endpoints.GetPolicyStatus()
		Expect(policyStatus[helpers.Enabled]).Should(Equal(2))
		Expect(policyStatus[helpers.Disabled]).Should(Equal(2))

		trace := kubectl.CiliumExec(ciliumPod, fmt.Sprintf(
			"cilium policy trace --src-k8s-pod default:%s --dst-k8s-pod default:%s --dport 80",
			appPods[helpers.App2], appPods[helpers.App1]))
		trace.ExpectSuccess(trace.CombineOutput().String())
		Expect(trace.Output().String()).Should(ContainSubstring("Final verdict: ALLOWED"))

		trace = kubectl.CiliumExec(ciliumPod, fmt.Sprintf(
			"cilium policy trace --src-k8s-pod default:%s --dst-k8s-pod default:%s",
			appPods[helpers.App3], appPods[helpers.App1]))
		trace.ExpectSuccess(trace.CombineOutput().String())
		Expect(trace.Output().String()).Should(ContainSubstring("Final verdict: DENIED"))

		_, err = kubectl.Exec(
			helpers.DefaultNamespace, appPods[helpers.App2], fmt.Sprintf("curl http://%s/public", clusterIP))
		Expect(err).Should(BeNil())

		_, err = kubectl.Exec(
			helpers.DefaultNamespace, appPods[helpers.App3], fmt.Sprintf("curl --fail -s http://%s/public", clusterIP))
		Expect(err).Should(HaveOccurred())

		eps = kubectl.CiliumEndpointPolicyVersion(ciliumPod)
		status = kubectl.Delete(l3Policy)
		status.ExpectSuccess()
		kubectl.CiliumEndpointWait(ciliumPod)

		//Only 1 endpoint is affected by L7 rule
		err = waitUntilEndpointUpdates(ciliumPod, eps, 4)
		Expect(err).Should(BeNil())

		By("Testing L7 Policy")
		//All Monkey testing in this section is on runtime

		eps = kubectl.CiliumEndpointPolicyVersion(ciliumPod)
		_, err = kubectl.CiliumImportPolicy(helpers.KubeSystemNamespace, l7Policy, 300)
		Expect(err).Should(BeNil())
		err = waitUntilEndpointUpdates(ciliumPod, eps, 4)
		Expect(err).Should(BeNil())

		appPods = getAppPods()

		_, err = kubectl.Exec(
			helpers.DefaultNamespace, appPods[helpers.App2], fmt.Sprintf("curl http://%s/public", clusterIP))
		Expect(err).Should(BeNil())

		msg, err := kubectl.Exec(
			helpers.DefaultNamespace, appPods[helpers.App2], fmt.Sprintf("curl --fail -s http://%s/private", clusterIP))
		Expect(err).Should(HaveOccurred(), msg)

		_, err = kubectl.Exec(
			helpers.DefaultNamespace, appPods[helpers.App3], fmt.Sprintf("curl --fail -s http://%s/public", clusterIP))
		Expect(err).Should(HaveOccurred())

		msg, err = kubectl.Exec(
			helpers.DefaultNamespace, appPods[helpers.App3], fmt.Sprintf("curl --fail -s http://%s/private", clusterIP))
		Expect(err).Should(HaveOccurred(), msg)

		eps = kubectl.CiliumEndpointPolicyVersion(ciliumPod)
		status = kubectl.Delete(l7Policy)
		status.ExpectSuccess()

		//Only 1 endpoint is affected by L7 rule
		err = waitUntilEndpointUpdates(ciliumPod, eps, 4)
		Expect(err).Should(BeNil())

		_, err = kubectl.Exec(
			helpers.DefaultNamespace, appPods[helpers.App3], fmt.Sprintf("curl --fail -s http://%s/public", clusterIP))
		Expect(err).Should(BeNil())
	}, 500)

})

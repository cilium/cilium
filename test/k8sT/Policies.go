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
	log "github.com/sirupsen/logrus"
)

var _ = Describe("K8sPolicyTest", func() {

	var demoPath string
	var initialized bool
	var kubectl *helpers.Kubectl
	var l3Policy, l7Policy string
	var logger *log.Entry
	var path string
	var podFilter string

	initialize := func() {
		if initialized == true {
			return
		}

		logger = log.WithFields(log.Fields{"testName": "K8sPolicyTest"})
		logger.Info("Starting")
		kubectl = helpers.CreateKubectl("k8s1", logger)
		podFilter = "k8s:zgroup=testapp"

		//Manifest paths
		demoPath = fmt.Sprintf("%s/demo.yaml", kubectl.ManifestsPath())
		l3Policy = fmt.Sprintf("%s/l3_l4_policy.yaml", kubectl.ManifestsPath())
		l7Policy = fmt.Sprintf("%s/l7_policy.yaml", kubectl.ManifestsPath())

		path = fmt.Sprintf("%s/cilium_ds.yaml", kubectl.ManifestsPath())
		kubectl.Apply(path)
		status, err := kubectl.WaitforPods("kube-system", "-l k8s-app=cilium", 300)
		Expect(status).Should(BeTrue())
		Expect(err).Should(BeNil())
		initialized = true
	}

	BeforeEach(func() {
		initialize()
		// kubectl.CiliumPolicyDeleteAll("kube-system")
		kubectl.Apply(demoPath)
		_, err := kubectl.WaitforPods("default", "-l zgroup=testapp", 300)
		Expect(err).Should(BeNil())
	})

	AfterEach(func() {
		if CurrentGinkgoTestDescription().Failed {
			ciliumPod, _ := kubectl.GetCiliumPodOnNode("kube-system", "k8s1")
			kubectl.CiliumReport("kube-system", ciliumPod, []string{
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
		apps := []string{"app1", "app2", "app3"}
		for _, v := range apps {
			res, err := kubectl.GetPodNames("default", fmt.Sprintf("id=%s", v))
			Expect(err).Should(BeNil())
			appPods[v] = res[0]
			logger.Infof("PolicyRulesTest: pod='%s' assigned to '%s'", res[0], v)
		}
		return appPods
	}

	It("PolicyEnforcement Changes", func() {
		//This is a small test that check that everything is working in k8s. Full monkey testing
		// is in runtime/Policies
		ciliumPod, err := kubectl.GetCiliumPodOnNode("kube-system", "k8s1")
		Expect(err).Should(BeNil())

		status := kubectl.CiliumExec(ciliumPod, "cilium config PolicyEnforcement=default")
		Expect(status.WasSuccessful()).Should(BeTrue())
		helpers.Sleep(5)
		kubectl.CiliumEndpointWait(ciliumPod)

		epsStatus := helpers.WithTimeout(func() bool {
			endpoints, err := kubectl.CiliumEndpointsListByTag(ciliumPod, podFilter)
			if err != nil {
				return false
			}
			return endpoints.AreReady()
		}, "Could not get endpoints", &helpers.TimeoutConfig{Timeout: 100})
		Expect(epsStatus).Should(BeNil())

		endpoints, err := kubectl.CiliumEndpointsListByTag(ciliumPod, podFilter)
		Expect(err).Should(BeNil())
		Expect(endpoints.AreReady()).Should(BeTrue())
		policyStatus := endpoints.GetPolicyStatus()
		Expect(policyStatus["enabled"]).Should(Equal(0))
		Expect(policyStatus["disabled"]).Should(Equal(4))

		By("Set PolicyEnforcement to always")

		status = kubectl.CiliumExec(ciliumPod, "cilium config PolicyEnforcement=always")
		Expect(status.WasSuccessful()).Should(BeTrue())
		kubectl.CiliumEndpointWait(ciliumPod)

		endpoints, err = kubectl.CiliumEndpointsListByTag(ciliumPod, podFilter)
		Expect(err).Should(BeNil())
		Expect(endpoints.AreReady()).Should(BeTrue())
		policyStatus = endpoints.GetPolicyStatus()
		Expect(policyStatus["enabled"]).Should(Equal(4))
		Expect(policyStatus["disabled"]).Should(Equal(0))

		By("Return PolicyEnforcement to default")
		status = kubectl.CiliumExec(ciliumPod, "cilium config PolicyEnforcement=default")
		Expect(status.WasSuccessful()).Should(BeTrue())
		kubectl.CiliumEndpointWait(ciliumPod)

		endpoints, err = kubectl.CiliumEndpointsListByTag(ciliumPod, podFilter)
		Expect(err).Should(BeNil())
		Expect(endpoints.AreReady()).Should(BeTrue())
		policyStatus = endpoints.GetPolicyStatus()
		Expect(policyStatus["enabled"]).Should(Equal(0))
		Expect(policyStatus["disabled"]).Should(Equal(4))
	}, 500)

	It("Policies", func() {
		appPods := getAppPods()
		clusterIP, err := kubectl.Get("default", "svc").Filter(
			"{.items[?(@.metadata.name == \"app1-service\")].spec.clusterIP}")
		logger.Infof("PolicyRulesTest: cluster service ip '%s'", clusterIP)
		Expect(err).Should(BeNil())

		ciliumPod, err := kubectl.GetCiliumPodOnNode("kube-system", "k8s1")
		Expect(err).Should(BeNil())

		status := kubectl.CiliumExec(ciliumPod, "cilium config PolicyEnforcement=default")
		Expect(status.WasSuccessful()).Should(BeTrue())
		kubectl.CiliumEndpointWait(ciliumPod)

		By("Testing L3/L4 rules")

		eps := kubectl.CiliumEndpointPolicyVersion(ciliumPod)
		_, err = kubectl.CiliumImportPolicy("kube-system", l3Policy, 300)
		Expect(err).Should(BeNil())

		err = waitUntilEndpointUpdates(ciliumPod, eps, 4)
		Expect(err).Should(BeNil())
		epsStatus := helpers.WithTimeout(func() bool {
			endpoints, err := kubectl.CiliumEndpointsListByTag(ciliumPod, podFilter)
			if err != nil {
				return false
			}
			return endpoints.AreReady()
		}, "Could not get endpoints", &helpers.TimeoutConfig{Timeout: 100})

		Expect(epsStatus).Should(BeNil())
		appPods = getAppPods()

		endpoints, err := kubectl.CiliumEndpointsListByTag(ciliumPod, podFilter)
		policyStatus := endpoints.GetPolicyStatus()
		Expect(policyStatus["enabled"]).Should(Equal(2))
		Expect(policyStatus["disabled"]).Should(Equal(2))

		trace := kubectl.CiliumExec(ciliumPod, fmt.Sprintf(
			"cilium policy trace --src-k8s-pod default:%s --dst-k8s-pod default:%s --dport 80",
			appPods["app2"], appPods["app1"]))

		Expect(trace.WasSuccessful()).Should(BeTrue(), trace.Output().String())
		Expect(trace.Output().String()).Should(ContainSubstring("Final verdict: ALLOWED"))

		trace = kubectl.CiliumExec(ciliumPod, fmt.Sprintf(
			"cilium policy trace --src-k8s-pod default:%s --dst-k8s-pod default:%s",
			appPods["app3"], appPods["app1"]))
		Expect(trace.WasSuccessful()).Should(BeTrue())
		Expect(trace.Output().String()).Should(ContainSubstring("Final verdict: DENIED"))

		_, err = kubectl.Exec(
			"default", appPods["app2"], fmt.Sprintf("curl http://%s/public", clusterIP))
		Expect(err).Should(BeNil())

		_, err = kubectl.Exec(
			"default", appPods["app3"], fmt.Sprintf("curl --fail -s http://%s/public", clusterIP))
		Expect(err).Should(HaveOccurred())

		eps = kubectl.CiliumEndpointPolicyVersion(ciliumPod)
		status = kubectl.Delete(l3Policy)
		Expect(status.WasSuccessful()).Should(BeTrue())
		kubectl.CiliumEndpointWait(ciliumPod)

		//Only 1 endpoint is affected by L7 rule
		err = waitUntilEndpointUpdates(ciliumPod, eps, 4)
		Expect(err).Should(BeNil())

		By("Testing L7 Policy")
		//All Monkey testing in this section is on runtime

		eps = kubectl.CiliumEndpointPolicyVersion(ciliumPod)
		_, err = kubectl.CiliumImportPolicy("kube-system", l7Policy, 300)
		Expect(err).Should(BeNil())
		err = waitUntilEndpointUpdates(ciliumPod, eps, 4)
		Expect(err).Should(BeNil())

		appPods = getAppPods()

		_, err = kubectl.Exec(
			"default", appPods["app2"], fmt.Sprintf("curl http://%s/public", clusterIP))
		Expect(err).Should(BeNil())

		msg, err := kubectl.Exec(
			"default", appPods["app2"], fmt.Sprintf("curl --fail -s http://%s/private", clusterIP))
		Expect(err).Should(HaveOccurred(), msg)

		_, err = kubectl.Exec(
			"default", appPods["app3"], fmt.Sprintf("curl -s --fail http://%s/public", clusterIP))
		Expect(err).Should(HaveOccurred())

		msg, err = kubectl.Exec(
			"default", appPods["app3"], fmt.Sprintf("curl --fail -s http://%s/private", clusterIP))
		Expect(err).Should(HaveOccurred(), msg)

		eps = kubectl.CiliumEndpointPolicyVersion(ciliumPod)
		status = kubectl.Delete(l7Policy)
		Expect(status.WasSuccessful()).Should(BeTrue())

		//Only 1 endpoint is affected by L7 rule
		err = waitUntilEndpointUpdates(ciliumPod, eps, 4)
		Expect(err).Should(BeNil())

		_, err = kubectl.Exec(
			"default", appPods["app3"], fmt.Sprintf("curl -s --fail http://%s/public", clusterIP))
		Expect(err).Should(BeNil())
	}, 500)

})

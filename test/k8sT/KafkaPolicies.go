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

	"github.com/cilium/cilium/api/v1/models"
	"github.com/cilium/cilium/test/helpers"
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	"github.com/sirupsen/logrus"
)

var _ = Describe("K8sKafkaPolicyTest", func() {

	var demoPath string
	var once sync.Once
	var kubectl *helpers.Kubectl
	var l7Policy string
	var logger *logrus.Entry
	var path string
	var podFilter string

	initialize := func() {
		logger = log.WithFields(logrus.Fields{"testName": "K8sKafkaPolicyTest"})
		logger.Info("Starting")
		kubectl = helpers.CreateKubectl(helpers.K8s1VMName(), logger)
		podFilter = "k8s:zgroup=kafkaTestApp"

		helpers.Sleep(5)

		//Manifest paths
		demoPath = kubectl.ManifestGet("kafka-sw-app.yaml")
		l7Policy = kubectl.ManifestGet("kafka-sw-security-policy.yaml")

		path = kubectl.ManifestGet("cilium_ds.yaml")
		kubectl.Apply(path)
		status, err := kubectl.WaitforPods(helpers.KubeSystemNamespace, "-l k8s-app=cilium", 300)
		Expect(status).Should(BeTrue())
		Expect(err).Should(BeNil())
		err = kubectl.WaitKubeDNS()
		Expect(err).Should(BeNil())
	}

	BeforeEach(func() {
		once.Do(initialize)
		kubectl.Apply(demoPath)
		_, err := kubectl.WaitforPods(helpers.DefaultNamespace, "-l zgroup=kafkaTestApp", 300)
		Expect(err).Should(BeNil())
	})

	AfterEach(func() {
		if CurrentGinkgoTestDescription().Failed {
			ciliumPod, _ := kubectl.GetCiliumPodOnNode(helpers.KubeSystemNamespace, helpers.K8s1)
			kubectl.CiliumReport(helpers.KubeSystemNamespace, ciliumPod, []string{
				"cilium bpf tunnel list",
				"cilium endpoint list",
				"cilium service list"})
		}

		kubectl.Delete(demoPath)

	})

	waitUntilEndpointUpdates := func(pod string, eps map[string]int64, min int) error {
		body := func() bool {
			updated := 0
			newEps := kubectl.CiliumEndpointPolicyVersion(pod)
			for k, v := range newEps {
				if eps[k] < v {
					logger.Infof("Endpoint %s had version %d now %d updated : %d", k, eps[k], v, updated)
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
		apps := []string{helpers.KafkaApp, helpers.Zookeeper, helpers.Backup, helpers.EmpireHq, helpers.Outpost}
		for _, v := range apps {
			fmt.Printf("getting pod name of app: %s\n", v)
			res, err := kubectl.GetPodNames(helpers.DefaultNamespace, fmt.Sprintf("app=%s", v))
			Expect(err).Should(BeNil())
			Expect(res).Should(Not(BeNil()))
			fmt.Printf("res output: %q\n", res)
			appPods[v] = res[0]
			logger.Infof("KafkaPolicyRulesTest: pod=%q assigned to %q", res[0], v)
		}
		return appPods
	}

	It("KafkaPolicies", func() {
		clusterIP, err := kubectl.Get(helpers.DefaultNamespace, "svc").Filter(
			"{.items[?(@.metadata.name == \"kafka-service\")].spec.clusterIP}")
		logger.Infof("PolicyRulesTest: cluster service ip '%s'", clusterIP)
		Expect(err).Should(BeNil())

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

		appPods := getAppPods()
		By("Testing basic kafka setup")

		_, err = kubectl.ExecKafkaPodCmd(
			helpers.DefaultNamespace, appPods[helpers.EmpireHq], fmt.Sprintf("-c \"echo “Happy 40th Birthday to General Tagge” | ./kafka-produce.sh --topic empire-announce\""))
		Expect(err).Should(BeNil())

		_, err = kubectl.ExecKafkaPodCmd(
			helpers.DefaultNamespace, appPods[helpers.Outpost], fmt.Sprintf("-c \"./kafka-consume.sh --topic empire-announce --from-beginning --max-messages 1\""))
		Expect(err).Should(BeNil())

		_, err = kubectl.ExecKafkaPodCmd(
			helpers.DefaultNamespace, appPods[helpers.EmpireHq], fmt.Sprintf("-c \"echo “deathstar reactor design v3” | ./kafka-produce.sh --topic deathstar-plans\""))
		Expect(err).Should(BeNil())

		_, err = kubectl.ExecKafkaPodCmd(
			helpers.DefaultNamespace, appPods[helpers.Outpost], fmt.Sprintf("-c \"./kafka-consume.sh --topic deathstar-plans --from-beginning --max-messages 1\""))
		Expect(err).Should(BeNil())

		_, err = kubectl.ExecKafkaPodCmd(
			helpers.DefaultNamespace, appPods[helpers.Backup], fmt.Sprintf("-c \"echo “Happy 40th Birthday to General Tagge” | ./kafka-produce.sh --topic empire-announce\""))
		Expect(err).Should(BeNil())

		_, err = kubectl.ExecKafkaPodCmd(
			helpers.DefaultNamespace, appPods[helpers.Outpost], fmt.Sprintf("-c \"echo “Vader Booed at Empire Karaoke Party” | ./kafka-produce.sh --topic empire-announce\""))
		Expect(err).Should(BeNil())

		By("Apply L7 kafka policy")
		eps := kubectl.CiliumEndpointPolicyVersion(ciliumPod)
		_, err = kubectl.CiliumPolicyAction(helpers.KubeSystemNamespace, l7Policy, helpers.KubectlApply, 300)
		Expect(err).Should(BeNil())

		err = waitUntilEndpointUpdates(ciliumPod, eps, 6)
		Expect(err).Should(BeNil())
		epsStatus = helpers.WithTimeout(func() bool {
			endpoints, err := kubectl.CiliumEndpointsListByLabel(ciliumPod, podFilter)
			if err != nil {
				return false
			}
			return endpoints.AreReady()
		}, "could not get endpoints", &helpers.TimeoutConfig{Timeout: 100})

		Expect(epsStatus).Should(BeNil())
		endpoints, err = kubectl.CiliumEndpointsListByLabel(ciliumPod, podFilter)
		policyStatus := endpoints.GetPolicyStatus()

		By("Testing Kafka endpoint policy enforcement status")
		Expect(policyStatus[models.EndpointPolicyEnabledNone]).Should(Equal(5))
		// Only the kafka broker app should have ingress policy enabled.
		Expect(policyStatus[models.EndpointPolicyEnabledIngress]).Should(Equal(1))
		Expect(policyStatus[models.EndpointPolicyEnabledEgress]).Should(Equal(0))
		Expect(policyStatus[models.EndpointPolicyEnabledBoth]).Should(Equal(0))

		By("Testing endpoint policy trace status")

		trace := kubectl.CiliumExec(ciliumPod, fmt.Sprintf(
			"cilium policy trace --src-k8s-pod default:%s --dst-k8s-pod default:%s --dport 9092",
			appPods[helpers.Outpost], appPods[helpers.KafkaApp]))
		trace.ExpectSuccess(trace.CombineOutput().String())
		Expect(trace.Output().String()).Should(ContainSubstring("Final verdict: ALLOWED"))

		trace = kubectl.CiliumExec(ciliumPod, fmt.Sprintf(
			"cilium policy trace --src-k8s-pod default:%s --dst-k8s-pod default:%s --dport 9092",
			appPods[helpers.Backup], appPods[helpers.KafkaApp]))
		trace.ExpectSuccess(trace.CombineOutput().String())
		Expect(trace.Output().String()).Should(ContainSubstring("Final verdict: ALLOWED"))

		trace = kubectl.CiliumExec(ciliumPod, fmt.Sprintf(
			"cilium policy trace --src-k8s-pod default:%s --dst-k8s-pod default:%s --dport 9092",
			appPods[helpers.EmpireHq], appPods[helpers.KafkaApp]))
		trace.ExpectSuccess(trace.CombineOutput().String())
		Expect(trace.Output().String()).Should(ContainSubstring("Final verdict: ALLOWED"))

		trace = kubectl.CiliumExec(ciliumPod, fmt.Sprintf(
			"cilium policy trace --src-k8s-pod default:%s --dst-k8s-pod default:%s --dport 80",
			appPods[helpers.EmpireHq], appPods[helpers.KafkaApp]))
		trace.ExpectSuccess(trace.CombineOutput().String())
		Expect(trace.Output().String()).Should(ContainSubstring("Final verdict: DENIED"))

		By("Testing Kafka L7 policy enforcement status")
		_, err = kubectl.ExecKafkaPodCmd(
			helpers.DefaultNamespace, appPods[helpers.EmpireHq], fmt.Sprintf("-c \"echo “Happy 40th Birthday to General Tagge” | ./kafka-produce.sh --topic empire-announce\""))
		Expect(err).Should(BeNil())

		_, err = kubectl.ExecKafkaPodCmd(
			helpers.DefaultNamespace, appPods[helpers.Outpost], fmt.Sprintf("-c \"./kafka-consume.sh --topic empire-announce --from-beginning --max-messages 1\""))
		Expect(err).Should(BeNil())

		_, err = kubectl.ExecKafkaPodCmd(
			helpers.DefaultNamespace, appPods[helpers.EmpireHq], fmt.Sprintf("-c \"echo “deathstar reactor design v3” | ./kafka-produce.sh --topic deathstar-plans\""))
		Expect(err).Should(BeNil())

		_, err = kubectl.ExecKafkaPodCmd(
			helpers.DefaultNamespace, appPods[helpers.Outpost], fmt.Sprintf("-c \"./kafka-consume.sh --topic empire-announce --from-beginning --max-messages 1\""))
		Expect(err).Should(BeNil())

		_, err = kubectl.ExecKafkaPodCmd(
			helpers.DefaultNamespace, appPods[helpers.Backup], fmt.Sprintf("-c \"echo “Happy 40th Birthday to General Tagge” | ./kafka-produce.sh --topic empire-announce\""))
		Expect(err).Should(HaveOccurred())

		_, err = kubectl.ExecKafkaPodCmd(
			helpers.DefaultNamespace, appPods[helpers.Outpost], fmt.Sprintf("-c \"./kafka-consume.sh --topic deathstar-plans --from-beginning --max-messages 1\""))
		Expect(err).Should(HaveOccurred())

		_, err = kubectl.ExecKafkaPodCmd(
			helpers.DefaultNamespace, appPods[helpers.Outpost], fmt.Sprintf("-c \"echo “Vader Booed at Empire Karaoke Party” | ./kafka-produce.sh --topic empire-announce\""))
		Expect(err).Should(HaveOccurred())

		eps = kubectl.CiliumEndpointPolicyVersion(ciliumPod)
		status = kubectl.Delete(l7Policy)
		status.ExpectSuccess()
		kubectl.CiliumEndpointWait(ciliumPod)

		//Only 1 endpoint is affected by L7 rule
		err = waitUntilEndpointUpdates(ciliumPod, eps, 6)
		Expect(err).Should(BeNil())

	}, 500)
})

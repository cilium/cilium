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

var _ = Describe("K8sValidatedKafkaPolicyTest", func() {

	var demoPath string
	var once sync.Once
	var kubectl *helpers.Kubectl
	var l7Policy string
	var logger *logrus.Entry
	var path string
	var podFilter string
	var apps []string
	var prodHqAnnounce string
	var conOutpostAnnoune string
	var prodHqDeathStar string
	var conOutDeathStar string
	var prodBackAnnounce string
	var prodOutAnnounce string


	initialize := func() {
		logger = log.WithFields(logrus.Fields{"testName": "K8sValidatedKafkaPolicyTest"})
		logger.Info("Starting")
		kubectl = helpers.CreateKubectl(helpers.K8s1VMName(), logger)
		podFilter = "k8s:zgroup=kafkaTestApp"

		//Manifest paths
		demoPath = kubectl.ManifestGet("kafka-sw-app.yaml")
		l7Policy = kubectl.ManifestGet("kafka-sw-security-policy.yaml")

		// Kafka GSG app pods
		apps = []string{helpers.KafkaApp, helpers.Zookeeper, helpers.Backup, helpers.EmpireHq, helpers.Outpost}

		// Kafka produce / consume exec commands
		prodHqAnnounce = "-c \"echo “Happy 40th Birthday to General Tagge” | ./kafka-produce.sh --topic empire-announce\""
		conOutpostAnnoune = "-c \"./kafka-consume.sh --topic empire-announce --from-beginning --max-messages 1\""
		prodHqDeathStar = "-c \"echo “deathstar reactor design v3” | ./kafka-produce.sh --topic deathstar-plans\""
		conOutDeathStar = "-c \"./kafka-consume.sh --topic deathstar-plans --from-beginning --max-messages 1\""
		prodBackAnnounce = "-c \"echo “Happy 40th Birthday to General Tagge” | ./kafka-produce.sh --topic empire-announce\""
		prodOutAnnounce = "-c \"echo “Vader Booed at Empire Karaoke Party” | ./kafka-produce.sh --topic empire-announce\""


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
				"cilium service list",
				"cilium policy get"})
		}

		By("Deleting demo path")
		kubectl.Delete(demoPath)
		err := kubectl.WaitCleanAllTerminatingPods()
		Expect(err).To(BeNil(), "Terminating containers are not deleted after timeout")

	})

	It("KafkaPolicies", func() {
		clusterIP, err := kubectl.Get(helpers.DefaultNamespace, "svc").Filter(
			"{.items[?(@.metadata.name == \"kafka-service\")].spec.clusterIP}")
		logger.Infof("KafkaPolicyRulesTest: cluster service ip '%s'", clusterIP)
		Expect(err).Should(BeNil())

		By("Getting Cilium Pods")
		ciliumPod, err := kubectl.GetCiliumPodOnNode(helpers.KubeSystemNamespace, helpers.K8s1)
		Expect(err).Should(BeNil())

		status := kubectl.CiliumExec(ciliumPod, fmt.Sprintf("cilium config %s=%s", helpers.PolicyEnforcement, helpers.PolicyEnforcementDefault))
		status.ExpectSuccess()

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

		appPods := helpers.GetAppPods(apps, helpers.DefaultNamespace, kubectl)
		By("Testing basic Kafka Produce and Consume")

		err = kubectl.ExecKafkaPodCmd(
			helpers.DefaultNamespace, appPods[helpers.EmpireHq], fmt.Sprintf(prodHqAnnounce))
		Expect(err).Should(BeNil())

		err = kubectl.ExecKafkaPodCmd(
			helpers.DefaultNamespace, appPods[helpers.Outpost], fmt.Sprintf(conOutpostAnnoune))
		Expect(err).Should(BeNil())

		err = kubectl.ExecKafkaPodCmd(
			helpers.DefaultNamespace, appPods[helpers.EmpireHq], fmt.Sprintf(prodHqDeathStar))
		Expect(err).Should(BeNil())

		err = kubectl.ExecKafkaPodCmd(
			helpers.DefaultNamespace, appPods[helpers.Outpost], fmt.Sprintf(conOutDeathStar))
		Expect(err).Should(BeNil())

		err = kubectl.ExecKafkaPodCmd(
			helpers.DefaultNamespace, appPods[helpers.Backup], fmt.Sprintf(prodBackAnnounce))
		Expect(err).Should(BeNil())

		err = kubectl.ExecKafkaPodCmd(
			helpers.DefaultNamespace, appPods[helpers.Outpost], fmt.Sprintf(prodOutAnnounce))
		Expect(err).Should(BeNil())

		By("Apply L7 kafka policy")
		eps := kubectl.CiliumEndpointPolicyVersion(ciliumPod)
		_, err = kubectl.CiliumPolicyAction(helpers.KubeSystemNamespace, l7Policy, helpers.KubectlApply, 300)
		Expect(err).Should(BeNil())

		By("Waiting for endpoint updates with L7 policy")
		err = helpers.WaitUntilEndpointUpdates(ciliumPod, eps, 6, kubectl)
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
		err = kubectl.ExecKafkaPodCmd(
			helpers.DefaultNamespace, appPods[helpers.EmpireHq], fmt.Sprintf(prodHqAnnounce))
		Expect(err).Should(BeNil())

		err = kubectl.ExecKafkaPodCmd(
			helpers.DefaultNamespace, appPods[helpers.Outpost], fmt.Sprintf(conOutpostAnnoune))
		Expect(err).Should(BeNil())

		err = kubectl.ExecKafkaPodCmd(
			helpers.DefaultNamespace, appPods[helpers.EmpireHq], fmt.Sprintf(prodHqDeathStar))
		Expect(err).Should(BeNil())

		err = kubectl.ExecKafkaPodCmd(
			helpers.DefaultNamespace, appPods[helpers.Outpost], fmt.Sprintf(conOutpostAnnoune))
		Expect(err).Should(BeNil())

		err = kubectl.ExecKafkaPodCmd(
			helpers.DefaultNamespace, appPods[helpers.Backup], fmt.Sprintf(prodBackAnnounce))
		Expect(err).Should(HaveOccurred())

		err = kubectl.ExecKafkaPodCmd(
			helpers.DefaultNamespace, appPods[helpers.Outpost], fmt.Sprintf(conOutDeathStar))
		Expect(err).Should(HaveOccurred())

		err = kubectl.ExecKafkaPodCmd(
			helpers.DefaultNamespace, appPods[helpers.Outpost], fmt.Sprintf(prodOutAnnounce))
		Expect(err).Should(HaveOccurred())

		eps = kubectl.CiliumEndpointPolicyVersion(ciliumPod)
		By("Deleting L7 policy")
		status = kubectl.Delete(l7Policy)
		status.ExpectSuccess()
		kubectl.CiliumEndpointWait(ciliumPod)

		//Only 1 endpoint is affected by L7 rule
		err = helpers.WaitUntilEndpointUpdates(ciliumPod, eps, 6, kubectl)
		Expect(err).Should(BeNil())

	}, 500)
})

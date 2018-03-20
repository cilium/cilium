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

	// kubectl exec arguments for Kafka produce/consume as per GSG
	var prodHqAnnounce string
	var conOutpostAnnoune string
	var prodHqDeathStar string
	var conOutDeathStar string
	var prodBackAnnounce string
	var prodOutAnnounce string

	// Kafka app pod names
	var kafkaApp string
	var zookApp string
	var backupApp string
	var empireHqApp string
	var outpostApp string

	initialize := func() {
		logger = log.WithFields(logrus.Fields{"testName": "K8sValidatedKafkaPolicyTest"})
		logger.Info("Starting")
		kubectl = helpers.CreateKubectl(helpers.K8s1VMName(), logger)
		podFilter = "k8s:zgroup=kafkaTestApp"

		kafkaApp = "kafka"
		zookApp = "zook"
		backupApp = "empire-backup"
		empireHqApp = "empire-hq"
		outpostApp = "empire-outpost"

		//Manifest paths
		demoPath = kubectl.ManifestGet("kafka-sw-app.yaml")
		l7Policy = kubectl.ManifestGet("kafka-sw-security-policy.yaml")

		// Kafka GSG app pods
		apps = []string{kafkaApp, zookApp, backupApp, empireHqApp, outpostApp}

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
		kubectl.ValidateNoErrorsOnLogs(CurrentGinkgoTestDescription().Duration)
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

		By("Waiting for all Cilium Pods and endpoints to be ready ")
		By("Waiting for node K8s1")
		ciliumPod1, _ := kubectl.WaitCiliumEndpointReady(podFilter, helpers.K8s1)

		By("Waiting for node K8s2")
		kubectl.WaitCiliumEndpointReady(podFilter, helpers.K8s2)

		appPods := helpers.GetAppPods(apps, helpers.DefaultNamespace, kubectl, "app")
		By("Testing basic Kafka Produce and Consume")

		// We need to produce first, since consumer script waits for
		// some messages to be already there by the producer.
		err = kubectl.ExecKafkaPodCmd(
			helpers.DefaultNamespace, appPods[empireHqApp], fmt.Sprintf(prodHqAnnounce))
		Expect(err).Should(BeNil())

		err = kubectl.ExecKafkaPodCmd(
			helpers.DefaultNamespace, appPods[outpostApp], fmt.Sprintf(conOutpostAnnoune))
		Expect(err).Should(BeNil())

		err = kubectl.ExecKafkaPodCmd(
			helpers.DefaultNamespace, appPods[empireHqApp], fmt.Sprintf(prodHqDeathStar))
		Expect(err).Should(BeNil())

		err = kubectl.ExecKafkaPodCmd(
			helpers.DefaultNamespace, appPods[outpostApp], fmt.Sprintf(conOutDeathStar))
		Expect(err).Should(BeNil())

		err = kubectl.ExecKafkaPodCmd(
			helpers.DefaultNamespace, appPods[backupApp], fmt.Sprintf(prodBackAnnounce))
		Expect(err).Should(BeNil())

		err = kubectl.ExecKafkaPodCmd(
			helpers.DefaultNamespace, appPods[outpostApp], fmt.Sprintf(prodOutAnnounce))
		Expect(err).Should(BeNil())

		By("Apply L7 kafka policy")
		eps1 := kubectl.CiliumEndpointPolicyVersion(ciliumPod1)
		_, err = kubectl.CiliumPolicyAction(helpers.KubeSystemNamespace, l7Policy, helpers.KubectlApply, 300)
		Expect(err).Should(BeNil())

		By("Waiting for endpoint updates with L7 policy")
		err = helpers.WaitUntilEndpointUpdates(ciliumPod1, eps1, 3, kubectl)
		Expect(err).Should(BeNil())
		epsStatus1 := helpers.WithTimeout(func() bool {
			endpoints1, err := kubectl.CiliumEndpointsListByLabel(ciliumPod1, podFilter)
			if err != nil {
				return false
			}
			return endpoints1.AreReady()
		}, "could not get endpoints", &helpers.TimeoutConfig{Timeout: 100})

		Expect(epsStatus1).Should(BeNil())

		endpoints1, err := kubectl.CiliumEndpointsListByLabel(ciliumPod1, podFilter)
		policyStatus1 := endpoints1.GetPolicyStatus()

		/*
			Kafka multinode setup:

			K8s1:
				1. empire-backup
				2. empire-hq
				3. kafka-broker : ingress policy only

			K8s2:
			   1. zook
			   2. empire-outpost-8888
			   3. empire-outpost-9999
		*/
		By("Testing Kafka endpoint policy enforcement status on K8s1")
		Expect(policyStatus1[models.EndpointPolicyEnabledNone]).Should(Equal(2))
		// Only the kafka broker app should have ingress policy enabled.
		Expect(policyStatus1[models.EndpointPolicyEnabledIngress]).Should(Equal(1))
		Expect(policyStatus1[models.EndpointPolicyEnabledEgress]).Should(Equal(0))
		Expect(policyStatus1[models.EndpointPolicyEnabledBoth]).Should(Equal(0))

		By("Testing endpoint policy trace status on kafka-broker node")

		trace := kubectl.CiliumExec(ciliumPod1, fmt.Sprintf(
			"cilium policy trace --src-k8s-pod default:%s --dst-k8s-pod default:%s --dport 9092",
			appPods[empireHqApp], appPods[kafkaApp]))
		trace.ExpectSuccess(trace.CombineOutput().String())
		Expect(trace.Output().String()).Should(ContainSubstring("Final verdict: ALLOWED"))

		trace = kubectl.CiliumExec(ciliumPod1, fmt.Sprintf(
			"cilium policy trace --src-k8s-pod default:%s --dst-k8s-pod default:%s --dport 9092",
			appPods[backupApp], appPods[kafkaApp]))
		trace.ExpectSuccess(trace.CombineOutput().String())
		Expect(trace.Output().String()).Should(ContainSubstring("Final verdict: ALLOWED"))

		trace = kubectl.CiliumExec(ciliumPod1, fmt.Sprintf(
			"cilium policy trace --src-k8s-pod default:%s --dst-k8s-pod default:%s --dport 80",
			appPods[empireHqApp], appPods[kafkaApp]))
		trace.ExpectSuccess(trace.CombineOutput().String())
		Expect(trace.Output().String()).Should(ContainSubstring("Final verdict: DENIED"))

		By("Testing Kafka L7 policy enforcement status")
		err = kubectl.ExecKafkaPodCmd(
			helpers.DefaultNamespace, appPods[empireHqApp], fmt.Sprintf(prodHqAnnounce))
		Expect(err).Should(BeNil())

		err = kubectl.ExecKafkaPodCmd(
			helpers.DefaultNamespace, appPods[outpostApp], fmt.Sprintf(conOutpostAnnoune))
		Expect(err).Should(BeNil())

		err = kubectl.ExecKafkaPodCmd(
			helpers.DefaultNamespace, appPods[empireHqApp], fmt.Sprintf(prodHqDeathStar))
		Expect(err).Should(BeNil())

		err = kubectl.ExecKafkaPodCmd(
			helpers.DefaultNamespace, appPods[outpostApp], fmt.Sprintf(conOutpostAnnoune))
		Expect(err).Should(BeNil())

		err = kubectl.ExecKafkaPodCmd(
			helpers.DefaultNamespace, appPods[backupApp], fmt.Sprintf(prodBackAnnounce))
		Expect(err).Should(HaveOccurred())

		err = kubectl.ExecKafkaPodCmd(
			helpers.DefaultNamespace, appPods[outpostApp], fmt.Sprintf(conOutDeathStar))
		Expect(err).Should(HaveOccurred())

		err = kubectl.ExecKafkaPodCmd(
			helpers.DefaultNamespace, appPods[outpostApp], fmt.Sprintf(prodOutAnnounce))
		Expect(err).Should(HaveOccurred())

		eps1 = kubectl.CiliumEndpointPolicyVersion(ciliumPod1)
		By("Deleting L7 policy")
		status := kubectl.Delete(l7Policy)
		status.ExpectSuccess()
		kubectl.CiliumEndpointWait(ciliumPod1)

		//Only 1 endpoint on node1 is affected by L7 rule
		err = helpers.WaitUntilEndpointUpdates(ciliumPod1, eps1, 3, kubectl)
		Expect(err).Should(BeNil())

	}, 500)
})

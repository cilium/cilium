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

	"github.com/cilium/cilium/api/v1/models"
	. "github.com/cilium/cilium/test/ginkgo-ext"
	"github.com/cilium/cilium/test/helpers"

	. "github.com/onsi/gomega"
	"github.com/sirupsen/logrus"
)

var _ = Describe("K8sValidatedKafkaPolicyTest", func() {

	var microscopeErr error
	var microscopeCancel func() error
	var kubectl *helpers.Kubectl
	var ciliumPod string

	var (
		logger      = log.WithFields(logrus.Fields{"testName": "K8sValidatedKafkaPolicyTest"})
		l7Policy    = helpers.ManifestGet("kafka-sw-security-policy.yaml")
		demoPath    = helpers.ManifestGet("kafka-sw-app.yaml")
		kafkaApp    = "kafka"
		zookApp     = "zook"
		backupApp   = "empire-backup"
		empireHqApp = "empire-hq"
		outpostApp  = "empire-outpost"
		apps        = []string{kafkaApp, zookApp, backupApp, empireHqApp, outpostApp}
		appPods     = map[string]string{}

		prodHqAnnounce    = `-c "echo 'Happy 40th Birthday to General Tagge' | ./kafka-produce.sh --topic empire-announce"`
		conOutpostAnnoune = `-c "./kafka-consume.sh --topic empire-announce --from-beginning --max-messages 1"`
		prodHqDeathStar   = `-c "echo 'deathstar reactor design v3' | ./kafka-produce.sh --topic deathstar-plans"`
		conOutDeathStar   = `-c "./kafka-consume.sh --topic deathstar-plans --from-beginning --max-messages 1"`
		prodBackAnnounce  = `-c "echo 'Happy 40th Birthday to General Tagge' | ./kafka-produce.sh --topic empire-announce"`
		prodOutAnnounce   = `-c "echo 'Vader Booed at Empire Karaoke Party' | ./kafka-produce.sh --topic empire-announce"`
	)

	BeforeAll(func() {
		logger = log.WithFields(logrus.Fields{"testName": "K8sValidatedKafkaPolicyTest"})
		kubectl = helpers.CreateKubectl(helpers.K8s1VMName(), logger)

		kubectl.Apply(helpers.ManifestGet("cilium_ds.yaml"))
		ExpectCiliumReady(kubectl)
		ExpectKubeDNSReady(kubectl)

		kubectl.Apply(demoPath)
		err := kubectl.WaitforPods(helpers.DefaultNamespace, "-l zgroup=kafkaTestApp", 300)
		Expect(err).Should(BeNil(), "Kafka Pods are not ready after timeout")

		appPods = helpers.GetAppPods(apps, helpers.DefaultNamespace, kubectl, "app")

		ciliumPod, err = kubectl.GetCiliumPodOnNode(helpers.KubeSystemNamespace, helpers.K8s2)
		Expect(err).To(BeNil(), "Cannot get cilium Pod")

	})

	AfterFailed(func() {
		kubectl.CiliumReport(helpers.KubeSystemNamespace,
			"cilium service list",
			"cilium endpoint list")
	})

	JustBeforeEach(func() {
		microscopeErr, microscopeCancel = kubectl.MicroscopeStart()
		Expect(microscopeErr).To(BeNil(), "Microscope cannot be started")
	})

	JustAfterEach(func() {
		kubectl.ValidateNoErrorsOnLogs(CurrentGinkgoTestDescription().Duration)
		Expect(microscopeCancel()).To(BeNil(), "cannot stop microscope")
	})

	AfterEach(func() {
		// On aftereach don't make assertions to delete all.
		_ = kubectl.Delete(demoPath)
		_ = kubectl.Delete(l7Policy)

		ExpectAllPodsTerminated(kubectl)

	})

	It("KafkaPolicies", func() {

		By("Testing basic Kafka Produce and Consume")
		// We need to produce first, since consumer script waits for
		// some messages to be already there by the producer.

		err := kubectl.ExecKafkaPodCmd(
			helpers.DefaultNamespace, appPods[empireHqApp], fmt.Sprintf(prodHqAnnounce))
		Expect(err).Should(BeNil(), "Failed to produce to empire-hq on topic empire-announce")

		err = kubectl.ExecKafkaPodCmd(
			helpers.DefaultNamespace, appPods[outpostApp], fmt.Sprintf(conOutpostAnnoune))
		Expect(err).Should(BeNil(), "Failed to consume from outpost on topic empire-announce")

		err = kubectl.ExecKafkaPodCmd(
			helpers.DefaultNamespace, appPods[empireHqApp], fmt.Sprintf(prodHqDeathStar))
		Expect(err).Should(BeNil(), "Failed to produce to empire-hq on topic deathstar-plans")

		err = kubectl.ExecKafkaPodCmd(
			helpers.DefaultNamespace, appPods[outpostApp], fmt.Sprintf(conOutDeathStar))
		Expect(err).Should(BeNil(), "Failed to consume from outpost on topic deathstar-plans")

		err = kubectl.ExecKafkaPodCmd(
			helpers.DefaultNamespace, appPods[backupApp], fmt.Sprintf(prodBackAnnounce))
		Expect(err).Should(BeNil(), "Failed to produce to backup on topic empire-announce")

		err = kubectl.ExecKafkaPodCmd(
			helpers.DefaultNamespace, appPods[outpostApp], fmt.Sprintf(prodOutAnnounce))
		Expect(err).Should(BeNil(), "Failed to produce to outpost on topic empire-announce")

		By("Waiting for CEP to exist for %q", appPods[kafkaApp])
		err = kubectl.WaitForCEPToExist(appPods[kafkaApp], helpers.DefaultNamespace)
		Expect(err).To(BeNil(), "CEP did not get created for %s", appPods[kafkaApp])

		By("Getting policy revision number for each endpoint")
		cep := kubectl.CepGet(helpers.DefaultNamespace, appPods[kafkaApp])
		Expect(cep).ToNot(BeNil(), "cannot get cep for app %q and pod %s", kafkaApp, appPods[kafkaApp])
		kafkaRevBeforeUpdate := cep.Status.Policy.Realized.PolicyRevision

		By("Apply L7 kafka policy and wait")

		_, err = kubectl.CiliumPolicyAction(
			helpers.KubeSystemNamespace, l7Policy,
			helpers.KubectlApply, helpers.HelperTimeout)
		Expect(err).To(BeNil(), "L7 policy cannot be imported correctly")

		By("validate that the pods have the correct policy")

		err = kubectl.WaitCEPRevisionIncrease(appPods[kafkaApp], helpers.DefaultNamespace, kafkaRevBeforeUpdate)

		desiredPolicyStatus := map[string]models.EndpointPolicyEnabled{
			backupApp:   models.EndpointPolicyEnabledNone,
			empireHqApp: models.EndpointPolicyEnabledNone,
			kafkaApp:    models.EndpointPolicyEnabledIngress,
			outpostApp:  models.EndpointPolicyEnabledNone,
			zookApp:     models.EndpointPolicyEnabledNone,
		}

		for app, policy := range desiredPolicyStatus {
			cep := kubectl.CepGet(helpers.DefaultNamespace, appPods[app])
			Expect(cep).ToNot(BeNil(), "cannot get cep for app %q and pod %s", app, appPods[app])
			Expect(cep.Status.Policy.Spec.PolicyEnabled).To(Equal(policy), "Policy for %q mismatch", app)
		}

		By("Validating Policy trace")
		trace := kubectl.CiliumExec(ciliumPod, fmt.Sprintf(
			"cilium policy trace --src-k8s-pod default:%s --dst-k8s-pod default:%s --dport 9092",
			appPods[empireHqApp], appPods[kafkaApp]))
		trace.ExpectSuccess("Cilium policy trace failed")
		trace.ExpectContains("Final verdict: ALLOWED")

		trace = kubectl.CiliumExec(ciliumPod, fmt.Sprintf(
			"cilium policy trace --src-k8s-pod default:%s --dst-k8s-pod default:%s --dport 9092",
			appPods[backupApp], appPods[kafkaApp]))
		trace.ExpectSuccess("Cilium policy trace failed")
		trace.ExpectContains("Final verdict: ALLOWED")

		trace = kubectl.CiliumExec(ciliumPod, fmt.Sprintf(
			"cilium policy trace --src-k8s-pod default:%s --dst-k8s-pod default:%s --dport 80",
			appPods[empireHqApp], appPods[kafkaApp]))
		trace.ExpectSuccess("Failed cilium policy trace")
		trace.ExpectContains("Final verdict: DENIED")

		By("Testing Kafka L7 policy enforcement status")
		err = kubectl.ExecKafkaPodCmd(
			helpers.DefaultNamespace, appPods[empireHqApp], fmt.Sprintf(prodHqAnnounce))
		Expect(err).Should(BeNil(), "Failed to produce to empire-hq on topic empire-announce")

		err = kubectl.ExecKafkaPodCmd(
			helpers.DefaultNamespace, appPods[outpostApp], fmt.Sprintf(conOutpostAnnoune))
		Expect(err).Should(BeNil(), "Failed to consume from outpost on topic empire-announce")

		err = kubectl.ExecKafkaPodCmd(
			helpers.DefaultNamespace, appPods[empireHqApp], fmt.Sprintf(prodHqDeathStar))
		Expect(err).Should(BeNil(), "Failed to produce from empire-hq on topic deathstar-plans")

		err = kubectl.ExecKafkaPodCmd(
			helpers.DefaultNamespace, appPods[outpostApp], fmt.Sprintf(conOutpostAnnoune))
		Expect(err).Should(BeNil(), "Failed to consume from outpost on topic empire-announce")

		err = kubectl.ExecKafkaPodCmd(
			helpers.DefaultNamespace, appPods[backupApp], fmt.Sprintf(prodBackAnnounce))
		Expect(err).Should(HaveOccurred(), " Produce to backup on topic empire-announce should have been denied")

		err = kubectl.ExecKafkaPodCmd(
			helpers.DefaultNamespace, appPods[outpostApp], fmt.Sprintf(conOutDeathStar))
		Expect(err).Should(HaveOccurred(), " Consume from outpost on topic deathstar-plans should have been denied")

		err = kubectl.ExecKafkaPodCmd(
			helpers.DefaultNamespace, appPods[outpostApp], fmt.Sprintf(prodOutAnnounce))
		Expect(err).Should(HaveOccurred(), "Produce to outpost on topic empire-announce should have been denied")
	})
})

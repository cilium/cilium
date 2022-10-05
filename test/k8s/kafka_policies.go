// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package k8sTest

import (
	"fmt"
	"time"

	. "github.com/onsi/gomega"

	. "github.com/cilium/cilium/test/ginkgo-ext"
	"github.com/cilium/cilium/test/helpers"
)

// The 5.4 CI job is intended to catch BPF complexity regressions and as such
// doesn't need to execute this test suite.
var _ = SkipDescribeIf(helpers.RunsOn54Kernel, "K8sKafkaPolicyTest", func() {

	var (
		kubectl *helpers.Kubectl

		// these two are set in BeforeAll
		l7Policy       string
		demoPath       string
		ciliumFilename string

		kafkaApp            = "kafka"
		backupApp           = "empire-backup"
		empireHqApp         = "empire-hq"
		outpostApp          = "empire-outpost"
		apps                = []string{kafkaApp, backupApp, empireHqApp, outpostApp}
		appPods             = map[string]string{}
		topicEmpireAnnounce = "empire-announce"
		topicDeathstarPlans = "deathstar-plans"
		topicTest           = "test-topic"

		prodHqAnnounce    = `sh -c "echo 'Happy 40th Birthday to General Tagge' | ./kafka-produce.sh --topic empire-announce"`
		conOutpostAnnoune = `sh -c "./kafka-consume.sh --topic empire-announce --from-beginning --max-messages 1"`
		prodHqDeathStar   = `sh -c "echo 'deathstar reactor design v3' | ./kafka-produce.sh --topic deathstar-plans"`
		conOutDeathStar   = `sh -c "./kafka-consume.sh --topic deathstar-plans --from-beginning --max-messages 1"`
		prodBackAnnounce  = `sh -c "echo 'Happy 40th Birthday to General Tagge' | ./kafka-produce.sh --topic empire-announce"`
		prodOutAnnounce   = `sh -c "echo 'Vader Booed at Empire Karaoke Party' | ./kafka-produce.sh --topic empire-announce"`
	)

	AfterFailed(func() {
		kubectl.CiliumReport("cilium service list", "cilium endpoint list")
	})

	AfterAll(func() {
		UninstallCiliumFromManifest(kubectl, ciliumFilename)
		kubectl.CloseSSHClient()
	})

	// Tests involving the L7 proxy do not work when built with -race, see issue #13757.
	SkipContextIf(func() bool { return helpers.SkipRaceDetectorEnabled() || helpers.RunsOnAKS() }, "Kafka Policy Tests", func() {
		createTopicCmd := func(topic string) string {
			return fmt.Sprintf("/opt/kafka_2.11-0.10.1.0/bin/kafka-topics.sh --create "+
				"--zookeeper localhost:2181 --replication-factor 1 "+
				"--partitions 1 --topic %s", topic)
		}

		createTopic := func(topic string, pod string) error {
			return kubectl.ExecKafkaPodCmd(helpers.DefaultNamespace, pod, createTopicCmd(topic))
		}

		// WaitKafkaBroker waits for the broker to be ready, by executing
		// a command repeatedly until it succeeds, or a timeout occurs
		waitForKafkaBroker := func(pod string, cmd string) error {
			body := func() bool {
				err := kubectl.ExecKafkaPodCmd(helpers.DefaultNamespace, pod, cmd)
				if err != nil {
					return false
				}
				return true
			}
			err := helpers.WithTimeout(body, "Kafka Broker not ready", &helpers.TimeoutConfig{Timeout: helpers.HelperTimeout})
			return err
		}

		waitForDNSResolution := func(pod, service string) error {
			body := func() bool {
				dnsLookupCmd := fmt.Sprintf("nslookup %s", service)
				res := kubectl.ExecPodCmd(helpers.DefaultNamespace, pod, dnsLookupCmd)

				if !res.WasSuccessful() {
					return false
				}
				return true
			}
			err := helpers.WithTimeout(body, fmt.Sprintf("unable to resolve DNS for service %s in pod %s", service, pod), &helpers.TimeoutConfig{Timeout: 240 * time.Second})
			return err
		}

		JustAfterEach(func() {
			kubectl.ValidateNoErrorsInLogs(CurrentGinkgoTestDescription().Duration)
		})

		AfterEach(func() {
			// On aftereach don't make assertions to delete all.
			_ = kubectl.Delete(demoPath)
			_ = kubectl.Delete(l7Policy)

			ExpectAllPodsTerminated(kubectl)
		})

		BeforeAll(func() {
			kubectl = helpers.CreateKubectl(helpers.K8s1VMName(), logger)

			l7Policy = helpers.ManifestGet(kubectl.BasePath(), "kafka-sw-security-policy.yaml")
			demoPath = helpers.ManifestGet(kubectl.BasePath(), "kafka-sw-app.yaml")

			ciliumFilename = helpers.TimestampFilename("cilium.yaml")
			DeployCiliumAndDNS(kubectl, ciliumFilename)

			kubectl.ApplyDefault(demoPath)
			err := kubectl.WaitforPods(helpers.DefaultNamespace, "-l zgroup=kafkaTestApp", helpers.HelperTimeout)
			Expect(err).Should(BeNil(), "Kafka Pods are not ready after timeout")

			err = kubectl.WaitForKubeDNSEntry("kafka-service", helpers.DefaultNamespace)
			Expect(err).To(BeNil(), "DNS entry of kafka-service is not ready after timeout")

			err = kubectl.CiliumEndpointWaitReady()
			Expect(err).To(BeNil(), "Endpoints are not ready after timeout")

			appPods = helpers.GetAppPods(apps, helpers.DefaultNamespace, kubectl, "app")

			By("Wait for Kafka broker to be up")
			err = waitForKafkaBroker(appPods[kafkaApp], createTopicCmd(topicTest))
			Expect(err).To(BeNil(), "Timeout: Kafka cluster failed to come up correctly")
		})

		It("KafkaPolicies", func() {
			By("Creating new kafka topic %s", topicEmpireAnnounce)
			err := createTopic(topicEmpireAnnounce, appPods[kafkaApp])
			Expect(err).Should(BeNil(), "Failed to create topic empire-announce")

			By("Creating new kafka topic %s", topicDeathstarPlans)
			err = createTopic(topicDeathstarPlans, appPods[kafkaApp])
			Expect(err).Should(BeNil(), "Failed to create topic deathstar-plans")

			By("Waiting for DNS to resolve within pods for kafka-service")
			err = waitForDNSResolution(appPods[empireHqApp], "kafka-service")
			Expect(err).Should(BeNil(), "Failed to resolve kafka-service DNS entry in pod %s", appPods[empireHqApp])
			err = waitForDNSResolution(appPods[outpostApp], "kafka-service")
			Expect(err).Should(BeNil(), "Failed to resolve kafka-service DNS entry in pod %s", appPods[outpostApp])

			By("Testing basic Kafka Produce and Consume")
			// We need to produce first, since consumer script waits for
			// some messages to be already there by the producer.

			err = kubectl.ExecKafkaPodCmd(
				helpers.DefaultNamespace, appPods[empireHqApp], prodHqAnnounce)
			Expect(err).Should(BeNil(), "Failed to produce from empire-hq on topic empire-announce")

			err = kubectl.ExecKafkaPodCmd(
				helpers.DefaultNamespace, appPods[outpostApp], conOutpostAnnoune)
			Expect(err).Should(BeNil(), "Failed to consume from outpost on topic empire-announce")

			err = kubectl.ExecKafkaPodCmd(
				helpers.DefaultNamespace, appPods[empireHqApp], prodHqDeathStar)
			Expect(err).Should(BeNil(), "Failed to produce from empire-hq on topic deathstar-plans")

			err = kubectl.ExecKafkaPodCmd(
				helpers.DefaultNamespace, appPods[outpostApp], conOutDeathStar)
			Expect(err).Should(BeNil(), "Failed to consume from outpost on topic deathstar-plans")

			err = kubectl.ExecKafkaPodCmd(
				helpers.DefaultNamespace, appPods[backupApp], prodBackAnnounce)
			Expect(err).Should(BeNil(), "Failed to produce to backup on topic empire-announce")

			err = kubectl.ExecKafkaPodCmd(
				helpers.DefaultNamespace, appPods[outpostApp], prodOutAnnounce)
			Expect(err).Should(BeNil(), "Failed to produce to outpost on topic empire-announce")

			By("Apply L7 kafka policy and wait")

			_, err = kubectl.CiliumPolicyAction(
				helpers.DefaultNamespace, l7Policy,
				helpers.KubectlApply, helpers.HelperTimeout)
			Expect(err).To(BeNil(), "L7 policy cannot be imported correctly")

			By("Testing Kafka L7 policy enforcement status")
			err = kubectl.ExecKafkaPodCmd(
				helpers.DefaultNamespace, appPods[empireHqApp], prodHqAnnounce)
			Expect(err).Should(BeNil(), "Failed to produce from empire-hq on topic empire-announce")

			err = kubectl.ExecKafkaPodCmd(
				helpers.DefaultNamespace, appPods[outpostApp], conOutpostAnnoune)
			Expect(err).Should(BeNil(), "Failed to consume from outpost on topic empire-announce")

			err = kubectl.ExecKafkaPodCmd(
				helpers.DefaultNamespace, appPods[empireHqApp], prodHqDeathStar)
			Expect(err).Should(BeNil(), "Failed to produce from empire-hq on topic deathstar-plans")

			err = kubectl.ExecKafkaPodCmd(
				helpers.DefaultNamespace, appPods[outpostApp], conOutpostAnnoune)
			Expect(err).Should(BeNil(), "Failed to consume from outpost on topic empire-announce")

			err = kubectl.ExecKafkaPodCmd(
				helpers.DefaultNamespace, appPods[backupApp], prodBackAnnounce)
			Expect(err).Should(HaveOccurred(), "Produce from backup on topic empire-announce should have been denied by egress policy")

			err = kubectl.ExecKafkaPodCmd(
				helpers.DefaultNamespace, appPods[outpostApp], conOutDeathStar)
			Expect(err).Should(HaveOccurred(), "Consume from outpost on topic deathstar-plans should have been denied")

			err = kubectl.ExecKafkaPodCmd(
				helpers.DefaultNamespace, appPods[outpostApp], prodOutAnnounce)
			Expect(err).Should(HaveOccurred(), "Produce from outpost on topic empire-announce should have been denied")
		})
	})
})

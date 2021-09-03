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

package RuntimeTest

import (
	"context"
	"fmt"
	"time"

	. "github.com/cilium/cilium/test/ginkgo-ext"
	"github.com/cilium/cilium/test/helpers"
	"github.com/cilium/cilium/test/helpers/constants"

	. "github.com/onsi/gomega"
)

var _ = Describe("RuntimeKafka", func() {

	var (
		vm            *helpers.SSHMeta
		testStartTime time.Time
		monitorRes    *helpers.CmdRes
		monitorStop   = func() error { return nil }

		allowedTopic  = "allowedTopic"
		disallowTopic = "disallowTopic"
		topicTest     = "test-topic"
		listTopicsCmd = "/opt/kafka/bin/kafka-topics.sh --list --zookeeper zook:2181"
		MaxMessages   = 5
		client        = "client"
	)

	containers := func(mode string) {

		images := map[string]string{
			"zook":   constants.ZookeeperImage,
			"client": constants.KafkaClientImage,
		}

		switch mode {
		case "create":
			for k, v := range images {
				vm.ContainerCreate(k, v, helpers.CiliumDockerNetwork, fmt.Sprintf("-l id.%s", k))
			}
			zook, err := vm.ContainerInspectNet("zook")
			Expect(err).Should(BeNil())

			vm.ContainerCreate("kafka", constants.KafkaImage, helpers.CiliumDockerNetwork, fmt.Sprintf(
				"-l id.kafka -e KAFKA_ZOOKEEPER_CONNECT=%s:2181 -e KAFKA_ZOOKEEPER_SESSION_TIMEOUT_MS=60000 -e KAFKA_LISTENERS=PLAINTEXT://:9092 -e KAFKA_ZOOKEEPER_CONNECTION_TIMEOUT_MS=60000", zook["IPv4"]))

		case "delete":
			for k := range images {
				vm.ContainerRm(k)
			}
			vm.ContainerRm("kafka")
		}
	}

	createTopicCmd := func(topic string) string {
		return fmt.Sprintf("/opt/kafka/bin/kafka-topics.sh --create --zookeeper zook:2181 "+
			"--replication-factor 1 --partitions 1 --topic %s", topic)
	}

	createTopic := func(topic string) {
		logger.Infof("Creating new kafka topic %s", topic)
		res := vm.ContainerExec(client, createTopicCmd(topic))
		res.ExpectSuccess("Unable to create topic  %s", topic)
	}

	consumerCmd := func(topic string, maxMsg int) string {
		return fmt.Sprintf("/opt/kafka/bin/kafka-console-consumer.sh --bootstrap-server "+
			"kafka:9092 --topic %s --max-messages %d --timeout-ms 300000 --from-beginning",
			topic, maxMsg)
	}

	consumer := func(topic string, maxMsg int) *helpers.CmdRes {
		return vm.ContainerExec(client, consumerCmd(topic, maxMsg))
	}

	producer := func(topic string, message string) {
		cmd := fmt.Sprintf(
			"echo %s | docker exec -i %s /opt/kafka/bin/kafka-console-producer.sh "+
				"--broker-list kafka:9092 --topic %s",
			message, client, topic)
		vm.Exec(cmd)
	}

	// WaitKafkaBroker waits for the broker to be ready, by executing
	// a command repeatedly until it succeeds, or a timeout occurs
	waitForKafkaBroker := func(pod string, cmd string) error {
		body := func() bool {
			res := vm.ContainerExec(pod, cmd)
			return res.WasSuccessful()
		}
		err := helpers.WithTimeout(body, "Kafka Broker not ready", &helpers.TimeoutConfig{Timeout: helpers.HelperTimeout})
		return err
	}

	BeforeAll(func() {
		vm = helpers.InitRuntimeHelper(helpers.Runtime, logger)
		ExpectCiliumReady(vm)

		status := vm.ExecCilium(fmt.Sprintf("config %s=true",
			helpers.OptionConntrackLocal))
		status.ExpectSuccess()

		containers("create")
		Expect(vm.WaitEndpointsReady()).Should(BeTrue(), "Endpoints are not ready after timeout")

		err := waitForKafkaBroker(client, createTopicCmd(topicTest))
		Expect(err).To(BeNil(), "Kafka broker failed to come up")

		By("Creating kafka topics")
		createTopic(allowedTopic)
		createTopic(disallowTopic)

		By("Listing created Kafka topics")
		res := vm.ContainerExec(client, listTopicsCmd)
		res.ExpectSuccess("Cannot list kafka topics")
	})

	AfterEach(func() {
		vm.PolicyDelAll()

	})

	AfterAll(func() {
		containers("delete")

		status := vm.ExecCilium(fmt.Sprintf("config %s=false",
			helpers.OptionConntrackLocal))
		status.ExpectSuccess()

		vm.CloseSSHClient()
	})

	JustBeforeEach(func() {
		testStartTime = time.Now()
		monitorRes, monitorStop = vm.MonitorStart("--type l7")
	})

	JustAfterEach(func() {
		vm.ValidateNoErrorsInLogs(time.Since(testStartTime))
		Expect(monitorStop()).To(BeNil(), "cannot stop monitor command")
	})

	AfterFailed(func() {
		vm.ReportFailed("cilium policy get")
	})

	SkipItIf(helpers.SkipRaceDetectorEnabled, "Kafka Policy Ingress", func() {
		_, err := vm.PolicyImportAndWait(vm.GetFullPath("Policies-kafka.json"), helpers.HelperTimeout)
		Expect(err).Should(BeNil())

		endPoints, err := vm.PolicyEndpointsSummary()
		Expect(err).Should(BeNil(), "Cannot get endpoint list")
		Expect(endPoints[helpers.Enabled]).To(Equal(1),
			"Check number of endpoints with policy enforcement enabled")
		Expect(endPoints[helpers.Disabled]).To(Equal(3),
			"Check number of endpoints with policy enforcement disabled")

		By("Allowed topic")

		By("Sending produce request on kafka topic `allowedTopic`")
		for i := 1; i <= MaxMessages; i++ {
			producer(allowedTopic, fmt.Sprintf("Message %d", i))
		}

		By("Sending consume request on kafka topic `allowedTopic`")
		res := consumer(allowedTopic, MaxMessages)
		res.ExpectSuccess("Failed to consume messages from kafka topic `allowedTopic`")
		Expect(res.CombineOutput().String()).
			Should(ContainSubstring("Processed a total of %d messages", MaxMessages),
				"Kafka did not process the expected number of messages")

		By("Disable topic")
		res = consumer(disallowTopic, MaxMessages)
		res.ExpectFail("Kafka consumer can access to disallowTopic")

		monitorRes.WaitUntilMatch("verdict Denied offsetfetch topic disallowTopic => 29")
		monitorRes.ExpectContains("verdict Denied offsetfetch topic disallowTopic => 29")
	})

	SkipItIf(helpers.SkipRaceDetectorEnabled, "Kafka Policy Role Egress", func() {
		_, err := vm.PolicyImportAndWait(vm.GetFullPath("Policies-kafka-Role.json"), helpers.HelperTimeout)
		Expect(err).Should(BeNil(), "Expected nil got %s while importing policy Policies-kafka-Role.json", err)

		endPoints, err := vm.PolicyEndpointsSummary()
		Expect(err).Should(BeNil(), "Expect nil. Failed to apply policy on all endpoints with error :%s", err)
		Expect(endPoints[helpers.Enabled]).To(Equal(2), "Expected 2 endpoint to be policy enabled. Policy enforcement failed")
		Expect(endPoints[helpers.Disabled]).To(Equal(2), "Expected 2 endpoint to be policy disabled. Policy enforcement failed")

		By("Sending produce request on kafka topic `allowedTopic`")
		for i := 1; i <= MaxMessages; i++ {
			producer(allowedTopic, fmt.Sprintf("Message %d", i))
		}

		By("Sending consume request on kafka topic `allowedTopic`")
		res := consumer(allowedTopic, MaxMessages)
		res.ExpectSuccess("Failed to consume messages from kafka topic `allowedTopic`")
		Expect(res.CombineOutput().String()).
			Should(ContainSubstring("Processed a total of %d messages", MaxMessages),
				"Kafka did not process the expected number of messages")

		By("Non-allowed topic")
		// Consumer timeout didn't work correctly, so make sure that AUTH is present in the reply
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		res = vm.ExecInBackground(ctx, fmt.Sprintf(
			"docker exec -i %s %s", client, consumerCmd(disallowTopic, MaxMessages)))
		err = res.WaitUntilMatch("{disallowTopic=TOPIC_AUTHORIZATION_FAILED}")
		Expect(err).To(BeNil(), "Traffic in disallowTopic is allowed")

		monitorRes.WaitUntilMatch("verdict Denied metadata topic disallowTopic => 29")
		monitorRes.ExpectContains("verdict Denied metadata topic disallowTopic => 29")
	})
})

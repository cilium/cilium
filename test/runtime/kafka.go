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

	. "github.com/cilium/cilium/test/ginkgo-ext"
	"github.com/cilium/cilium/test/helpers"

	. "github.com/onsi/gomega"
	"github.com/sirupsen/logrus"
)

var _ = Describe("RuntimeValidatedKafka", func() {

	var logger *logrus.Entry
	var vm *helpers.SSHMeta
	var monitorStop func() error

	var allowedTopic string = "allowedTopic"
	var disallowTopic string = "disallowTopic"
	var produceCmd string = fmt.Sprintf(
		"echo \"Message 0\" | docker exec -i client /opt/kafka/bin/kafka-console-producer.sh "+
			"--broker-list kafka:9092 --topic %s", allowedTopic)
	var listTopicsCmd string = "/opt/kafka/bin/kafka-topics.sh --list --zookeeper zook:2181"
	var MaxMessages int = 6
	var client string = "client"

	containers := func(mode string) {

		images := map[string]string{
			"zook":   "digitalwonderland/zookeeper",
			"client": "cilium/kafkaclient2",
		}

		switch mode {
		case "create":
			for k, v := range images {
				vm.ContainerCreate(k, v, helpers.CiliumDockerNetwork, fmt.Sprintf("-l id.%s", k))
			}
			zook, err := vm.ContainerInspectNet("zook")
			Expect(err).Should(BeNil())

			vm.ContainerCreate("kafka", "wurstmeister/kafka", helpers.CiliumDockerNetwork, fmt.Sprintf(
				"-l id.kafka -e KAFKA_ZOOKEEPER_CONNECT=%s:2181 -e KAFKA_ZOOKEEPER_SESSION_TIMEOUT_MS=20000 -e KAFKA_LISTENERS=PLAINTEXT://:9092 -e KAFKA_ZOOKEEPER_CONNECTION_TIMEOUT_MS=20000", zook["IPv4"]))

		case "delete":
			for k := range images {
				vm.ContainerRm(k)
			}
			vm.ContainerRm("kafka")
		}
	}

	createTopic := func(name string) {
		logger.Infof("Creating new kafka topic %s", name)
		res := vm.ContainerExec(client, fmt.Sprintf(
			"/opt/kafka/bin/kafka-topics.sh --create --zookeeper zook:2181 "+
				"--replication-factor 1 --partitions 1 --topic %s", name))
		res.ExpectSuccess("Unable to create topic  %s", name)
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
	// a produce request on existing topics and waiting for a response from broker
	waitForKafkaBroker := func(pod string, cmd string) error {
		body := func() bool {
			res := vm.ContainerExec(pod, cmd)
			return res.WasSuccessful()
		}
		err := helpers.WithTimeout(body, "Kafka Broker not ready", &helpers.TimeoutConfig{Timeout: 150})
		return err
	}

	BeforeAll(func() {
		logger = log.WithFields(logrus.Fields{"testName": "RuntimeValidatedKafka"})
		vm = helpers.CreateNewRuntimeHelper(helpers.Runtime, logger)

		containers("create")
		epsReady := vm.WaitEndpointsReady()
		Expect(epsReady).Should(BeTrue(), "Endpoints are not ready after timeout")

		err := waitForKafkaBroker(client, listTopicsCmd)
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
	})

	JustBeforeEach(func() {
		monitorStop = vm.MonitorStart()
	})

	JustAfterEach(func() {
		vm.ValidateNoErrorsOnLogs(CurrentGinkgoTestDescription().Duration)
		Expect(monitorStop()).To(BeNil(), "cannot stop monitor command")
	})

	AfterFailed(func() {
		vm.ReportFailed("cilium policy get")
	})

	It("Kafka Policy Ingress", func() {
		_, err := vm.PolicyImportAndWait(vm.GetFullPath("Policies-kafka.json"), 300)
		Expect(err).Should(BeNil())

		endPoints, err := vm.PolicyEndpointsSummary()
		Expect(err).Should(BeNil(), "Cannot get endpoint list")
		Expect(endPoints[helpers.Enabled]).To(Equal(1),
			"Check number of endpoints with policy enforcement enabled")
		Expect(endPoints[helpers.Disabled]).To(Equal(2),
			"Check number of endpoints with policy enforcement disabled")

		// Waiting for kafka broker to be up.
		err = waitForKafkaBroker(client, produceCmd)
		Expect(err).To(BeNil(), "Kafka broker failed to come up")

		By("Allowed topic")

		By("Sending produce request on kafka topic `allowedTopic`")
		for i := 1; i <= MaxMessages-1; i++ {
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
	})

	It("Kafka Policy Role Ingress", func() {
		_, err := vm.PolicyImportAndWait(vm.GetFullPath("Policies-kafka-Role.json"), 300)
		Expect(err).Should(BeNil(), "Expected nil got %s while importing policy Policies-kafka-Role.json", err)

		endPoints, err := vm.PolicyEndpointsSummary()
		Expect(err).Should(BeNil(), "Expect nil. Failed to apply policy on all endpoints with error :%s", err)
		Expect(endPoints[helpers.Enabled]).To(Equal(1), "Expected 1 endpoint to be policy enabled. Policy enforcement failed")
		Expect(endPoints[helpers.Disabled]).To(Equal(2), "Expected 2 endpoint to be policy disabled. Policy enforcement failed")

		// Waiting for kafka broker to be up.
		err = waitForKafkaBroker(client, produceCmd)
		Expect(err).To(BeNil(), "Kafka broker failed to come up")

		By("By sending produce/consume request on topic `allowedTopic`")

		By("Sending produce request on kafka topic `allowedTopic`")
		for i := 1; i <= MaxMessages-1; i++ {
			producer(allowedTopic, fmt.Sprintf("Message %d", i))
		}

		By("Sending consume request on kafka topic `allowedTopic`")
		res := consumer(allowedTopic, MaxMessages)
		res.ExpectSuccess("Failed to consume messages from kafka topic `allowedTopic`")
		Expect(res.CombineOutput().String()).
			Should(ContainSubstring("Processed a total of %d messages", MaxMessages),
				"Kafka did not process the expected number of messages")

		By("Disable topic")
		// Consumer timeout didn't work correctly, so make sure that AUTH is present in the reply
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		res = vm.ExecContext(ctx, fmt.Sprintf(
			"docker exec -i %s %s", client, consumerCmd(disallowTopic, MaxMessages)))
		err = res.WaitUntilMatch("{disallowTopic=TOPIC_AUTHORIZATION_FAILED}")
		Expect(err).To(BeNil(), "Traffic in disallowTopic is allowed")
	})
})

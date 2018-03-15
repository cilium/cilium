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
	"sync"

	. "github.com/cilium/cilium/test/ginkgo-ext"
	"github.com/cilium/cilium/test/helpers"

	. "github.com/onsi/gomega"
	"github.com/sirupsen/logrus"
)

var _ = Describe("RuntimeValidatedKafka", func() {

	var once sync.Once
	var logger *logrus.Entry
	var vm *helpers.SSHMeta

	var allowedTopic string = "allowedTopic"
	var disallowTopic string = "disallowTopic"
	var MaxMessages int = 5

	initialize := func() {
		logger = log.WithFields(logrus.Fields{"testName": "RuntimeKafka"})
		logger.Info("Starting")
		vm = helpers.CreateNewRuntimeHelper(helpers.Runtime, logger)
	}

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
				"-l id.kafka -e KAFKA_ZOOKEEPER_CONNECT=%s:2181 ", zook["IPv4"]))

		case "delete":
			for k := range images {
				vm.ContainerRm(k)
			}
			vm.ContainerRm("kafka")
		}
	}

	createTopic := func(name string) {
		logger.Infof("Creating new kafka topic %s", name)
		res := vm.ContainerExec("client", fmt.Sprintf(
			"/opt/kafka/bin/kafka-topics.sh --create --zookeeper zook:2181 "+
				"--replication-factor 1 --partitions 1 --topic %s", name))
		res.ExpectSuccess()
	}

	consumer := func(topic string, maxMsg int) string {
		return fmt.Sprintf(
			"docker exec client /opt/kafka/bin/kafka-console-consumer.sh --bootstrap-server "+
				"kafka:9092 --topic %s --max-messages %d --timeout-ms 30000", topic, maxMsg)
	}

	producer := func(topic string, message string) {
		cmd := fmt.Sprintf(
			"echo %s | docker exec -i client /opt/kafka/bin/kafka-console-producer.sh "+
				"--broker-list kafka:9092 --topic %s",
			message, topic)
		vm.Exec(cmd)
	}

	BeforeEach(func() {
		once.Do(initialize)
		containers("create")
		epsReady := vm.WaitEndpointsReady()
		Expect(epsReady).Should(BeTrue())
	})

	AfterEach(func() {
		if CurrentGinkgoTestDescription().Failed {
			vm.ReportFailed()
		}
		vm.Exec("policy delete --all")
		containers("delete")
	})

	It("Kafka Policy Ingress", func() {
		_, err := vm.PolicyImportAndWait(vm.GetFullPath("Policies-kafka.json"), 300)
		Expect(err).Should(BeNil())

		endPoints, err := vm.PolicyEndpointsSummary()
		Expect(err).Should(BeNil())
		Expect(endPoints[helpers.Enabled]).To(Equal(1))
		Expect(endPoints[helpers.Disabled]).To(Equal(2))

		createTopic(allowedTopic)
		createTopic(disallowTopic)

		res := vm.ContainerExec("client",
			"/opt/kafka/bin/kafka-topics.sh --list --zookeeper zook:2181")
		res.ExpectSuccess("Cannot get kafka topics")

		By("Allowed topic")
		ctx, cancel := context.WithCancel(context.Background())
		data := vm.ExecContext(ctx, consumer(allowedTopic, MaxMessages))

		//TODO: wait until ready GH #3116
		helpers.Sleep(10)
		for i := 1; i <= MaxMessages; i++ {
			producer(allowedTopic, fmt.Sprintf("Message %d", i))
		}
		cancel()

		err = data.WaitUntilMatch(fmt.Sprintf("Processed a total of %d messages", MaxMessages))
		Expect(err).To(BeNil())

		Expect(data.Output().String()).Should(ContainSubstring(
			"Processed a total of %d messages", MaxMessages))

		By("Disable topic")
		res = vm.Exec(consumer(disallowTopic, MaxMessages))
		res.ExpectFail("Kafka consumer can access to disallowTopic")
	})

	It("Kafka Policy Role Ingress", func() {
		_, err := vm.PolicyImportAndWait(vm.GetFullPath("Policies-kafka-Role.json"), 300)
		Expect(err).Should(BeNil(), "Expected nil got %s while importing policy Policies-kafka-Role.json", err)

		endPoints, err := vm.PolicyEndpointsSummary()
		Expect(err).Should(BeNil(), "Expect nil. Failed to apply policy on all endpoints with error :%s", err)
		Expect(endPoints[helpers.Enabled]).To(Equal(1), "Expected 1 endpoint to be policy enabled. Policy enforcement failed")
		Expect(endPoints[helpers.Disabled]).To(Equal(2), "Expected 2 endpoint to be policy disabled. Policy enforcement failed")

		createTopic(allowedTopic)
		createTopic(disallowTopic)

		res := vm.ContainerExec("client",
			"/opt/kafka/bin/kafka-topics.sh --list --zookeeper zook:2181")
		res.ExpectSuccess("Cannot get kafka topics")

		By("By sending produce/consume request on topic `allowedTopic`")
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		data := vm.ExecContext(ctx, consumer(allowedTopic, MaxMessages))

		//TODO: wait until ready GH #3116
		helpers.Sleep(10)
		for i := 1; i <= MaxMessages; i++ {
			producer(allowedTopic, fmt.Sprintf("Message %d", i))
		}

		err = data.WaitUntilMatch(fmt.Sprintf("Processed a total of %d messages", MaxMessages))
		Expect(err).To(BeNil())

		Expect(data.Output().String()).Should(ContainSubstring(
			"Processed a total of %d messages", MaxMessages))

		By("By sending produce/consume request on topic `disallowedTopic`")
		res = vm.Exec(consumer(disallowTopic, MaxMessages))
		res.ExpectFail("Kafka consumer can access to disallowTopic")
	})
})

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

	"github.com/cilium/cilium/test/helpers"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	"github.com/sirupsen/logrus"
)

var _ = Describe("RuntimeKafka", func() {

	var initialized bool
	var logger *log.Entry
	var docker *helpers.Docker
	var cilium *helpers.Cilium

	var allowedTopic string = "allowedTopic"
	var disallowTopic string = "disallowTopic"
	var MaxMessages int = 5

	initialize := func() {
		if initialized == true {
			return
		}
		logger = log.WithFields(logrus.Fields{"testName": "RuntimeKafka"})
		logger.Info("Starting")
		docker, cilium = helpers.CreateNewRuntimeHelper("runtime", logger)
		docker.NetworkCreate(helpers.CiliumDockerNetwork, "")
		initialized = true
	}

	containers := func(mode string) {

		images := map[string]string{
			"zook":   "digitalwonderland/zookeeper",
			"client": "cilium/kafkaclient2",
		}

		switch mode {
		case "create":
			for k, v := range images {
				docker.ContainerCreate(k, v, helpers.CiliumDockerNetwork, fmt.Sprintf("-l id.%s", k))
			}
			zook, err := docker.ContainerInspectNet("zook")
			Expect(err).Should(BeNil())

			docker.ContainerCreate("kafka", "wurstmeister/kafka", helpers.CiliumDockerNetwork, fmt.Sprintf(
				"-l id.kafka -e KAFKA_ZOOKEEPER_CONNECT=%s:2181 ", zook["IPv4"]))

		case "delete":
			for k := range images {
				docker.ContainerRm(k)
			}
			docker.ContainerRm("kafka")
		}
	}

	createTopic := func(name string) {
		logger.Infof("Creating new kafka topic %s", name)
		res := docker.ContainerExec("client", fmt.Sprintf(
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
		docker.Node.Exec(cmd)
	}

	BeforeEach(func() {
		initialize()
		containers("create")
		epsReady := cilium.WaitEndpointsReady()
		Expect(epsReady).Should(BeTrue())
	})

	AfterEach(func() {
		if CurrentGinkgoTestDescription().Failed {
			cilium.ReportFailed()
		}
		cilium.Exec("policy delete --all")
		containers("delete")
	})

	It("Kafka Policy Ingress", func() {
		_, err := cilium.PolicyImport(cilium.GetFullPath("Policies-kafka.json"), 300)
		Expect(err).Should(BeNil())

		endPoints, err := cilium.PolicyEndpointsSummary()
		Expect(err).Should(BeNil())
		Expect(endPoints[helpers.Enabled]).To(Equal(1))
		Expect(endPoints[helpers.Disabled]).To(Equal(2))

		createTopic(allowedTopic)
		createTopic(disallowTopic)

		res := docker.ContainerExec("client",
			"/opt/kafka/bin/kafka-topics.sh --list --zookeeper zook:2181")
		res.ExpectSuccess("Cannot get kafka topics")

		By("Allowed topic")
		ctx, cancel := context.WithCancel(context.Background())
		data := cilium.Node.ExecContext(ctx, consumer(allowedTopic, MaxMessages))

		//TODO: wait until ready
		helpers.Sleep(5)
		for i := 1; i <= MaxMessages; i++ {
			producer(allowedTopic, fmt.Sprintf("Message %d", i))
		}
		cancel()

		Expect(data.Output().String()).Should(ContainSubstring(
			"Processed a total of %d messages", MaxMessages))

		By("Disable topic")
		res = cilium.Node.Exec(consumer(disallowTopic, MaxMessages))
		res.ExpectFail("Kafka consumer can access to disallowTopic")
	})
})

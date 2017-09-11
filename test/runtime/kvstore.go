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

	"github.com/cilium/cilium/test/helpers"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	log "github.com/sirupsen/logrus"
)

var _ = Describe("RuntimeKVStoreTest", func() {

	var initialized bool
	var networkName string = "cilium-net"

	var netperfImage string = "tgraf/netperf"
	var logger *log.Entry
	var docker *helpers.Docker
	var cilium *helpers.Cilium

	initialize := func() {
		if initialized == true {
			return
		}
		logger = log.WithFields(log.Fields{"testName": "RuntimeKVStoreTest"})
		logger.Info("Starting")
		docker, cilium = helpers.CreateNewRuntimeHelper("runtime", logger)
		initialized = true
	}
	containers := func(option string) {
		switch option {
		case "create":
			docker.NetworkCreate(networkName, "")
			docker.ContainerCreate("client", netperfImage, networkName, "-l id.client")
		case "delete":
			docker.ContainerRm("client")

		}
	}

	BeforeEach(func() {
		initialize()
		docker.Node.Exec("sudo systemctl stop cilium")
	}, 150)

	AfterEach(func() {
		if CurrentGinkgoTestDescription().Failed {
			cilium.ReportFailed(
				"sudo docker ps -a",
				"sudo cilium endpoint list")
		}
		containers("delete")
		docker.Node.Exec("sudo systemctl start cilium")
	})

	It("Consul KVStore", func() {
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		cilium.Node.ExecContext(
			ctx,
			"sudo cilium-agent --kvstore consul --kvstore-opt consul.address=127.0.0.1:8500 --debug")
		err := cilium.WaitUntilReady(150)
		Expect(err).Should(BeNil())

		docker.Node.Exec("sudo systemctl restart cilium-docker")
		helpers.Sleep(2)
		containers("create")
		cilium.EndpointWaitUntilReady()
		eps, err := cilium.GetEndpointsNames()
		Expect(err).Should(BeNil())
		Expect(len(eps)).To(Equal(1))
	})

	It("Etcd KVStore", func() {
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		cilium.Node.ExecContext(
			ctx,
			"sudo cilium-agent --kvstore etcd --kvstore-opt etcd.address=127.0.0.1:4001")
		err := cilium.WaitUntilReady(150)
		Expect(err).Should(BeNil())

		docker.Node.Exec("sudo systemctl restart cilium-docker")
		helpers.Sleep(2)
		containers("create")
		cilium.EndpointWaitUntilReady()

		eps, err := cilium.GetEndpointsNames()
		Expect(err).Should(BeNil())
		Expect(len(eps)).To(Equal(1))
	})
})

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
	"github.com/cilium/cilium/test/helpers"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	log "github.com/sirupsen/logrus"
)

var _ = Describe("RuntimeChaos", func() {

	var initialized bool
	var logger *log.Entry
	var docker *helpers.Docker
	var cilium *helpers.Cilium

	initialize := func() {
		if initialized == true {
			return
		}
		logger = log.WithFields(log.Fields{"testName": "RuntimeChaos"})
		logger.Info("Starting")
		docker, cilium = helpers.CreateNewRuntimeHelper(helpers.Runtime, logger)
		docker.NetworkCreate(helpers.CiliumDockerNetwork, "")
		initialized = true
	}

	waitForCilium := func() {
		err := cilium.WaitUntilReady(100)
		Expect(err).Should(BeNil())

		status := cilium.WaitEndpointsReady()
		Expect(status).Should(BeTrue())

	}

	BeforeEach(func() {
		initialize()
		docker.ContainerCreate(helpers.Client, helpers.NetperfImage, helpers.CiliumDockerNetwork, "-l id.client")
		docker.ContainerCreate(helpers.Server, helpers.NetperfImage, helpers.CiliumDockerNetwork, "-l id.server")

		areEndpointsReady := cilium.WaitEndpointsReady()
		Expect(areEndpointsReady).Should(BeTrue())
	})

	AfterEach(func() {
		if CurrentGinkgoTestDescription().Failed {
			cilium.ReportFailed()
		}
		docker.ContainerRm(helpers.Client)
		docker.ContainerRm(helpers.Server)
	})

	It("Endpoint recovery on restart", func() {
		originalIps := cilium.Node.Exec(`
		curl -s --unix-socket /var/run/cilium/cilium.sock \
		http://localhost/v1beta/healthz/ | jq ".ipam.ipv4|length"`)

		res := cilium.Node.Exec("sudo systemctl restart cilium")
		res.ExpectSuccess()

		waitForCilium()

		ips := cilium.Node.Exec(`
		curl -s --unix-socket /var/run/cilium/cilium.sock \
		http://localhost/v1beta/healthz/ | jq ".ipam.ipv4|length"`)
		Expect(originalIps.Output().String()).To(Equal(ips.Output().String()))

	}, 300)

	It("removing leftover Cilium interfaces", func() {
		originalLinks, err := docker.Node.Exec("sudo ip link show | wc -l").IntOutput()
		Expect(err).Should(BeNil())

		_ = docker.Node.Exec("sudo ip link add lxc12345 type veth peer name tmp54321")

		res := cilium.Node.Exec("sudo systemctl restart cilium")
		res.ExpectSuccess()

		waitForCilium()

		status := docker.Node.Exec("sudo ip link show lxc12345")
		status.ExpectFail("leftover interface were not properly cleaned up")

		links, err := docker.Node.Exec("sudo ip link show | wc -l").IntOutput()
		Expect(links).Should(Equal(originalLinks),
			"Some network interfaces were accidentally removed!")
	}, 300)
})

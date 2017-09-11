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

var _ = Describe("RuntimeChaosMonkey", func() {

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
		logger = log.WithFields(log.Fields{"testName": "RuntimeChaosMonkey"})
		logger.Info("Starting")
		docker, cilium = helpers.CreateNewRuntimeHelper("runtime", logger)
		docker.NetworkCreate(networkName, "")
		initialized = true
	}

	waitForCilium := func() {
		err := cilium.WaitUntilReady(100)
		Expect(err).Should(BeNil())

		status := cilium.EndpointWaitUntilReady()
		Expect(status).Should(BeTrue())

	}

	BeforeEach(func() {
		initialize()
		docker.ContainerCreate("client", netperfImage, networkName, "-l id.client")
		docker.ContainerCreate("server", netperfImage, networkName, "-l id.server")

	})

	AfterEach(func() {
		docker.ContainerRm("client")
		docker.ContainerRm("server")
	})

	It("Endpoint recovery on restart", func() {
		originalIps := cilium.Node.Exec(`
		curl -s --unix-socket /var/run/cilium/cilium.sock \
		http://localhost/v1beta/healthz/ | jq ".ipam.ipv4|length"`)

		res := cilium.Node.Exec("sudo systemctl restart cilium")
		Expect(res.WasSuccessful()).Should(BeTrue())

		waitForCilium()

		ips := cilium.Node.Exec(`
		curl -s --unix-socket /var/run/cilium/cilium.sock \
		http://localhost/v1beta/healthz/ | jq ".ipam.ipv4|length"`)
		Expect(originalIps.Output()).To(Equal(ips.Output()))

	}, 300)

	It("removing leftover Cilium interfaces", func() {
		originalLinks, err := docker.Node.Exec("sudo ip link show | wc -l").IntOutput()
		Expect(err).Should(BeNil())

		_ = docker.Node.Exec("sudo ip link add lxc12345 type veth peer name tmp54321")

		res := cilium.Node.Exec("sudo systemctl restart cilium")
		Expect(res.WasSuccessful()).Should(BeTrue())

		waitForCilium()

		status := docker.Node.Exec("sudo ip link show lxc12345")
		Expect(status.WasSuccessful()).Should(BeFalse(),
			"leftover interface were not properly cleaned up")

		links, err := docker.Node.Exec("sudo ip link show | wc -l").IntOutput()
		Expect(links).Should(Equal(originalLinks),
			"Some network interfaces were accidentally removed!")
	}, 300)
})

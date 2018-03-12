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
	"crypto/md5"
	"fmt"
	"sync"

	. "github.com/cilium/cilium/test/ginkgo-ext"
	"github.com/cilium/cilium/test/helpers"

	. "github.com/onsi/gomega"
	"github.com/sirupsen/logrus"
)

var _ = Describe("RuntimeValidatedChaos", func() {

	var vm *helpers.SSHMeta
	var once sync.Once

	initialize := func() {
		logger := log.WithFields(logrus.Fields{"testName": "RuntimeValidatedChaos"})
		logger.Info("Starting")
		vm = helpers.CreateNewRuntimeHelper(helpers.Runtime, logger)
	}

	BeforeEach(func() {
		once.Do(initialize)
		vm.ContainerCreate(helpers.Client, helpers.NetperfImage, helpers.CiliumDockerNetwork, "-l id.client")
		vm.ContainerCreate(helpers.Server, helpers.NetperfImage, helpers.CiliumDockerNetwork, "-l id.server")

		areEndpointsReady := vm.WaitEndpointsReady()
		Expect(areEndpointsReady).Should(BeTrue())
	})

	AfterEach(func() {
		if CurrentGinkgoTestDescription().Failed {
			vm.ReportFailed()
		}
		vm.ContainerRm(helpers.Client)
		vm.ContainerRm(helpers.Server)
	})

	It("Endpoint recovery on restart", func() {
		hasher := md5.New()

		originalIps := vm.Exec(`
		curl -s --unix-socket /var/run/cilium/cilium.sock \
		http://localhost/v1beta/healthz/ | jq ".ipam.ipv4|length"`)

		endpointListCmd := "cilium endpoint list | grep -v reserved"
		originalEndpointList := vm.Exec(endpointListCmd)

		err := vm.RestartCilium()
		Expect(err).Should(BeNil())

		ips := vm.Exec(`
		curl -s --unix-socket /var/run/cilium/cilium.sock \
		http://localhost/v1beta/healthz/ | jq ".ipam.ipv4|length"`)
		Expect(originalIps.Output().String()).To(Equal(ips.Output().String()))

		EndpointList := vm.Exec(endpointListCmd)
		By(fmt.Sprintf("original: %s", originalEndpointList.Output().String()))
		By(fmt.Sprintf("new: %s", EndpointList.Output().String()))
		Expect(EndpointList.Output().String()).To(Equal(originalEndpointList.Output().String()))
		Expect(hasher.Sum(EndpointList.Output().Bytes())).To(
			Equal(hasher.Sum(originalEndpointList.Output().Bytes())))

	}, 300)

	It("removing leftover Cilium interfaces", func() {
		originalLinks, err := vm.Exec("sudo ip link show | wc -l").IntOutput()
		Expect(err).Should(BeNil())

		_ = vm.Exec("sudo ip link add lxc12345 type veth peer name tmp54321")

		err = vm.RestartCilium()
		Expect(err).Should(BeNil())

		status := vm.Exec("sudo ip link show lxc12345")
		status.ExpectFail("leftover interface were not properly cleaned up")

		links, err := vm.Exec("sudo ip link show | wc -l").IntOutput()
		Expect(links).Should(Equal(originalLinks),
			"Some network interfaces were accidentally removed!")
	}, 300)

	It("Checking for file-descriptor leak", func() {
		threshold := 5000
		fds, err := vm.Exec("sudo lsof -p `pidof cilium-node-monitor` -p `pidof cilium-agent` -p `pidof cilium-docker` 2>/dev/null | wc -l").IntOutput()
		Expect(err).Should(BeNil())

		Expect(fds).To(BeNumerically("<", threshold),
			fmt.Sprintf("%d file descriptors open from Cilium processes", fds))
	}, 300)
})
